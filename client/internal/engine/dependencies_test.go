package engine

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/agent/claude"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/agent/cursor"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/scratch"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/vcs"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

// depReviewer is the cloud reviewer's dependency call, faked: it records each request and
// answers with a fixed notice.
type depReviewer struct {
	fakeReviewer
	depRequests []wire.DependenciesRequest
}

const depNotice = "LeoPrevent: lodash 4.17.15 (was 4.17.10) has 2 high vulnerabilities."

func (d *depReviewer) CheckDependencies(req wire.DependenciesRequest) (wire.DependenciesResponse, error) {
	d.depRequests = append(d.depRequests, req)
	msg := depNotice
	return wire.DependenciesResponse{Ecosystem: req.Ecosystem, Messages: wire.DependencyMessages{Developer: &msg}}, nil
}

func npmLock(lodash string) string {
	return fmt.Sprintf(`{"lockfileVersion": 3, "packages": {"": {"dependencies": {"lodash": "*"}},
		"node_modules/lodash": {"version": %q, "resolved": "https://registry.npmjs.org/lodash/-/lodash-%s.tgz"}}}`, lodash, lodash)
}

// depTurn makes a repository with a committed lockfile, captures the turn start, then applies
// the turn's writes and runs the Stop.
func depTurn(t *testing.T, session string, r Reviewer, writes map[string]string) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	gitCmd := func(args ...string) {
		c := exec.Command("git", append([]string{"-C", dir}, args...)...)
		c.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	write := func(rel, body string) {
		if err := os.WriteFile(filepath.Join(dir, rel), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	gitCmd("init", "-q")
	write("app.py", "import os\n")
	write("package-lock.json", npmLock("4.17.10"))
	gitCmd("add", "-A")
	gitCmd("commit", "-q", "-m", "init")
	t.Cleanup(func() { _ = os.Remove(filepath.Join(scratch.Dir("baselines"), session)) })
	if err := vcs.CaptureBaseline(dir, session); err != nil {
		t.Fatal(err)
	}
	for rel, body := range writes {
		write(rel, body)
	}
	stdin := fmt.Sprintf(`{"stop_hook_active":false,"hook_event_name":"Stop","cwd":%q,"session_id":%q}`, dir, session)
	code, stdout, _ := runWith(claude.New(), r, stdin)
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	return stdout
}

func hookOutput(t *testing.T, stdout string) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("hook output isn't JSON: %v\n%s", err, stdout)
	}
	return out
}

// A lockfile-only turn has nothing for the review (the gate drops lockfiles), but it is
// checked: the change from the start of the turn is sent, and the notice is printed.
func TestALockfileOnlyTurnIsChecked(t *testing.T) {
	t.Setenv("LEOPREVENT_SEND_DEPENDENCIES", "on")
	r := &depReviewer{}
	stdout := depTurn(t, "engine-deps-lockfile-only", r, map[string]string{"package-lock.json": npmLock("4.17.15")})
	if r.called {
		t.Error("a lockfile-only turn has nothing to review")
	}
	if len(r.depRequests) != 1 {
		t.Fatalf("requests: %+v", r.depRequests)
	}
	p := r.depRequests[0].Packages[0]
	if p.Name != "lodash" || p.Version != "4.17.15" || p.Change != wire.DependencyChanged || p.Previous != "4.17.10" {
		t.Errorf("sent %+v, want lodash changed from 4.17.10", p)
	}
	out := hookOutput(t, stdout)
	if out["systemMessage"] != depNotice || out["decision"] != nil {
		t.Errorf("a plain notice, never a decision: %v", out)
	}
}

// With code changes too, the review wakes the agent exactly as before; the notice is only added
// to what the developer sees, never to what the agent is told.
func TestTheNoticeRidesOnTheReviewWithoutChangingIt(t *testing.T) {
	t.Setenv("LEOPREVENT_SEND_DEPENDENCIES", "on")
	r := &depReviewer{fakeReviewer: fakeReviewer{prompt: "FIX THESE FINDINGS"}}
	stdout := depTurn(t, "engine-deps-with-review", r, map[string]string{
		"package-lock.json": npmLock("4.17.15"),
		"app.py":            "import os\nx = eval(input())\n",
	})
	if !r.called {
		t.Fatal("the code was reviewed")
	}
	out := hookOutput(t, stdout)
	if out["decision"] != "block" || out["reason"] != "FIX THESE FINDINGS" {
		t.Errorf("the review wake is unchanged: %v", out)
	}
	msg, _ := out["systemMessage"].(string)
	if !strings.HasSuffix(msg, depNotice) || msg == depNotice {
		t.Errorf("the notice follows the review's own banner: %q", msg)
	}
	if strings.Contains(fmt.Sprint(out["reason"]), "lodash") {
		t.Error("the agent is never told")
	}
}

// Off by default: nothing is read or sent.
func TestTheDependencyCheckIsOffByDefault(t *testing.T) {
	t.Setenv("LEOPREVENT_SEND_DEPENDENCIES", "")
	r := &depReviewer{}
	if stdout := depTurn(t, "engine-deps-off", r, map[string]string{"package-lock.json": npmLock("4.17.15")}); len(r.depRequests) != 0 || stdout != "" {
		t.Errorf("switched off: requests %+v, output %q", r.depRequests, stdout)
	}
}

// An agent whose notices aren't a systemMessage (Cursor logs them) keeps its output as it is.
func TestAttachNoticeAsksTheAgent(t *testing.T) {
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	if got := string(attachNotice(cursor.New(), []byte(`{"followup_message":"x"}`), "n", quiet)); got != `{"followup_message":"x"}` {
		t.Errorf("cursor: %s", got)
	}
	if got := string(attachNotice(claude.New(), []byte("not json"), "n", quiet)); got != "not json" {
		t.Errorf("unparseable output is left alone: %s", got)
	}
	got := hookOutput(t, string(attachNotice(claude.New(), []byte(`{"decision":"block","reason":"r"}`), "n", quiet)))
	if got["systemMessage"] != "n" || got["reason"] != "r" {
		t.Errorf("no banner yet: %v", got)
	}
}
