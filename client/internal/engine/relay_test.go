package engine

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/agent/claude"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/config"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/notify"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/outcome"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/review"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/scratch"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/vcs"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

// relayTurn plays a turn on the given surface with the dependency check on and answering with
// depNotice, then, when reply is set, the Stop after the agent's fix with that as its reply. It
// returns both Stops' output.
func relayTurn(t *testing.T, surface string, r *depReviewer, writes, fix map[string]string, reply string, firstCleanShown bool) (string, string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	t.Setenv("CLAUDE_CODE_ENTRYPOINT", surface)
	t.Setenv("LEOPREVENT_SEND_DEPENDENCIES", "on")
	restore := config.SetUserConfigDirForTest(t.TempDir())
	t.Cleanup(restore)
	withLicense(t, "lp_test_relay")
	if firstCleanShown {
		config.ClaimFirstClean("lp_test_relay")
	}
	dir := t.TempDir()
	gitCmd := func(args ...string) {
		c := exec.Command("git", append([]string{"-C", dir}, args...)...)
		c.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	write := func(files map[string]string) {
		for rel, body := range files {
			if err := os.WriteFile(filepath.Join(dir, rel), []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	gitCmd("init", "-q")
	write(map[string]string{"app.py": "import os\n", "package-lock.json": npmLock("4.17.10")})
	gitCmd("add", "-A")
	gitCmd("commit", "-q", "-m", "init")
	session := "relay-" + strings.NewReplacer("/", "-", " ", "-").Replace(t.Name())
	for _, f := range []func(){func() { notify.Clear(session) }, func() { outcome.Take(session) }, func() { takeRelayed(session) }} {
		f()
		t.Cleanup(f)
	}
	notify.FirstThisSession(session, sessionScanKey) // a later turn: the scan is tested on its own
	t.Cleanup(func() { _ = os.Remove(filepath.Join(scratch.Dir("baselines"), session)) })
	if err := vcs.CaptureBaseline(dir, session); err != nil {
		t.Fatal(err)
	}
	write(writes)
	stdin := fmt.Sprintf(`{"stop_hook_active":false,"hook_event_name":"Stop","cwd":%q,"session_id":%q}`, dir, session)
	_, first, _ := runWith(claude.New(), r, stdin)
	if fix == nil {
		return first, ""
	}
	write(fix)
	stdin = fmt.Sprintf(`{"stop_hook_active":true,"hook_event_name":"Stop","cwd":%q,"session_id":%q,"last_assistant_message":%q}`, dir, session, reply)
	_, second, _ := runWith(claude.New(), r, stdin)
	return first, second
}

func findingsReviewer() *depReviewer {
	return &depReviewer{fakeReviewer: fakeReviewer{prompt: "FIX THESE FINDINGS", findings: []wire.Finding{sqlFinding},
		pending: &outcome.Pending{ReviewID: "rid-relay", Findings: []wire.Finding{sqlFinding}}}}
}

// A lockfile-only turn in the desktop app: the agent is asked to print the notice and stop.
func TestTheDesktopAppRelaysANoticeOnItsOwn(t *testing.T) {
	first, _ := relayTurn(t, "claude-desktop", &depReviewer{}, map[string]string{"package-lock.json": npmLock("4.17.15")}, nil, "", true)
	out := hookOutput(t, first)
	reason, _ := out["reason"].(string)
	if out["decision"] != "block" || !strings.HasPrefix(reason, "LeoPrevent has a notice for the developer") ||
		!strings.Contains(reason, review.DeveloperMarkdown("package-lock.json:\n"+depNotice)) {
		t.Errorf("lockfile only, desktop app: %v", out)
	}
}

// A clean review whose first-clean notice is due, plus a dependency notice: one relay, not two.
func TestTheDesktopAppMergesTheFirstCleanRelay(t *testing.T) {
	first, _ := relayTurn(t, "claude-desktop", &depReviewer{},
		map[string]string{"app.py": "import os\nx = 1\n", "package-lock.json": npmLock("4.17.15")}, nil, "", false)
	reason, _ := hookOutput(t, first)["reason"].(string)
	if !strings.HasPrefix(reason, strings.TrimRight(review.FirstCleanRelayPrompt(), "\n")) ||
		!strings.Contains(reason, "> "+depNotice) || strings.Count(reason, "Reply with exactly") != 1 {
		t.Errorf("first-clean plus a notice:\n%s", reason)
	}
}

// Review findings plus a dependency notice in the desktop app: the review's prompt is kept and
// the agent is also asked to print the notice. On the next Stop the printed notice is removed
// from the agent's reply before /outcome, which only ever scores the review's own findings.
func TestTheRelayedNoticeNeverReachesOutcome(t *testing.T) {
	r := findingsReviewer()
	md := review.DeveloperMarkdown("package-lock.json:\n" + depNotice)
	// The agent printed the review block, the notice (re-flowed, as agents do) and its account.
	reply := "> 🛡️ LeoPrevent · automated security review\n> Reviewed 2 changed files and flagged 1 finding to fix.\n\n" +
		strings.ReplaceAll(md, "\n", "\n\n  ") + "\n\nFixed the SQL injection in app.py with a parameterised query."
	first, second := relayTurn(t, "claude-desktop", r,
		map[string]string{"app.py": "import os\nq = f\"SELECT {x}\"\n", "package-lock.json": npmLock("4.17.15")},
		map[string]string{"app.py": "import os\nq = run(\"SELECT ?\", x)\n"}, reply, true)

	out := hookOutput(t, first)
	reason, _ := out["reason"].(string)
	if out["decision"] != "block" || !strings.HasPrefix(reason, "FIX THESE FINDINGS\n\n") || !strings.Contains(reason, review.DeveloperAddendum(md)) {
		t.Errorf("the review's wake, with the notice to print:\n%s", reason)
	}
	if !r.shipped {
		t.Fatalf("the fix was scored by /outcome as before; second Stop printed %q", second)
	}
	if strings.Contains(r.shippedResponse, "lodash") || strings.Contains(r.shippedResponse, "dependency check") {
		t.Errorf("/outcome received the relayed notice:\n%s", r.shippedResponse)
	}
	if !strings.Contains(r.shippedResponse, "Fixed the SQL injection") || !strings.Contains(r.shippedResponse, "security review") {
		t.Errorf("the agent's own account and the review block must still reach /outcome:\n%s", r.shippedResponse)
	}
	if len(r.shippedPending.Findings) != 1 || r.shippedPending.Findings[0].Rule != sqlFinding.Rule {
		t.Errorf("/outcome scores only the review's own findings: %+v", r.shippedPending.Findings)
	}
}

// In the terminal nothing is relayed, so nothing needs removing: the reply goes to /outcome as it is.
func TestTheTerminalRelaysNothing(t *testing.T) {
	r := findingsReviewer()
	reply := "Fixed the SQL injection.\n\n> " + depNotice
	first, _ := relayTurn(t, "cli", r,
		map[string]string{"app.py": "import os\nq = f\"SELECT {x}\"\n", "package-lock.json": npmLock("4.17.15")},
		map[string]string{"app.py": "import os\nq = run(\"SELECT ?\", x)\n"}, reply, true)
	out := hookOutput(t, first)
	if out["reason"] != "FIX THESE FINDINGS" {
		t.Errorf("the terminal's wake is the review's alone: %v", out["reason"])
	}
	if r.shippedResponse != reply {
		t.Errorf("nothing was dictated, so nothing is removed: %q", r.shippedResponse)
	}
}
