package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/agent/claude"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/agent/copilot"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/notify"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/vcs"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

// copilotStop is a VS Code agent-mode Stop payload with a REAL cwd — the shape that
// produced the live incident: the Stop hook fires and reaches the server on every
// turn, but no baseline was ever recorded, and copilot has no transcript fallback.
func copilotStop(cwd, session string) string {
	return fmt.Sprintf(
		`{"hook_event_name":"Stop","stop_hook_active":false,"session_id":%q,"cwd":%q}`,
		session, cwd)
}

// noticeText extracts the systemMessage from a non-blocking Stop notice, and asserts
// it carries NO decision — a notice must never block the stop.
func noticeText(t *testing.T, stdout string) string {
	t.Helper()
	if stdout == "" {
		return ""
	}
	var out struct {
		Decision      string `json:"decision"`
		SystemMessage string `json:"systemMessage"`
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("notice is not valid JSON: %v (%q)", err, stdout)
	}
	if out.Decision != "" {
		t.Fatalf("a skip notice must NOT block the stop, got decision=%q", out.Decision)
	}
	return out.SystemMessage
}

// ⚠️ A TURN THAT DISCOVERED NOTHING IS NOW SILENT, AND THIS REPLACES TWO TESTS THAT
// PINNED THE OPPOSITE.
//
// The generic "no git snapshot for this turn" notice was added because an unreviewed turn
// was indistinguishable from a quiet one — a pilot on an agent with no transcript fallback
// spent a weekend at zero coverage with no signal anywhere. Two things have since closed
// that: PreToolUse discovery resolves the repository behind a named path or a shell
// command, and the Stop-time HEAD fallback covers what nothing named. So a write we could
// not see now produces either a real review or the specific HeadDeclined notice, both of
// which say more than this ever did — and what remained was a turn where nothing was
// written at all, where the message is true, unactionable, and printed over the
// developer's work every time.
//
// The WARN in client.log stays, so a genuinely unseen write is still diagnosable. Only the
// terminal message is gone. RESIDUAL GAP, accepted deliberately: a write into a repository
// more than two levels below cwd, or outside it entirely, that nothing named, is silent.
func TestATurnThatDiscoveredNothingIsSilent(t *testing.T) {
	session := "engine-nobaseline-silent"
	t.Cleanup(func() { notify.Clear(session) })

	r := &fakeReviewer{}
	// A real directory that is deliberately NOT a git repo, and holds no repository to
	// discover — so neither the fallback nor the declined notice has anything to say.
	code, stdout, _ := runWith(copilot.New(), r, copilotStop(t.TempDir(), session))

	if code != 0 {
		t.Fatalf("must still fail open, got code=%d", code)
	}
	if r.called {
		t.Error("reviewer must not run when nothing was discovered")
	}
	if stdout != "" {
		t.Errorf("a turn that discovered nothing must print nothing, got %q", stdout)
	}
}

// ⚠️ The guard that keeps the notice honest. A turn that genuinely changed nothing
// INSIDE a working repo is just a question, and must stay silent — otherwise every
// developer asking their agent a question gets a security warning.
func TestQuietTurnInAGitRepoStaysSilent(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir, session := t.TempDir(), "engine-nobaseline-quiet"
	seedRepo(t, dir)
	t.Cleanup(func() {
		notify.Clear(session)
		_ = os.Remove(filepath.Join(os.TempDir(), "leoprevent-baselines", session))
	})
	if err := vcs.CaptureBaseline(dir, session); err != nil {
		t.Fatal(err)
	}

	r := &fakeReviewer{}
	code, stdout, _ := runWith(copilot.New(), r, copilotStop(dir, session))
	if code != 0 || stdout != "" {
		t.Errorf("a no-change turn in a real repo must be silent, got code=%d stdout=%q", code, stdout)
	}
	// It is a genuine no-change turn, so telemetry must record that git DID work — the
	// distinction the whole fix exists to preserve.
	if !r.telemetryMeta.GitBaseline {
		t.Error("telemetry must report git_baseline=true when the baseline was used")
	}
	if r.telemetryMeta.BaselineSkip != "" {
		t.Errorf("a working baseline must carry no skip reason, got %q", r.telemetryMeta.BaselineSkip)
	}
}

// The regression this fix exists for: shipTelemetry built its meta from turnMeta
// alone, and the baseline fields are assigned further down Run — so every no-review
// turn reported neither. Prod carried 1,781 such events across 0.2.15..0.2.20, none of
// which could say WHY the turn had nothing to review.
func TestNoChangeTelemetryRecordsWhyThereWasNothingToReview(t *testing.T) {
	session := "engine-nobaseline-telemetry"
	t.Cleanup(func() { notify.Clear(session) })

	r := &fakeReviewer{}
	runWith(copilot.New(), r, copilotStop(t.TempDir(), session))

	if r.telemetryCalls != 1 || r.telemetryReason != wire.TelemetryNoChange {
		t.Fatalf("expected one no_change telemetry call, got calls=%d reason=%q",
			r.telemetryCalls, r.telemetryReason)
	}
	if r.telemetryMeta.GitBaseline {
		t.Error("git_baseline must be false when no baseline was used")
	}
	if r.telemetryMeta.BaselineSkip != string(vcs.SkipNotGitRepo) {
		t.Errorf("telemetry must carry the skip reason, want %q got %q",
			vcs.SkipNotGitRepo, r.telemetryMeta.BaselineSkip)
	}
}

// An INERT turn carries the baseline facts too. It reaches shipTelemetry by a second
// call site, so a fix applied to only one of them leaves half the no-review turns blind.
func TestInertTelemetryCarriesTheBaselineFactsToo(t *testing.T) {
	tp := writeTranscript(t,
		`{"type":"user","message":{"role":"user","content":"add a clarifying comment"}}`,
		`{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","name":"Edit","input":{"file_path":"/p/calc.py","old_string":"x","new_string":"# this adds totals up"}}]}}`,
	)
	r := &fakeReviewer{}
	// claude, so the transcript fallback produces the (inert) change set.
	runWith(claude.New(), r, payload(tp))

	if r.telemetryReason != wire.TelemetryInert {
		t.Fatalf("expected an inert telemetry call, got %q", r.telemetryReason)
	}
	if r.telemetryMeta.BaselineSkip == "" {
		t.Error("inert telemetry from a fallback turn must record the skip reason")
	}
}

// A missing cwd is a payload-shape problem, not something the developer can act on,
// so it must NOT produce a notice telling them to `git init` a folder we cannot name.
// Same conservative default an unclassified SkipError takes.
func TestMissingCwdStaysSilent(t *testing.T) {
	r := &fakeReviewer{}
	_, stdout, _ := runWith(copilot.New(), r,
		`{"hook_event_name":"Stop","stop_hook_active":false,"session_id":"engine-nocwd","cwd":""}`)
	if stdout != "" {
		t.Errorf("a payload with no cwd must stay silent, got %q", stdout)
	}
}

// seedRepo makes dir a git repo with one commit.
func seedRepo(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) {
		c := exec.Command("git", append([]string{"-C", dir}, args...)...)
		c.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-q")
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte("import os\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", "-A")
	run("commit", "-q", "-m", "init")
}

// uniqueSession returns a session id that no other RUN of this suite can share, plus
// cleanup for every piece of per-session scratch a turn can leave behind.
//
// ⚠️ A TEST THAT TRIGGERS A BLOCK ARMS THE COPILOT LOOP-GUARD MARKER, and that marker
// outlives the process. With a fixed session id the NEXT `go test` consumes it, so
// ParseEvent reports stop_hook_active, Run takes the already-reviewed branch and the
// reviewer is never called — the suite then passes and fails on ALTERNATE RUNS with no
// output explaining why (verified: pass, fail, pass). Production session ids are
// unique, so this mirrors reality rather than papering over it.
func uniqueSession(t *testing.T, name string) string {
	t.Helper()
	id := name + "-" + filepath.Base(t.TempDir())
	t.Cleanup(func() {
		notify.Clear(id)
		vcs.ClearBaseline(id)
		_ = os.Remove(filepath.Join(os.TempDir(), "leoprevent-copilot-guard", id))
	})
	return id
}

// preTool records a repository the way the PreToolUse hook does: by naming the file the
// agent is about to write. Since LEO-154 this is the ONLY way a repository outside cwd
// becomes known — CaptureBaseline no longer walks the tree — so every workspace test
// below has to take this step, exactly as a real turn does.
func preTool(t *testing.T, cwd, file, session string) {
	t.Helper()
	if err := vcs.RecordEditedRepo(file, cwd, session); err != nil {
		t.Fatalf("RecordEditedRepo(%s): %v", file, err)
	}
}

// ⚠️ THE INCIDENT, END TO END. Copilot in VS Code with the editor opened on a folder
// that HOLDS repositories rather than being one. That produced no baseline, and
// because the copilot adapter has no transcript fallback it produced no changed files
// either: sixteen turns, zero reviews, and a notice was the best we could do.
//
// With per-repo baselines the same turn is reviewed. This asserts the reviewer runs
// and receives the edited file, qualified by its repository.
func TestWorkspaceOfReposIsReviewedOnCopilot(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	ws := t.TempDir()
	session := uniqueSession(t, "engine-workspace-review")
	seedRepo(t, filepath.Join(ws, "project-a"))
	seedRepo(t, filepath.Join(ws, "project-b"))

	if err := vcs.CaptureBaseline(ws, session); err != nil {
		t.Fatal(err)
	}
	// The agent's first write to project-a: the PreToolUse hook names the file, which
	// is what makes the repository knowable at all (it is not cwd, and nothing walks
	// down to it any more).
	preTool(t, ws, filepath.Join(ws, "project-a", "app.py"), session)
	// A shell-style write, which the transcript could never have seen.
	app := filepath.Join(ws, "project-a", "app.py")
	body, err := os.ReadFile(app)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(app, append(body, []byte("x = requests.get(url)\n")...), 0o644); err != nil {
		t.Fatal(err)
	}

	r := &fakeReviewer{prompt: "FINDINGS"}
	code, stdout, _ := runWith(copilot.New(), r, copilotStop(ws, session))

	if !r.called {
		t.Fatal("the turn must now be REVIEWED; the reviewer was never called")
	}
	if code != 0 {
		t.Errorf("still fail-open, got code=%d", code)
	}
	if stdout == "" {
		t.Error("a triggered review must re-wake the agent")
	}
	if len(r.gotChanges) != 1 || r.gotChanges[0].FilePath != "project-a/app.py" {
		t.Errorf("expected the edited file qualified by its repo, got %+v", r.gotChanges)
	}
	if !r.gotMeta.GitBaseline {
		t.Error("this is the git path, not the degraded fallback; git_baseline must be true")
	}
}

// And the notice must NOT fire for that turn: it was reviewed, so telling the
// developer nothing was reviewed would be a false alarm on a working setup.
func TestWorkspaceReviewDoesNotAlsoWarnAboutNoBaseline(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	ws := t.TempDir()
	session := uniqueSession(t, "engine-workspace-nonotice")
	seedRepo(t, filepath.Join(ws, "only"))
	if err := vcs.CaptureBaseline(ws, session); err != nil {
		t.Fatal(err)
	}
	preTool(t, ws, filepath.Join(ws, "only", "app.py"), session)

	r := &fakeReviewer{}
	_, stdout, _ := runWith(copilot.New(), r, copilotStop(ws, session))
	if msg := noticeText(t, stdout); strings.Contains(msg, "no git snapshot") {
		t.Errorf("a workspace WITH baselines must not warn about a missing one, got %q", msg)
	}
}

// ⚠️ TurnMeta.Repo is the "app" dimension every dashboard groups by, and it holds ONE
// value. A workspace turn used to carry none at all, because turnMeta resolves it from
// cwd and a folder of projects is not a repository.
func TestWorkspaceTurnNamesTheRepoThatChanged(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	ws := t.TempDir()
	session := uniqueSession(t, "engine-workspace-repo")
	seedRepo(t, filepath.Join(ws, "project-a"))
	seedRepo(t, filepath.Join(ws, "project-b"))
	addOrigin(t, filepath.Join(ws, "project-a"), "git@github.com:acme/project-a.git")
	addOrigin(t, filepath.Join(ws, "project-b"), "git@github.com:acme/project-b.git")
	if err := vcs.CaptureBaseline(ws, session); err != nil {
		t.Fatal(err)
	}
	preTool(t, ws, filepath.Join(ws, "project-b", "app.py"), session)
	touch(t, filepath.Join(ws, "project-b", "app.py"), "x = requests.get(url)\n")

	r := &fakeReviewer{prompt: "FINDINGS"}
	runWith(copilot.New(), r, copilotStop(ws, session))
	if !r.called {
		t.Fatal("expected a review")
	}
	if got, want := r.gotMeta.Repo, "github.com/acme/project-b"; got != want {
		t.Errorf("the changed repo must be named, got %q want %q", got, want)
	}
}

// ...but a turn spanning SEVERAL repos names none. One field cannot hold two apps, and
// filing a cross-project turn under an arbitrary one reads as fact where a blank reads
// as unknown.
func TestTurnSpanningTwoReposNamesNeither(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	ws := t.TempDir()
	session := uniqueSession(t, "engine-workspace-tworepos")
	seedRepo(t, filepath.Join(ws, "project-a"))
	seedRepo(t, filepath.Join(ws, "project-b"))
	addOrigin(t, filepath.Join(ws, "project-a"), "git@github.com:acme/project-a.git")
	addOrigin(t, filepath.Join(ws, "project-b"), "git@github.com:acme/project-b.git")
	if err := vcs.CaptureBaseline(ws, session); err != nil {
		t.Fatal(err)
	}
	preTool(t, ws, filepath.Join(ws, "project-a", "app.py"), session)
	preTool(t, ws, filepath.Join(ws, "project-b", "app.py"), session)
	touch(t, filepath.Join(ws, "project-a", "app.py"), "a = requests.get(url)\n")
	touch(t, filepath.Join(ws, "project-b", "app.py"), "b = requests.get(url)\n")

	r := &fakeReviewer{prompt: "FINDINGS"}
	runWith(copilot.New(), r, copilotStop(ws, session))
	if !r.called {
		t.Fatal("expected a review")
	}
	if r.gotMeta.Repo != "" {
		t.Errorf("a cross-repo turn must name no single app, got %q", r.gotMeta.Repo)
	}
	if len(r.gotChanges) != 2 {
		t.Errorf("both repos' files should still be reviewed, got %d", len(r.gotChanges))
	}
}

func addOrigin(t *testing.T, dir, url string) {
	t.Helper()
	c := exec.Command("git", "-C", dir, "remote", "add", "origin", url)
	if out, err := c.CombinedOutput(); err != nil {
		t.Fatalf("git remote add: %v\n%s", err, out)
	}
}

func touch(t *testing.T, path, extra string) {
	t.Helper()
	old, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(old, []byte(extra)...), 0o644); err != nil {
		t.Fatal(err)
	}
}

// ...and a turn whose only changes were INERT names it too (LEO-194).
//
// `shipTelemetry` built its meta from `turnMeta` alone and applied none of the workspace
// correction the review path applies, so a workspace turn that edited nothing but comments
// reported no repository while the identical turn with reviewable code reported one. `Repo`
// is the dimension the Repositories tab counts TURNS by, so the same account's turn count
// and review count came off different populations — and a repository whose recent work was
// all comments simply looked idle.
//
// Fails against the pre-fix `shipTelemetry`, which took a count rather than the changes and
// so had nothing to resolve the repository from.
func TestInertTelemetryNamesTheRepositoryThatChanged(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	ws := t.TempDir()
	session := uniqueSession(t, "engine-workspace-inert-repo")
	seedRepo(t, filepath.Join(ws, "project-a"))
	seedRepo(t, filepath.Join(ws, "project-b"))
	addOrigin(t, filepath.Join(ws, "project-a"), "git@github.com:acme/project-a.git")
	addOrigin(t, filepath.Join(ws, "project-b"), "git@github.com:acme/project-b.git")
	if err := vcs.CaptureBaseline(ws, session); err != nil {
		t.Fatal(err)
	}
	preTool(t, ws, filepath.Join(ws, "project-b", "app.py"), session)
	touch(t, filepath.Join(ws, "project-b", "app.py"), "# just a note, nothing to review\n")

	r := &fakeReviewer{}
	runWith(copilot.New(), r, copilotStop(ws, session))
	if r.called {
		t.Fatal("a comment-only change must not be reviewed")
	}
	if r.telemetryReason != wire.TelemetryInert {
		t.Fatalf("expected an inert telemetry call, got %q", r.telemetryReason)
	}
	if got, want := r.telemetryMeta.Repo, "github.com/acme/project-b"; got != want {
		t.Errorf("inert telemetry must name the repo that changed, got %q want %q", got, want)
	}
	if r.telemetryChanged != 1 {
		t.Errorf("the inert change should still be counted, got %d", r.telemetryChanged)
	}
}

// But an inert turn spanning TWO repositories still names neither — the correction is
// `soleRepoOrigin`, so the review path's refusal to guess reaches this path unchanged.
func TestInertTelemetrySpanningTwoReposNamesNeither(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	ws := t.TempDir()
	session := uniqueSession(t, "engine-workspace-inert-tworepos")
	seedRepo(t, filepath.Join(ws, "project-a"))
	seedRepo(t, filepath.Join(ws, "project-b"))
	addOrigin(t, filepath.Join(ws, "project-a"), "git@github.com:acme/project-a.git")
	addOrigin(t, filepath.Join(ws, "project-b"), "git@github.com:acme/project-b.git")
	if err := vcs.CaptureBaseline(ws, session); err != nil {
		t.Fatal(err)
	}
	preTool(t, ws, filepath.Join(ws, "project-a", "app.py"), session)
	preTool(t, ws, filepath.Join(ws, "project-b", "app.py"), session)
	touch(t, filepath.Join(ws, "project-a", "app.py"), "# a note\n")
	touch(t, filepath.Join(ws, "project-b", "app.py"), "# b note\n")

	r := &fakeReviewer{}
	runWith(copilot.New(), r, copilotStop(ws, session))
	if r.telemetryReason != wire.TelemetryInert {
		t.Fatalf("expected an inert telemetry call, got %q", r.telemetryReason)
	}
	if r.telemetryMeta.Repo != "" {
		t.Errorf("a cross-repo inert turn must name no single app, got %q", r.telemetryMeta.Repo)
	}
}
