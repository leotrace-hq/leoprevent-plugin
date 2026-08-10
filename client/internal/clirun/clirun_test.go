package clirun

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/engine"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/outcome"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

// fakeReviewer flags any change whose code contains the trigger, else clean —
// standing in for the real /review judge so the test needs no server.
type fakeReviewer struct {
	trigger string
	calls   int
	// outcome capture: how many times ShipOutcome was called + the pending it received,
	// so a test can assert the loop ships exactly one verified-fix outcome after a block.
	outcomeCalls   int
	lastPending    outcome.Pending
	lastAfter      []transcript.Change
	lastAgentReply string
}

func (f *fakeReviewer) Review(_ string, changes []transcript.Change, _ wire.TurnMeta) (engine.Result, error) {
	f.calls++
	for _, c := range changes {
		if strings.Contains(c.AddedText, f.trigger) || strings.Contains(c.FullContent, f.trigger) {
			// Mirror the cloud tier: a block returns the re-wake prompt AND a Pending
			// (findings + before-code) so the loop can score the fix after the loop ends.
			return engine.Result{
				Prompt:  "🔒 LeoPrevent: remove " + f.trigger,
				Pending: &outcome.Pending{ReviewID: "rid-1", Findings: []wire.Finding{{Rule: f.trigger}}},
			}, nil
		}
	}
	return engine.Result{}, nil
}

func (f *fakeReviewer) ShipOutcome(p outcome.Pending, after []transcript.Change, reply string, _ wire.TurnMeta) ([]wire.Finding, []wire.Finding, error) {
	f.outcomeCalls++
	f.lastPending, f.lastAfter, f.lastAgentReply = p, after, reply
	return nil, nil, nil
}

func (f *fakeReviewer) ShipResolution(_ outcome.Pending, _ []transcript.Change, _ wire.TurnMeta) ([]wire.Finding, error) {
	return nil, nil
}

func (f *fakeReviewer) ShipTelemetry(_ wire.TurnMeta, _ string, _ int) error {
	return nil
}

func gitInit(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	for _, args := range [][]string{{"init", "-q"}, {"config", "user.email", "t@t"}, {"config", "user.name", "t"}} {
		if out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	_ = os.WriteFile(filepath.Join(dir, "seed.txt"), []byte("x\n"), 0o644)
	_ = exec.Command("git", "-C", dir, "add", "-A").Run()
	_ = exec.Command("git", "-C", dir, "commit", "-qm", "seed").Run()
	return dir
}

// TestLoop_ConvergesToClean: round 1 the agent introduces a vuln, the reviewer
// flags it, round 2 the agent (driven by the re-wake) fixes it, the reviewer is
// clean — the faithful in-turn-fix cycle, headless.
func TestLoop_ConvergesToClean(t *testing.T) {
	dir := gitInit(t)
	app := filepath.Join(dir, "app.py")
	round := 0
	run := func(cwd, prompt string, out io.Writer) error {
		round++
		if round == 1 {
			return os.WriteFile(app, []byte("import os\nx = requests.get(url)\n"), 0o644)
		}
		return os.WriteFile(app, []byte("import os\nx = safe_fetch(url)\n"), 0o644) // "fix"
	}
	rev := &fakeReviewer{trigger: "requests.get"}
	res, err := Loop(rev, Options{Cwd: dir, Prompt: "add fetch", MaxRounds: 3, Run: run, Out: &bytes.Buffer{}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Clean || res.Rounds != 2 {
		t.Errorf("want clean after 2 rounds, got %+v", res)
	}
}

// TestLoop_ShipsOutcomeAfterBlock: when a round blocks (Change D), the loop must ship
// exactly ONE /outcome after it converges — carrying the original block's Pending and
// the final (fixed) after-state — so codex eval cells stop landing in "Unconfirmed".
func TestLoop_ShipsOutcomeAfterBlock(t *testing.T) {
	dir := gitInit(t)
	app := filepath.Join(dir, "app.py")
	round := 0
	run := func(cwd, prompt string, out io.Writer) error {
		round++
		if round == 1 {
			return os.WriteFile(app, []byte("x = requests.get(url)\n"), 0o644)
		}
		_, _ = out.Write([]byte("I removed the SSRF and used a safe fetch.\n")) // agent reply (round 2)
		return os.WriteFile(app, []byte("x = safe_fetch(url)\n"), 0o644)
	}
	rev := &fakeReviewer{trigger: "requests.get"}
	res, err := Loop(rev, Options{Cwd: dir, Prompt: "add fetch", MaxRounds: 3, Run: run, Out: &bytes.Buffer{}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Clean || res.Rounds != 2 {
		t.Fatalf("want clean after 2 rounds, got %+v", res)
	}
	if rev.outcomeCalls != 1 {
		t.Fatalf("want exactly 1 outcome shipped, got %d", rev.outcomeCalls)
	}
	if rev.lastPending.ReviewID != "rid-1" {
		t.Errorf("outcome carried the wrong pending: %+v", rev.lastPending)
	}
	// The after-state must be the FIXED code (round 2), and the agent's reply must ride along.
	if len(rev.lastAfter) == 0 || !strings.Contains(rev.lastAfter[0].FullContent, "safe_fetch") {
		t.Errorf("outcome after-state is not the fixed code: %+v", rev.lastAfter)
	}
	if !strings.Contains(rev.lastAgentReply, "safe fetch") {
		t.Errorf("agent reply not captured for /outcome: %q", rev.lastAgentReply)
	}
}

// TestLoop_NoOutcomeWhenNeverBlocked: a clean-first-try run must NOT ship an outcome
// (nothing blocked → nothing to re-verify).
func TestLoop_NoOutcomeWhenNeverBlocked(t *testing.T) {
	dir := gitInit(t)
	run := func(cwd, prompt string, out io.Writer) error {
		return os.WriteFile(filepath.Join(dir, "ok.py"), []byte("x = 1 + 1\n"), 0o644)
	}
	rev := &fakeReviewer{trigger: "requests.get"}
	if _, err := Loop(rev, Options{Cwd: dir, Prompt: "math", MaxRounds: 3, Run: run, Out: &bytes.Buffer{}}); err != nil {
		t.Fatal(err)
	}
	if rev.outcomeCalls != 0 {
		t.Errorf("clean run should ship no outcome, got %d", rev.outcomeCalls)
	}
}

// TestLoop_GivesUpAfterMaxRounds: the agent never fixes it → the loop stops at the
// cap (not clean), never spinning forever.
func TestLoop_GivesUpAfterMaxRounds(t *testing.T) {
	dir := gitInit(t)
	app := filepath.Join(dir, "app.py")
	run := func(cwd, prompt string, out io.Writer) error {
		return os.WriteFile(app, []byte("x = requests.get(url)\n"), 0o644) // always vuln
	}
	rev := &fakeReviewer{trigger: "requests.get"}
	res, err := Loop(rev, Options{Cwd: dir, Prompt: "x", MaxRounds: 2, Run: run, Out: &bytes.Buffer{}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Clean || res.Rounds != 2 || rev.calls != 2 {
		t.Errorf("want not-clean after exactly 2 rounds, got %+v (reviewer calls=%d)", res, rev.calls)
	}
}

// TestLoop_CleanFirstTry: a safe change passes review on round 1 — the agent runs
// once, no re-wake.
func TestLoop_CleanFirstTry(t *testing.T) {
	dir := gitInit(t)
	run := func(cwd, prompt string, out io.Writer) error {
		return os.WriteFile(filepath.Join(dir, "ok.py"), []byte("x = 1 + 1\n"), 0o644)
	}
	rev := &fakeReviewer{trigger: "requests.get"}
	res, err := Loop(rev, Options{Cwd: dir, Prompt: "add math", MaxRounds: 3, Run: run, Out: &bytes.Buffer{}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Clean || res.Rounds != 1 {
		t.Errorf("want clean after 1 round, got %+v", res)
	}
}
