package engine

import (
	"bytes"
	"io"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/agent/claude"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/notify"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

// fakeCheck is a check whose file choice, output and timing a test sets.
type fakeCheck struct {
	label    string
	suffix   string // selects changed files ending in this
	always   bool
	output   string
	notice   string
	markdown string
	code     int
	delay    time.Duration
	runs     *atomic.Int32
	gotFiles *[]string
}

func (f fakeCheck) name() string           { return f.label }
func (f fakeCheck) runsWithoutFiles() bool { return f.always }
func (f fakeCheck) selectFiles(changes []transcript.Change) []transcript.Change {
	var out []transcript.Change
	for _, c := range changes {
		if strings.HasSuffix(c.FilePath, f.suffix) {
			out = append(out, c)
		}
	}
	return out
}
func (f fakeCheck) run(_ stopTurn, files []transcript.Change) stopResult {
	if f.runs != nil {
		f.runs.Add(1)
	}
	if f.gotFiles != nil {
		for _, c := range files {
			*f.gotFiles = append(*f.gotFiles, c.FilePath)
		}
	}
	time.Sleep(f.delay)
	return stopResult{output: []byte(f.output), notice: f.notice, noticeMarkdown: f.markdown, code: f.code}
}

func routerTurn(paths ...string) stopTurn {
	var changes []transcript.Change
	for _, p := range paths {
		changes = append(changes, transcript.Change{FilePath: p})
	}
	return stopTurn{a: claude.New(), log: slog.New(slog.NewTextHandler(io.Discard, nil)), changes: changes}
}

// Each check gets only the files it selects; a check with none doesn't run unless it runs
// without files; a file two checks select goes to both.
func TestTheRouterGivesEachCheckItsOwnFiles(t *testing.T) {
	var codeFiles, lockFiles []string
	var lockRuns, idleRuns atomic.Int32
	checks := []stopCheck{
		fakeCheck{label: "code", suffix: "", always: true, gotFiles: &codeFiles},
		fakeCheck{label: "deps", suffix: "go.mod", gotFiles: &lockFiles, runs: &lockRuns},
		fakeCheck{label: "idle", suffix: ".never", runs: &idleRuns},
	}
	runChecks(routerTurn("app.go", "go.mod"), checks, io.Discard)
	if strings.Join(codeFiles, ",") != "app.go,go.mod" || strings.Join(lockFiles, ",") != "go.mod" {
		t.Errorf("code got %v, deps got %v", codeFiles, lockFiles)
	}
	if lockRuns.Load() != 1 || idleRuns.Load() != 0 {
		t.Errorf("deps ran %d times, idle ran %d times", lockRuns.Load(), idleRuns.Load())
	}
	codeFiles = nil
	runChecks(routerTurn(), checks, io.Discard)
	if lockRuns.Load() != 1 {
		t.Error("a check with no files of its own doesn't run")
	}
}

// The checks run at the same time: the Stop takes as long as the slowest, not the sum.
func TestTheRouterRunsChecksAtTheSameTime(t *testing.T) {
	checks := []stopCheck{
		fakeCheck{label: "a", always: true, delay: 300 * time.Millisecond},
		fakeCheck{label: "b", always: true, delay: 300 * time.Millisecond},
	}
	start := time.Now()
	runChecks(routerTurn("x"), checks, io.Discard)
	if took := time.Since(start); took > 550*time.Millisecond {
		t.Errorf("took %s, want about 300ms (run together, not one after the other)", took)
	}
}

// One combined delivery: the code review's output as it is, every notice joined into its
// systemMessage, and the exit code from the check that owns it. A third check needs no change
// to the router.
func TestTheRouterCombinesResultsIntoOneDelivery(t *testing.T) {
	t.Setenv("CLAUDE_CODE_ENTRYPOINT", "cli")
	var out bytes.Buffer
	code := runChecks(routerTurn("app.go", "go.mod", "LICENSE"), []stopCheck{
		fakeCheck{label: "code", always: true, output: `{"decision":"block","reason":"FIX","systemMessage":"banner"}`, code: 0},
		fakeCheck{label: "deps", suffix: "go.mod", notice: "dependency notice"},
		fakeCheck{label: "licences", suffix: "LICENSE", notice: "licence notice"},
	}, &out)
	got := hookOutput(t, out.String())
	if got["decision"] != "block" || got["reason"] != "FIX" || got["systemMessage"] != "banner\n\ndependency notice\n\nlicence notice" || code != 0 {
		t.Errorf("combined: %v (code %d)", got, code)
	}
	// Nothing printed by the code review: the notices alone, as a plain notice.
	out.Reset()
	runChecks(routerTurn("go.mod"), []stopCheck{
		fakeCheck{label: "code", always: true},
		fakeCheck{label: "deps", suffix: "go.mod", notice: "dependency notice"},
	}, &out)
	if got := hookOutput(t, out.String()); got["systemMessage"] != "dependency notice" || got["decision"] != nil {
		t.Errorf("notice alone: %v", got)
	}
	// Nothing to say at all: nothing printed.
	out.Reset()
	runChecks(routerTurn("go.mod"), []stopCheck{fakeCheck{label: "code", always: true}, fakeCheck{label: "deps", suffix: "go.mod"}}, &out)
	if out.Len() != 0 {
		t.Errorf("quiet: %q", out.String())
	}
}

// The dependency check selects the files a reader reads, and never a deleted or virtual one.
func TestTheDependencyCheckSelectsFromTheReaders(t *testing.T) {
	got := dependencyCheck{}.selectFiles([]transcript.Change{
		{FilePath: "web/package-lock.json"}, {FilePath: "api/go.mod"}, {FilePath: "npm-shrinkwrap.json"},
		{FilePath: "package.json"}, {FilePath: "go.sum"}, {FilePath: "src/app.ts"},
		{FilePath: "old/package-lock.json", Deleted: true}, {FilePath: "mcp/go.mod", Virtual: true},
	})
	var paths []string
	for _, c := range got {
		paths = append(paths, c.FilePath)
	}
	if strings.Join(paths, ",") != "web/package-lock.json,api/go.mod,npm-shrinkwrap.json" {
		t.Errorf("selected %v", paths)
	}
	if all := (codeReviewCheck{}).selectFiles([]transcript.Change{{FilePath: "a"}, {FilePath: "b"}}); len(all) != 2 {
		t.Error("the code review takes every changed file; its own gate decides")
	}
}

// Where the notice is relayed, the agent prints each check's markdown, or its text when it has
// none; the systemMessage is the text either way.
func TestTheRouterRelaysEachChecksMarkdown(t *testing.T) {
	t.Setenv("CLAUDE_CODE_ENTRYPOINT", "claude-desktop")
	turn := routerTurn("go.mod", "LICENSE")
	turn.ev.SessionID = "router-markdown"
	t.Cleanup(func() { takeRelayed("router-markdown") })
	var out bytes.Buffer
	runChecks(turn, []stopCheck{
		fakeCheck{label: "code", always: true},
		fakeCheck{label: "deps", suffix: "go.mod", notice: "deps text", markdown: "deps [md](u)"},
		fakeCheck{label: "licences", suffix: "LICENSE", notice: "licence text"},
	}, &out)
	got := hookOutput(t, out.String())
	reason, _ := got["reason"].(string)
	if !strings.Contains(reason, "> deps [md](u)\n>\n> licence text") || got["systemMessage"] != "deps text\n\nlicence text" {
		t.Errorf("relayed: %v", got)
	}
	if relayed := takeRelayed("router-markdown"); !strings.Contains(relayed, "deps [md](u)") {
		t.Errorf("the markdown printed is what the next Stop removes: %q", relayed)
	}
}

// scanChecker is a dependency checker for the session-scan test; it's never called there.
type scanChecker struct{ fakeReviewer }

func (scanChecker) CheckDependencies(wire.DependenciesRequest) (wire.DependenciesResponse, error) {
	return wire.DependenciesResponse{}, nil
}

// The session's first Stop has the dependency scan, which runs even with no changed files; every
// later Stop has the per-turn dependency check. Off, neither.
func TestTheSessionScanIsTheFirstStopsDependencyCheck(t *testing.T) {
	t.Setenv("LEOPREVENT_SEND_DEPENDENCIES", "on")
	turn := routerTurn()
	turn.r = &scanChecker{}
	turn.ev.SessionID = "router-session-scan"
	notify.Clear(turn.ev.SessionID)
	t.Cleanup(func() { notify.Clear(turn.ev.SessionID) })
	names := func() []string {
		var out []string
		for _, c := range stopChecks(turn) {
			out = append(out, c.name())
		}
		return out
	}
	if got := names(); strings.Join(got, ",") != "code review,dependency scan" {
		t.Errorf("first Stop: %v", got)
	}
	if !(sessionScanCheck{}).runsWithoutFiles() {
		t.Error("the scan runs even when the turn changed nothing")
	}
	for i := 0; i < 2; i++ {
		if got := names(); strings.Join(got, ",") != "code review,dependency check" {
			t.Errorf("later Stop: %v", got)
		}
	}
	t.Setenv("LEOPREVENT_SEND_DEPENDENCIES", "")
	notify.Clear(turn.ev.SessionID)
	if got := names(); strings.Join(got, ",") != "code review" {
		t.Errorf("switched off: %v", got)
	}
}

// recordingChecker keeps the requests it's sent.
type recordingChecker struct{ got []wire.DependenciesRequest }

func (r *recordingChecker) CheckDependencies(req wire.DependenciesRequest) (wire.DependenciesResponse, error) {
	r.got = append(r.got, req)
	return wire.DependenciesResponse{}, nil
}

// Every dependency request carries who and where, what ran it, and its scan, and never the
// prompt or token counts.
func TestDependencyRequestsAreStamped(t *testing.T) {
	rec := &recordingChecker{}
	meta := &wire.TurnMeta{Agent: "claude", Repo: "github.com/acme/web"}
	c := stamped{checker: rec, meta: meta, trigger: wire.DependencyTriggerScan, scanID: "s1"}
	if _, err := c.CheckDependencies(wire.DependenciesRequest{Ecosystem: "npm"}); err != nil {
		t.Fatal(err)
	}
	if r := rec.got[0]; r.Meta != meta || r.Trigger != "scan" || r.ScanID != "s1" || r.Ecosystem != "npm" {
		t.Errorf("sent %+v", r)
	}
	turn := routerTurn()
	turn.ev.SessionID = "router-stamp"
	m := dependencyMeta(turn)
	if m.Agent != "claude" || m.Prompt != "" || m.InputTokens != 0 || m.DurationMs != 0 {
		t.Errorf("identity only: %+v", m)
	}
	if a, b := newScanID(), newScanID(); a == "" || a == b || len(a) != 24 {
		t.Errorf("scan ids %q, %q", a, b)
	}
}
