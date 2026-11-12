package engine

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/scratch"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/agent"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/agent/claude"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/agent/codex"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/agent/copilot"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/agent/cursor"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/agent/devin"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/apiclient"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/depcheck"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/notify"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/review"
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
	agent    string
	offer    string
	asked    []string
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
	return stopResult{output: []byte(f.output), notice: f.notice, noticeMarkdown: f.markdown, code: f.code, agent: f.agent, offer: f.offer, asked: f.asked}
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
	turn.r = &fakeReviewer{} // a tier with no dependency check
	if got := names(); strings.Join(got, ",") != "code review" {
		t.Errorf("no dependency check on this tier: %v", got)
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

// A dependency check that puts something to the agent wakes it once: after the code review's
// prompt, which stays as it is, or on its own. What it was asked is recorded for the session, and
// the next Stop knows to re-check. An agent whose adapter can't wake for it yet keeps the notice
// only, and nothing is recorded.
func TestTheDependencyCheckWakesTheAgentOnce(t *testing.T) {
	t.Setenv("CLAUDE_CODE_ENTRYPOINT", "cli")
	turn := routerTurn("app.go", "package-lock.json")
	turn.ev.SessionID = "router-dependency-wake"
	notify.Clear(turn.ev.SessionID)
	t.Cleanup(func() { notify.Clear(turn.ev.SessionID); takeDependencyWake(turn.ev.SessionID) })
	deps := fakeCheck{label: "deps", suffix: "package-lock.json", notice: "dependency notice", agent: "CHANGE LODASH",
		asked: []string{askKey("package-lock.json", "lodash@4.17.15")}}

	var out bytes.Buffer
	runChecks(turn, []stopCheck{fakeCheck{label: "code", always: true, output: `{"decision":"block","reason":"FIX","systemMessage":"banner"}`}, deps}, &out)
	if got := hookOutput(t, out.String()); got["decision"] != "block" || got["reason"] != "FIX\n\nCHANGE LODASH" || got["systemMessage"] != "banner\n\ndependency notice" {
		t.Errorf("with the review's wake: %v", got)
	}
	if got := notify.Recorded(turn.ev.SessionID, askPrefix("package-lock.json")); strings.Join(got, ",") != "lodash@4.17.15" {
		t.Errorf("recorded %v", got)
	}
	if !takeDependencyWake(turn.ev.SessionID) || takeDependencyWake(turn.ev.SessionID) {
		t.Error("the next Stop re-checks, once")
	}

	out.Reset()
	runChecks(turn, []stopCheck{fakeCheck{label: "code", always: true}, deps}, &out)
	if got := hookOutput(t, out.String()); got["decision"] != "block" || got["reason"] != "CHANGE LODASH" || got["systemMessage"] != "dependency notice" {
		t.Errorf("on its own: %v", got)
	}

	notify.Clear(turn.ev.SessionID)
	takeDependencyWake(turn.ev.SessionID)
	turn.a = noWake{claude.New()}
	out.Reset()
	runChecks(turn, []stopCheck{fakeCheck{label: "code", always: true}, deps}, &out)
	if strings.Contains(out.String(), "CHANGE LODASH") || notify.Recorded(turn.ev.SessionID, "deps-ask:") != nil || takeDependencyWake(turn.ev.SessionID) {
		t.Errorf("an adapter that can't wake for it: %q", out.String())
	}
}

// The session scan's offer (LEO-673) goes in the same wake as everything else, last: after the
// review's prompt and the turn's own dependency instructions, so the agent asks after doing what
// it must. In the desktop app the request to print the scan's notice comes right after the
// review's prompt, before any of that, so the developer sees the list before being asked about it;
// never the print-only relay, whose "nothing else" would forbid the question. Offered packages are recorded
// as asked. An offer on its own wakes the agent too, the terminal included. Claude adds
// AskUserQuestion only where it's switched on; without it, the plain question stands. In the
// desktop app it proposes the fix as a session of its own instead.
func TestTheScansOfferJoinsTheWakeLast(t *testing.T) {
	t.Cleanup(review.SetNonceForTest("test0nce"))
	t.Setenv("CLAUDE_CODE_ENTRYPOINT", "claude-desktop")
	t.Setenv("CLAUDE_CODE_ENABLE_ASK_USER_QUESTION_TOOL", "")
	turn := routerTurn("app.go")
	turn.ev.SessionID = "router-scan-offer"
	notify.Clear(turn.ev.SessionID)
	t.Cleanup(func() {
		notify.Clear(turn.ev.SessionID)
		takeDependencyWake(turn.ev.SessionID)
		takeRelayed(turn.ev.SessionID)
	})
	scan := fakeCheck{label: "deps", always: true, notice: "scan notice", agent: "CHANGE P1", offer: "OFFER HB",
		asked: []string{askKey("package-lock.json", "p1@0.1.7"), askKey("package-lock.json", "hb@4.0.14")}}
	review_ := fakeCheck{label: "code", always: true, output: `{"decision":"block","reason":"FIX","systemMessage":"banner"}`}

	var out bytes.Buffer
	runChecks(turn, []stopCheck{review_, scan}, &out)
	got := hookOutput(t, out.String())
	reason, _ := got["reason"].(string)
	if want := "FIX\n\n" + review.DeveloperAddendumFirst(review.DeveloperMarkdown("scan notice"), true) + "\nCHANGE P1\n\nOFFER HB\nDon't ask that question. Instead,"; !strings.HasPrefix(reason, want) || !strings.Contains(reason, "start_session") {
		t.Errorf("review, then print the notice, then the turn's instructions, then the offer, proposed as a fix session in the desktop app:\n%s\nwant a prefix of\n%s", reason, want)
	}
	if strings.Contains(reason, "and nothing else") {
		t.Errorf("never the print-only relay with an offer:\n%s", reason)
	}
	if got := strings.Join(notify.Recorded(turn.ev.SessionID, askPrefix("package-lock.json")), ","); !strings.Contains(got, "hb@4.0.14") || !strings.Contains(got, "p1@0.1.7") {
		t.Errorf("offered packages are recorded as asked: %s", got)
	}

	notify.Clear(turn.ev.SessionID)
	takeDependencyWake(turn.ev.SessionID)
	t.Setenv("CLAUDE_CODE_ENTRYPOINT", "cli")
	out.Reset()
	runChecks(turn, []stopCheck{fakeCheck{label: "code", always: true}, fakeCheck{label: "deps", always: true, notice: "scan notice", offer: "OFFER HB"}}, &out)
	got = hookOutput(t, out.String())
	if got["decision"] != "block" || got["reason"] != "OFFER HB" || got["systemMessage"] != "scan notice" {
		t.Errorf("an offer on its own wakes the agent in the terminal: %v", got)
	}

	t.Setenv("CLAUDE_CODE_ENABLE_ASK_USER_QUESTION_TOOL", "true")
	notify.Clear(turn.ev.SessionID)
	takeDependencyWake(turn.ev.SessionID)
	out.Reset()
	runChecks(turn, []stopCheck{fakeCheck{label: "code", always: true}, fakeCheck{label: "deps", always: true, offer: "OFFER HB"}}, &out)
	if got := hookOutput(t, out.String()); !strings.HasPrefix(got["reason"].(string), "OFFER HB\nInstead of writing that question at the end of your reply, ask it with the AskUserQuestion tool") {
		t.Errorf("with AskUserQuestion switched on: %v", got["reason"])
	}
	for name, a := range map[string]agent.Agent{"codex": codex.New(), "devin": devin.New()} {
		if _, ok := a.(offerQuestioner); ok {
			t.Errorf("%s keeps the plain question", name)
		}
	}
}

// failingChecker answers every request with err, counting the requests that reach it.
type failingChecker struct {
	fakeReviewer
	err   error
	calls int
}

func (f *failingChecker) CheckDependencies(wire.DependenciesRequest) (wire.DependenciesResponse, error) {
	f.calls++
	return wire.DependenciesResponse{}, f.err
}

// A 404 from /dependencies means the server has no dependency check, which won't change during
// the session, so the check is off for the rest of it: the request that got the 404 is the last
// one sent, and later Stops have no dependency check at all. A 503 or a timeout only fails that
// Stop, and the next one tries again.
func TestA404TurnsTheDependencyCheckOffForTheSession(t *testing.T) {
	for name, tc := range map[string]struct {
		err error
		off bool
	}{
		"404":     {&apiclient.StatusError{Path: "/dependencies", Status: 404}, true},
		"503":     {&apiclient.StatusError{Path: "/dependencies", Status: 503}, false},
		"timeout": {errors.New("context deadline exceeded"), false},
	} {
		t.Run(name, func(t *testing.T) {
			session := "router-deps-" + name
			notify.Clear(session)
			t.Cleanup(func() { notify.Clear(session) })
			fc := &failingChecker{err: tc.err}
			c := stamped{checker: fc, trigger: wire.DependencyTriggerTurn, sessionID: session}
			for i := 0; i < 3; i++ {
				_, err := c.CheckDependencies(wire.DependenciesRequest{Ecosystem: "npm", Path: "package-lock.json"})
				if errors.Is(err, depcheck.ErrUnavailable) != tc.off {
					t.Errorf("request %d: %v is unavailable: %v, want %v", i, err, errors.Is(err, depcheck.ErrUnavailable), tc.off)
				}
			}
			if want := map[bool]int{true: 1, false: 3}[tc.off]; fc.calls != want {
				t.Errorf("%d requests reached the server, want %d", fc.calls, want)
			}
			turn := routerTurn()
			turn.r, turn.ev.SessionID = fc, session
			notify.FirstThisSession(session, sessionScanKey) // a later Stop, not the scan
			names := []string{}
			for _, ch := range stopChecks(turn) {
				names = append(names, ch.name())
			}
			if got, want := strings.Join(names, ","), map[bool]string{true: "code review", false: "code review,dependency check"}[tc.off]; got != want {
				t.Errorf("later Stop's checks: %s, want %s", got, want)
			}
			if dependenciesUnavailable(session) != tc.off {
				t.Errorf("off for the session: %v, want %v", dependenciesUnavailable(session), tc.off)
			}
		})
	}
	if dependenciesUnavailable("") {
		t.Error("no session, nothing recorded")
	}
}

// The re-check's follow-up (LEO-672) wakes the agent once, after the review's notices on that
// Stop: its packages are recorded as asked, and it's marked so the Stop after it reports only.
// Cursor, whose hook stops after two follow-ups, gets none after a review's fix check, and one
// after a dependency-only wake.
func TestTheFollowUpWakesOnceAfterTheFixCheck(t *testing.T) {
	t.Setenv("CLAUDE_CODE_ENTRYPOINT", "cli")
	session := "router-follow-up"
	notify.Clear(session)
	t.Cleanup(func() {
		notify.Clear(session)
		takeDependencyWake(session)
		takeDependencyWake(session + followUpSuffix)
	})
	ev := agent.Event{SessionID: session, Cwd: "/tmp"}
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	dep := recheckResult{notice: "still open", followUp: "PIN QS", asked: []string{askKey("package-lock.json", "qs@6.7.0")}}

	var out bytes.Buffer
	deliverAfterWake(claude.New(), ev, []string{"your fix is still vulnerable"}, dep, true, quiet, &out)
	got := hookOutput(t, out.String())
	if got["decision"] != "block" || got["reason"] != "PIN QS" || !strings.HasPrefix(fmt.Sprint(got["systemMessage"]), "your fix is still vulnerable") {
		t.Errorf("the review's notice first, then the follow-up: %v", got)
	}
	if strings.Join(notify.Recorded(session, askPrefix("package-lock.json")), ",") != "qs@6.7.0" {
		t.Error("the follow-up's packages are recorded as asked")
	}
	if !takeDependencyWake(session) || !takeDependencyWake(session+followUpSuffix) {
		t.Error("the Stop after the follow-up re-checks, and knows it's the one after a follow-up")
	}

	cu := cursor.New()
	if _, err := cu.ParseEvent([]byte(`{"hook_event_name":"stop","status":"completed","conversation_id":"router-follow-up-cursor","cwd":"/tmp"}`)); err != nil {
		t.Fatal(err)
	}
	cev := agent.Event{SessionID: "router-follow-up-cursor", Cwd: "/tmp"}
	t.Cleanup(func() {
		notify.Clear(cev.SessionID)
		takeDependencyWake(cev.SessionID)
		takeDependencyWake(cev.SessionID + followUpSuffix)
	})
	out.Reset()
	deliverAfterWake(cu, cev, nil, dep, true, quiet, &out)
	if strings.Contains(out.String(), "PIN QS") || takeDependencyWake(cev.SessionID+followUpSuffix) {
		t.Errorf("Cursor after a review's fix check: no follow-up: %s", out.String())
	}
	out.Reset()
	deliverAfterWake(cu, cev, nil, dep, false, quiet, &out)
	if !strings.Contains(out.String(), "PIN QS") || !takeDependencyWake(cev.SessionID+followUpSuffix) {
		t.Errorf("Cursor after a dependency-only wake: one follow-up: %s", out.String())
	}
}

// noWake is an adapter with only the Agent methods: no way to wake for the dependency check.
type noWake struct{ agent.Agent }

// Every adapter wakes for the dependency check in its own shape, the review's prompt kept first.
func TestEveryAdapterWakesForTheDependencyCheck(t *testing.T) {
	review := `{"decision":"block","reason":"FIX","systemMessage":"banner"}`
	for name, w := range map[string]dependencyWaker{"claude": claude.New(), "codex": codex.New(), "devin": devin.New()} {
		got := hookOutput(t, string(mustWake(t, w, review)))
		if got["decision"] != "block" || got["reason"] != "FIX\n\nDEPS" || got["systemMessage"] != "banner" {
			t.Errorf("%s: %v", name, got)
		}
	}
	cp := copilot.New()
	if _, err := cp.ParseEvent([]byte(`{"hookEventName":"Stop","sessionId":"router-copilot-wake","cwd":"/tmp"}`)); err != nil {
		t.Fatal(err)
	}
	got := hookOutput(t, string(mustWake(t, cp, "")))
	hso, _ := got["hookSpecificOutput"].(map[string]any)
	if got["reason"] != "DEPS" || hso["decision"] != "block" || hso["reason"] != "DEPS" {
		t.Errorf("copilot: %v", got)
	}
	// Its guard is armed with what was delivered: the wake's own Stop is let through.
	ev, err := copilot.New().ParseEvent([]byte(`{"hookEventName":"Stop","sessionId":"router-copilot-wake","cwd":"/tmp"}`))
	if err != nil || !ev.StopHookActive {
		t.Errorf("copilot's next Stop: %+v %v", ev, err)
	}
	cu := cursor.New()
	if _, err := cu.ParseEvent([]byte(`{"hook_event_name":"stop","status":"completed","conversation_id":"router-cursor-wake","cwd":"/tmp"}`)); err != nil {
		t.Fatal(err)
	}
	if got := hookOutput(t, string(mustWake(t, cu, `{"followup_message":"banner\n\nFIX"}`))); got["followup_message"] != "banner\n\nFIX\n\nDEPS" {
		t.Errorf("cursor: %v", got)
	}
	if ev, err := cursor.New().ParseEvent([]byte(`{"hook_event_name":"stop","status":"completed","conversation_id":"router-cursor-wake","cwd":"/tmp"}`)); err != nil || !ev.StopHookActive {
		t.Errorf("cursor's next Stop: %+v %v", ev, err)
	}
}

// Every adapter whose client shows no Stop systemMessage relays the developer's notice through
// its own wake (LEO-662): Devin and Copilot with decision/reason (Copilot in both dialects, its
// guard re-armed so the relay's own Stop is let through), Cursor with followup_message (its digest
// recorded). On its own the agent is asked only to print it; after a review's wake, the review's
// instructions stay first. What it was asked to print is recorded, so it's stripped before
// /outcome. Codex shows a systemMessage, so its notice stays one and nothing is relayed.
func TestEveryAdapterRelaysTheDevelopersNotice(t *testing.T) {
	t.Cleanup(review.SetNonceForTest("test0nce"))
	const notice = "🛡️ LeoPrevent · dependency check (1 package) · package-lock.json\nlodash 4.17.15 has 1 high vulnerability."
	md := review.DeveloperMarkdown(notice)
	deliver := func(a agent.Agent, session, out string) map[string]any {
		t.Helper()
		turn := routerTurn()
		turn.a, turn.ev.SessionID = a, session
		t.Cleanup(func() { takeRelayed(session) })
		return hookOutput(t, string(deliverForDeveloper(turn, []byte(out), notice, "", "")))
	}

	got := deliver(devin.New(), "router-devin-relay", "")
	if got["decision"] != "block" || got["reason"] != review.DeveloperRelayPrompt(md) || got["systemMessage"] != notice {
		t.Errorf("devin, on its own: %v", got)
	}
	if takeRelayed("router-devin-relay") != md {
		t.Error("devin: the printed notice is recorded for the strip before /outcome")
	}
	got = deliver(devin.New(), "router-devin-relay", `{"decision":"block","reason":"FIX","systemMessage":"banner"}`)
	if got["reason"] != "FIX\n\n"+review.DeveloperAddendum(md) || got["systemMessage"] != "banner\n\n"+notice {
		t.Errorf("devin, after a review's wake: %v", got)
	}

	cp := copilot.New()
	if _, err := cp.ParseEvent([]byte(`{"hookEventName":"Stop","sessionId":"router-copilot-relay","cwd":"/tmp"}`)); err != nil {
		t.Fatal(err)
	}
	got = deliver(cp, "router-copilot-relay", "")
	hso, _ := got["hookSpecificOutput"].(map[string]any)
	if got["decision"] != "block" || got["reason"] != review.DeveloperRelayPrompt(md) || hso["decision"] != "block" || hso["reason"] != got["reason"] {
		t.Errorf("copilot, both dialects: %v", got)
	}
	if ev, err := copilot.New().ParseEvent([]byte(`{"hookEventName":"Stop","sessionId":"router-copilot-relay","cwd":"/tmp"}`)); err != nil || !ev.StopHookActive {
		t.Errorf("copilot's next Stop is let through: %+v %v", ev, err)
	}
	if takeRelayed("router-copilot-relay") != md {
		t.Error("copilot: the printed notice is recorded")
	}

	cu := cursor.New()
	if _, err := cu.ParseEvent([]byte(`{"hook_event_name":"stop","status":"completed","conversation_id":"router-cursor-relay","cwd":"/tmp"}`)); err != nil {
		t.Fatal(err)
	}
	got = deliver(cu, "router-cursor-relay", `{"followup_message":"banner\n\nFIX"}`)
	if got["followup_message"] != "banner\n\nFIX\n\n"+review.DeveloperAddendum(md) {
		t.Errorf("cursor, after a review's follow-up: %v", got)
	}
	if ev, err := cursor.New().ParseEvent([]byte(`{"hook_event_name":"stop","status":"completed","conversation_id":"router-cursor-relay","cwd":"/tmp"}`)); err != nil || !ev.StopHookActive {
		t.Errorf("cursor's next Stop is the one after the relay: %+v %v", ev, err)
	}
	got = deliver(cu, "router-cursor-relay", "{}")
	if got["followup_message"] != review.DeveloperRelayPrompt(md) {
		t.Errorf("cursor, on its own: %v", got)
	}
	if takeRelayed("router-cursor-relay") != md {
		t.Error("cursor: the printed notice is recorded")
	}

	got = deliver(codex.New(), "router-codex-relay", `{"decision":"block","reason":"FIX","systemMessage":"banner"}`)
	if got["reason"] != "FIX" || got["systemMessage"] != "banner\n\n"+notice {
		t.Errorf("codex keeps the systemMessage: %v", got)
	}
	if takeRelayed("router-codex-relay") != "" {
		t.Error("codex: nothing relayed")
	}
}

func mustWake(t *testing.T, w dependencyWaker, out string) []byte {
	t.Helper()
	b, err := w.WakeForDependencies([]byte(out), "DEPS")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// answeringChecker answers every request with an agent message naming lodash.
type answeringChecker struct{ got []wire.DependenciesRequest }

func (a *answeringChecker) CheckDependencies(req wire.DependenciesRequest) (wire.DependenciesResponse, error) {
	a.got = append(a.got, req)
	msg := "CHANGE LODASH"
	return wire.DependenciesResponse{Messages: wire.DependencyMessages{Agent: &msg, AgentPackages: []string{"lodash@4.17.15"}}}, nil
}

// Each request says what in its file the agent has already been asked about this session, and
// what the answer puts to the agent is gathered, keyed by the file, to be recorded on a wake.
func TestDependencyRequestsSayWhatWasAsked(t *testing.T) {
	session := "router-asked"
	notify.Clear(session)
	t.Cleanup(func() { notify.Clear(session) })
	notify.Record(session, askKey("web/package-lock.json", "qs@6.5.2"), askKey("web/package-lock.json", "debug@2.6.8"), askKey("api/go.mod", "x@1.0.0"))
	ac := &answeringChecker{}
	put := &askedKeys{}
	c := stamped{checker: ac, trigger: wire.DependencyTriggerTurn, sessionID: session, put: put}
	if _, err := c.CheckDependencies(wire.DependenciesRequest{Ecosystem: "npm", Path: "web/package-lock.json"}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(ac.got[0].Asked, ","); got != "debug@2.6.8,qs@6.5.2" {
		t.Errorf("asked %q: only this file's, sorted", got)
	}
	if got := put.list(); strings.Join(got, ",") != askKey("web/package-lock.json", "lodash@4.17.15") {
		t.Errorf("gathered %v", got)
	}
	// A test area's answer never reaches the agent, so nothing from it is gathered.
	if _, err := c.CheckDependencies(wire.DependenciesRequest{Ecosystem: "npm", Path: "e2e/package-lock.json"}); err != nil {
		t.Fatal(err)
	}
	if got := put.list(); len(got) != 1 {
		t.Errorf("a test area's packages were gathered: %v", got)
	}
	// With no session, nothing is said or gathered beyond the response.
	ac2 := &answeringChecker{}
	if _, err := (stamped{checker: ac2}).CheckDependencies(wire.DependenciesRequest{Path: "web/package-lock.json"}); err != nil || ac2.got[0].Asked != nil {
		t.Errorf("no session: %v %v", err, ac2.got[0].Asked)
	}
}

// The wake mark is taken by exactly one Stop, however many overlap.
func TestTheDependencyWakeIsTakenOnce(t *testing.T) {
	session := "router-wake-once"
	t.Cleanup(func() { takeDependencyWake(session) })
	for round := 0; round < 20; round++ {
		rememberDependencyWake(session, slog.New(slog.NewTextHandler(io.Discard, nil)))
		var took atomic.Int32
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if takeDependencyWake(session) {
					took.Add(1)
				}
			}()
		}
		wg.Wait()
		if n := took.Load(); n != 1 {
			t.Fatalf("round %d: the mark was taken %d times, want 1", round, n)
		}
	}
}

// A session ID can't place a wake mark outside its folder: only its last element is used, and every
// mark is opened through the folder's os.Root.
func TestTheWakeMarkStaysInItsFolder(t *testing.T) {
	session := "../../wake-escape"
	t.Cleanup(func() { takeDependencyWake(session) })
	rememberDependencyWake(session, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if _, err := os.Stat(filepath.Join(scratch.Dir("dependency-wake"), "wake-escape")); err != nil {
		t.Fatalf("the mark isn't in its folder: %v", err)
	}
	if !takeDependencyWake(session) {
		t.Error("the mark wasn't taken")
	}
}
