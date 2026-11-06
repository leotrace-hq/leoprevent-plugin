package engine

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/depcheck"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/depquiet"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/notify"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/scratch"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/agent/claude"
)

// The offer is asked the agent's own way wherever it's made: the Stop's wake and /leoprevent:sca
// share DependencyPrompt. Instructions come first, then the offers, then the adapter's question.
func TestDependencyPrompt(t *testing.T) {
	t.Setenv("CLAUDE_CODE_ENTRYPOINT", "claude-desktop")
	t.Setenv("CLAUDE_CODE_ENABLE_ASK_USER_QUESTION_TOOL", "true")
	got := DependencyPrompt(claude.New(), []string{"FIX THE TURN", ""}, []string{"OFFER A", "", "OFFER B"})
	fix, a, b, ask := strings.Index(got, "FIX THE TURN"), strings.Index(got, "OFFER A"), strings.Index(got, "OFFER B"), strings.Index(got, "AskUserQuestion")
	if fix != 0 || a < fix || b < a || ask < b || !strings.Contains(got, "Fix in a new session") {
		t.Errorf("prompt =\n%s", got)
	}
	if got := DependencyPrompt(claude.New(), []string{"FIX"}, nil); got != "FIX" {
		t.Errorf("no offer, no question: %q", got)
	}
	if got := DependencyPrompt(nil, nil, []string{"OFFER"}); got != "OFFER" {
		t.Errorf("an agent with no question of its own keeps the plain one: %q", got)
	}
	if got := DependencyPrompt(claude.New(), nil, nil); got != "" {
		t.Errorf("nothing to ask: %q", got)
	}
}

// /leoprevent:sca's output has the notice as markdown first, to be written as text before any
// tool call, then the same prompt the wake would carry; with nothing to ask, the hook's own relay;
// and a scan with nothing to say still answers the developer who asked.
func TestScanReportCommandOutput(t *testing.T) {
	t.Setenv("CLAUDE_CODE_ENTRYPOINT", "claude-desktop")
	t.Setenv("CLAUDE_CODE_ENABLE_ASK_USER_QUESTION_TOOL", "true")
	rep := ScanReport{Notice: "PLAINTEXT-NOTICE", Markdown: "🛡️ LeoPrevent · dependency scan (1 package) · package-lock.json\n- x", Offer: "Ask once: \"Fix it?\"", Files: 1}
	got := rep.CommandOutput(claude.New())
	notice, ask, tool := strings.Index(got, "> 🛡️ LeoPrevent · dependency scan (1 package)"), strings.Index(got, "Ask once"), strings.Index(got, "with the AskUserQuestion tool")
	if !strings.HasPrefix(got, "[For the agent: the user cannot see this output.") || notice < 0 || ask < notice || tool < ask || !strings.Contains(got, "before you call any other tool (AskUserQuestion included)") || strings.Contains(got, "PLAINTEXT-NOTICE") {
		t.Errorf("output =\n%s", got)
	}
	for r, want := range map[*ScanReport]string{
		{Files: 3}:          "nothing high or critical in the 3 dependency files checked",
		{Files: 1}:          "in the 1 dependency file checked",
		{}:                  "no dependency files LeoPrevent reads",
		{Unavailable: true}: "not available with this license key. The dependency check may be off for your account or this repository, or the key may be invalid or revoked. Ask your LeoPrevent admin, or check your key under Plugin setup",
	} {
		out := r.CommandOutput(claude.New())
		if !strings.Contains(out, want) || !strings.Contains(out, "End your reply with exactly the markdown") || strings.Contains(out, "AskUserQuestion") || strings.Contains(out, "—") {
			t.Errorf("output for %+v =\n%s", *r, out)
		}
	}
}

// A pending offer is left once every check has finished, merged with an unanswered one of the same
// repository's; an offer that lists nothing leaves the earlier one as it is.
func TestPendingOffersAreLeftAfterTheChecks(t *testing.T) {
	sid := "router-pending-after-checks"
	t.Cleanup(func() { depquiet.TakePending(sid) })
	a := depquiet.Entry{Path: "package-lock.json", Name: "lodash", Version: "4.17.15"}
	b := depquiet.Entry{Path: "go.mod", Name: "golang.org/x/net", Version: "v0.1.0"}
	turn := routerTurn()
	turn.ev.SessionID = sid
	checks := []stopCheck{
		pendingCheck{p: pendOffer("r", "offer", []depquiet.Entry{a})},
		pendingCheck{p: pendOffer("r", "offer", []depquiet.Entry{b})},
		pendingCheck{p: pendOffer("r", "offer", nil)},
	}
	runChecks(turn, checks, io.Discard)
	p, ok := depquiet.TakePending(sid)
	if !ok || len(p.Entries) != 2 {
		t.Errorf("pending = %+v", p)
	}
}

// pendingCheck is a check that only leaves an offer pending.
type pendingCheck struct{ p *depquiet.Pending }

func (pendingCheck) name() string                                        { return "pending" }
func (pendingCheck) runsWithoutFiles() bool                              { return true }
func (pendingCheck) selectFiles([]transcript.Change) []transcript.Change { return nil }
func (c pendingCheck) run(stopTurn, []transcript.Change) stopResult      { return stopResult{pending: c.p} }

// /leoprevent:sca with a session saves its report for that turn's Stop, which delivers it once,
// as the shown session scan's notice and offer are delivered: notice, offer, what it asked and the
// offer left pending only then.
func TestTheScanReportIsDeliveredByTheStop(t *testing.T) {
	t.Cleanup(scratch.SetUserCacheDirForTest(t.TempDir()))
	sid := "router-sca-report-stop"
	now := time.Now()
	pending := &depquiet.Pending{Repo: "r", Entries: []depquiet.Entry{{Path: "package-lock.json", Name: "lodash", Version: "4.17.15"}}}
	rep := ScanReport{Notice: "🛡️ LeoPrevent · dependency scan (1 package) · package-lock.json", Offer: "Ask once: \"Fix it?\"", Files: 1,
		Asked: []string{askKey("package-lock.json", "lodash@4.17.15")}, Pending: pending}
	if !rep.SaveForStop(sid, now) {
		t.Fatal("not saved")
	}
	turn := routerTurn()
	turn.ev.SessionID, turn.now = sid, now.Add(time.Minute)
	turn.r = &fakeReviewer{}
	var names []string
	for _, c := range stopChecks(turn) {
		names = append(names, c.name())
	}
	if strings.Join(names, ",") != "code review,dependency scan (/leoprevent:sca)" {
		t.Fatalf("checks = %v", names)
	}
	res := scaReportCheck{}.run(turn, nil)
	if res.notice != rep.Notice || res.offer != rep.Offer || len(res.asked) != 1 || res.pending == nil || res.pending.Entries[0].Name != "lodash" {
		t.Errorf("result = %+v", res)
	}
	if hasScanReport(sid) {
		t.Error("delivered once: the report must be gone")
	}
	if _, ok := depquiet.TakePending(sid); ok {
		t.Error("the offer is left pending by runChecks once delivered, never by the command")
	}
	if got := (ScanReport{Files: 2}).SaveForStop("../escape", now); got {
		t.Error("a session id that isn't a plain name is refused")
	}
}

// A report whose Stop never came (Esc, a hook that failed open) isn't delivered on a later turn.
func TestAStaleScanReportIsNotDelivered(t *testing.T) {
	t.Cleanup(scratch.SetUserCacheDirForTest(t.TempDir()))
	sid := "router-sca-report-stale"
	now := time.Now()
	if !(ScanReport{Notice: "old", Files: 1}).SaveForStop(sid, now.Add(-time.Hour)) {
		t.Fatal("not saved")
	}
	if _, ok := takeScanReport(sid, now); ok {
		t.Error("an hour-old report was delivered")
	}
	if hasScanReport(sid) {
		t.Error("a stale report is removed")
	}
}

// The command's scan is the session's scan: a session whose first prompt is /leoprevent:sca
// doesn't send every file again when that turn ends, and in a folder with no git what it checked
// is recorded as seen, so gitlessCheck doesn't send it again either. The offer isn't left pending
// by the command.
func TestTheScanReportCountsAsTheSessionScan(t *testing.T) {
	t.Cleanup(scratch.SetUserCacheDirForTest(t.TempDir()))
	sid := "router-sca-report-first"
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/x\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	RunScanReport(&recordingChecker{}, nil, dir, sid, slog.New(slog.NewTextHandler(io.Discard, nil)), time.Now())
	if notify.FirstThisSession(sid, sessionScanKey) {
		t.Error("the first Stop would scan again")
	}
	files, _ := unseen(sid, dir, []depcheck.ScanFile{{Label: "go.mod", Path: filepath.Join(dir, "go.mod")}})
	if len(files) != 0 {
		t.Errorf("gitlessCheck would send again: %v", files)
	}
	if _, ok := depquiet.TakePending(sid); ok {
		t.Error("the command left an offer pending before it was asked")
	}
}

// /leoprevent:sca is the developer asking for the offer, so it's made again even for packages the
// session was already asked about (a skip, a "not now"): the request carries no Asked.
func TestTheScanReportOffersAgain(t *testing.T) {
	t.Cleanup(scratch.SetUserCacheDirForTest(t.TempDir()))
	sid := "router-sca-report-again"
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/x\n\ngo 1.22\n\nrequire golang.org/x/net v0.1.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	notify.Record(sid, askKey("go.mod", "golang.org/x/net@v0.1.0"))
	rc := &recordingChecker{}
	RunScanReport(rc, nil, dir, sid, slog.New(slog.NewTextHandler(io.Discard, nil)), time.Now())
	if len(rc.got) == 0 {
		t.Fatal("nothing was sent")
	}
	for _, req := range rc.got {
		if len(req.Asked) > 0 {
			t.Errorf("the command sent what the session was asked, so nothing would be offered again: %v", req.Asked)
		}
	}
}
