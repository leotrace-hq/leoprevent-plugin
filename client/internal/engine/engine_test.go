package engine

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/agent"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/agent/claude"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/agent/codex"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/notify"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/outcome"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/review"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/vcs"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

// fakeReviewer records whether it was called and returns a scripted result.
// reasonCall is one reasons-only resolution (the next-turn ticket capture).
type reasonCall struct {
	ReviewID string
	Prompt   string
	Reply    string
	Findings []wire.Finding
}

type fakeReviewer struct {
	reasonCalls []reasonCall
	reasonErr   error

	prompt     string
	pending    *outcome.Pending
	err        error
	called     bool
	gotChanges []transcript.Change
	gotMeta    wire.TurnMeta

	shipped            bool
	shippedPending     outcome.Pending
	shippedAfter       []transcript.Change
	shippedResponse    string
	shippedMeta        wire.TurnMeta
	outcomeStillFiring []wire.Finding // what ShipOutcome reports still firing (re-verify)
	outcomePreFiring   []wire.Finding // pre-existing still firing → seeds the cross-turn ledger
	shipErr            error          // ShipOutcome error (e.g. wrapping outcome.ErrUnscored)

	resolutionCalls       int
	resolutionPending     outcome.Pending
	resolutionAfter       []transcript.Change
	resolutionStillFiring []wire.Finding // what ShipResolution reports still open
	resolutionErr         error          // ShipResolution error (e.g. wrapping outcome.ErrUnscored)
	resolutionDelay       time.Duration  // per-call sleep, to exercise the pass budget

	telemetryCalls   int
	telemetryReason  string
	telemetryChanged int
	telemetryMeta    wire.TurnMeta
}

func (f *fakeReviewer) Review(_ string, ch []transcript.Change, meta wire.TurnMeta) (Result, error) {
	f.called = true
	f.gotChanges = ch
	f.gotMeta = meta
	return Result{Prompt: f.prompt, Pending: f.pending}, f.err
}

func (f *fakeReviewer) ShipOutcome(p outcome.Pending, after []transcript.Change, agentResponse string, meta wire.TurnMeta) ([]wire.Finding, []wire.Finding, error) {
	f.shipped = true
	f.shippedPending = p
	f.shippedAfter = after
	f.shippedResponse = agentResponse
	f.shippedMeta = meta
	if f.shipErr != nil {
		return nil, nil, f.shipErr
	}
	return f.outcomeStillFiring, f.outcomePreFiring, nil
}

// reasonCalls records the reasons-only resolutions — the next-turn ticket capture.
func (f *fakeReviewer) ShipReasons(p outcome.Pending, prompt, reply string, _ wire.TurnMeta) error {
	f.reasonCalls = append(f.reasonCalls, reasonCall{ReviewID: p.ReviewID, Prompt: prompt, Reply: reply, Findings: p.Findings})
	return f.reasonErr
}

func (f *fakeReviewer) ShipResolution(p outcome.Pending, after []transcript.Change, _ wire.TurnMeta) ([]wire.Finding, error) {
	f.resolutionCalls++
	f.resolutionPending = p
	f.resolutionAfter = after
	if f.resolutionDelay > 0 {
		time.Sleep(f.resolutionDelay)
	}
	if f.resolutionErr != nil {
		return nil, f.resolutionErr
	}
	return f.resolutionStillFiring, nil
}

func (f *fakeReviewer) ShipTelemetry(meta wire.TurnMeta, reason string, changedFiles int) error {
	f.telemetryCalls++
	f.telemetryReason = reason
	f.telemetryChanged = changedFiles
	f.telemetryMeta = meta
	return nil
}

// runWith drives the engine for a given agent + reviewer. It mirrors main:
// parse the stdin into an Event (failing open on a parse error), then Run.
func runWith(a agent.Agent, r Reviewer, stdin string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	ev, err := a.ParseEvent([]byte(stdin))
	if err != nil {
		fmt.Fprintf(&stderr, "leoprevent[%s]: parse stdin: %v (failing open)\n", a.Name(), err)
		return 0, stdout.String(), stderr.String()
	}
	code := Run(a, r, ev, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

// run uses the claude adapter and a reviewer that should never be reached.
func run(t *testing.T, stdin string) (int, string, string) {
	t.Helper()
	r := &fakeReviewer{prompt: "SHOULD-NOT-BE-DELIVERED"}
	code, stdout, stderr := runWith(claude.New(), r, stdin)
	if r.called {
		t.Errorf("reviewer should not have been called for stdin %q", stdin)
	}
	return code, stdout, stderr
}

// Fail-open contract: any error → exit 0, no stdout.

func TestFailOpenEmptyStdin(t *testing.T) {
	code, stdout, _ := run(t, "")
	if code != 0 || stdout != "" {
		t.Errorf("expected silent exit 0, got code=%d stdout=%q", code, stdout)
	}
}

func TestFailOpenGarbageStdin(t *testing.T) {
	code, stdout, stderr := run(t, "not json {{{")
	if code != 0 || stdout != "" {
		t.Errorf("expected silent exit 0, got code=%d stdout=%q", code, stdout)
	}
	if stderr == "" {
		t.Error("expected error logged to stderr")
	}
	if !strings.Contains(stderr, "claude") {
		t.Errorf("stderr should name the agent, got %q", stderr)
	}
}

func TestFailOpenMissingTranscript(t *testing.T) {
	code, stdout, _ := run(t, `{"stop_hook_active":false,"transcript_path":"/nonexistent/x.jsonl","cwd":"/tmp"}`)
	if code != 0 || stdout != "" {
		t.Errorf("expected silent exit 0, got code=%d stdout=%q", code, stdout)
	}
}

// Per-turn guard: stop_hook_active=true → silent allow, reviewer never reached.

func TestStopHookActiveAllowsStop(t *testing.T) {
	code, stdout, stderr := run(t, `{"stop_hook_active":true,"transcript_path":"/nonexistent/x.jsonl"}`)
	if code != 0 || stdout != "" || stderr != "" {
		t.Errorf("expected fully silent, got code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

// A BLOCK persists the pending outcome so the next Stop can score the agent's fix.
func TestBlockPersistsPendingOutcome(t *testing.T) {
	session := "engine-persist-test"
	t.Cleanup(func() { outcome.Clear(session) })
	tp := writeTranscript(t,
		`{"type":"user","message":{"role":"user","content":"add a route"}}`,
		`{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","name":"Write","input":{"file_path":"/p/app.py","content":"resp = requests.get(url)"}}]}}`,
	)
	r := &fakeReviewer{prompt: "FIX THIS", pending: &outcome.Pending{ReviewID: "rid-2"}}
	stdin := fmt.Sprintf(`{"stop_hook_active":false,"session_id":%q,"transcript_path":%q,"cwd":""}`, session, tp)
	if code, stdout, _ := runWith(claude.New(), r, stdin); code != 0 || stdout == "" {
		t.Fatalf("expected a re-wake delivered, code=%d stdout=%q", code, stdout)
	}
	got, ok := outcome.Take(session)
	if !ok || got.ReviewID != "rid-2" {
		t.Errorf("block must persist the pending outcome, got ok=%v %+v", ok, got)
	}
}

// The post-re-wake Stop (stop_hook_active=true) ships the pending outcome — the
// agent's reply (last_assistant_message) included — WITHOUT re-running the review,
// and stays silent. No pending → nothing shipped.
func TestSecondStopShipsOutcome(t *testing.T) {
	session := "engine-ship-test"
	t.Cleanup(func() { outcome.Clear(session) })
	if err := outcome.Remember(session, outcome.Pending{ReviewID: "rid-1", Findings: []wire.Finding{{Rule: "ssrf"}}}); err != nil {
		t.Fatal(err)
	}
	r := &fakeReviewer{}
	stdin := fmt.Sprintf(`{"stop_hook_active":true,"session_id":%q,"transcript_path":"/nonexistent/x.jsonl","last_assistant_message":"I resolved the URL to an IP."}`, session)
	code, stdout, _ := runWith(claude.New(), r, stdin)
	if code != 0 || stdout != "" {
		t.Errorf("second stop must be silent, got code=%d stdout=%q", code, stdout)
	}
	if r.called {
		t.Error("Review must NOT run on the post-re-wake stop")
	}
	if !r.shipped || r.shippedPending.ReviewID != "rid-1" || r.shippedResponse != "I resolved the URL to an IP." {
		t.Errorf("outcome not shipped correctly: shipped=%v pending=%+v response=%q", r.shipped, r.shippedPending, r.shippedResponse)
	}
}

// The shipped reply is the agent's WHOLE post-re-wake prose, not the Stop stdin's
// last_assistant_message.
//
// ⚠️ THIS IS THE REGRESSION GUARD. Reverting engine.Run to pass
// `ev.LastAssistantMessage` makes this fail and nothing else does: the outcome still
// ships, the dashboard still renders, and the field still has plausible text in it —
// just the closing sentence rather than the reasoning. It was only caught by reading
// a card in the prevention log and noticing the argument was missing.
func TestSecondStopShipsTheWholePostRewakeReply(t *testing.T) {
	session := "engine-reply-capture"
	t.Cleanup(func() { outcome.Clear(session) })
	if err := outcome.Remember(session, outcome.Pending{ReviewID: "rid-1", Findings: []wire.Finding{{Rule: "ssrf"}}}); err != nil {
		t.Fatal(err)
	}

	// A turn shaped like a real one: the agent argues, runs a tool, then signs off. The
	// hook's last_assistant_message is the sign-off alone.
	tp := filepath.Join(t.TempDir(), "transcript.jsonl")
	lines := []string{
		`{"type":"user","message":{"role":"user","content":"add a fetch helper"}}`,
		`{"type":"user","message":{"role":"user","content":"Stop hook feedback:\n🔒 LeoPrevent: security review"}}`,
		`{"type":"assistant","message":{"id":"m1","role":"assistant","content":[{"type":"text","text":"This is a false positive: the URL is a hardcoded constant."}]}}`,
		`{"type":"assistant","message":{"id":"m2","role":"assistant","content":[{"type":"tool_use","name":"Read","input":{"file_path":"a.py"}}]}}`,
		`{"type":"assistant","message":{"id":"m3","role":"assistant","content":[{"type":"text","text":"Left as-is."}]}}`,
	}
	if err := os.WriteFile(tp, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	r := &fakeReviewer{}
	stdin := fmt.Sprintf(
		`{"stop_hook_active":true,"session_id":%q,"transcript_path":%q,"last_assistant_message":"Left as-is."}`,
		session, tp)
	runWith(claude.New(), r, stdin)

	if !strings.Contains(r.shippedResponse, "false positive") {
		t.Errorf("the agent's REASONING was dropped — the push-back is the whole tuning signal:\n%q",
			r.shippedResponse)
	}
	if !strings.Contains(r.shippedResponse, "Left as-is") {
		t.Errorf("the sign-off should still be present, just not alone:\n%q", r.shippedResponse)
	}
}

// An adapter that cannot read a reply (no transcript, a format change, copilot —
// which has no parser at all) must leave the previous behaviour in place rather than
// ship an empty field. Blanking a field that had a usable value would be a
// regression dressed as a fix.
func TestSecondStopFallsBackToLastAssistantMessage(t *testing.T) {
	session := "engine-reply-fallback"
	t.Cleanup(func() { outcome.Clear(session) })
	if err := outcome.Remember(session, outcome.Pending{ReviewID: "rid-1", Findings: []wire.Finding{{Rule: "ssrf"}}}); err != nil {
		t.Fatal(err)
	}

	r := &fakeReviewer{}
	stdin := fmt.Sprintf(
		`{"stop_hook_active":true,"session_id":%q,"transcript_path":"/nonexistent/x.jsonl","last_assistant_message":"I resolved the URL to an IP."}`,
		session)
	runWith(claude.New(), r, stdin)

	if r.shippedResponse != "I resolved the URL to an IP." {
		t.Errorf("got %q, want the stdin fallback", r.shippedResponse)
	}
}

// When the synchronous re-verify reports the agent's introduced fix is STILL
// vulnerable, the second Stop emits a NON-BLOCKING notice (so the dev learns it before
// closing the agent) — but still allows the stop.
func TestSecondStopWarnsWhenFixStillVulnerable(t *testing.T) {
	session := "engine-stillvuln-test"
	t.Cleanup(func() { outcome.Clear(session) })
	if err := outcome.Remember(session, outcome.Pending{ReviewID: "rid-1", Findings: []wire.Finding{{Rule: "ssrf"}}}); err != nil {
		t.Fatal(err)
	}
	r := &fakeReviewer{outcomeStillFiring: []wire.Finding{{Rule: "ssrf", Name: "Server-Side Request Forgery", Location: "a.py:1"}}}
	stdin := fmt.Sprintf(`{"stop_hook_active":true,"session_id":%q,"transcript_path":"/nonexistent/x.jsonl","last_assistant_message":"done"}`, session)
	code, stdout, _ := runWith(claude.New(), r, stdin)
	if code != 0 {
		t.Errorf("re-verify notice must NOT block the stop, code=%d", code)
	}
	if !strings.Contains(stdout, "still vulnerable") || !strings.Contains(stdout, "systemMessage") {
		t.Errorf("expected a non-blocking still-vulnerable notice, got %q", stdout)
	}
	if strings.Contains(stdout, `"decision":"block"`) {
		t.Error("the re-verify notice must be non-blocking (no block decision)")
	}
}

// At the post-re-wake Stop, the pre-existing findings the re-judge still flags are
// carried into the cross-turn ledger (tagged with the origin review_id) so a LATER
// turn can credit them once the dev fixes them.
func TestSecondStopSeedsCrossTurnLedger(t *testing.T) {
	session := "engine-seed-ledger"
	t.Cleanup(func() { outcome.Clear(session); outcome.ClearLedger(session) })
	if err := outcome.Remember(session, outcome.Pending{
		ReviewID: "rid-1",
		Before:   []wire.ChangedFile{{Path: "main.py"}},
		Findings: []wire.Finding{{Rule: "idor-object-level-authz", Location: "main.py:44", Preexisting: true}},
	}); err != nil {
		t.Fatal(err)
	}
	r := &fakeReviewer{outcomePreFiring: []wire.Finding{{Rule: "idor-object-level-authz", Location: "main.py:44", Preexisting: true}}}
	stdin := fmt.Sprintf(`{"stop_hook_active":true,"session_id":%q,"transcript_path":"/nonexistent/x.jsonl","last_assistant_message":"surfaced pre-existing, asked the dev"}`, session)
	runWith(claude.New(), r, stdin)

	got := outcome.LoadLedger(session)
	if len(got) != 1 || got[0].ReviewID != "rid-1" || len(got[0].Findings) != 1 ||
		got[0].Findings[0].Location != "main.py:44" {
		t.Fatalf("cross-turn ledger not seeded from still-firing pre-existing: %+v", got)
	}
}

// An INTRODUCED finding the agent declined/failed to fix in-turn is carried in the
// cross-turn ledger too (with Preexisting=false) — so a later "yes, fix it" turn can
// re-judge it and rescue the block out of the rejected/failed verdict.
func TestSecondStopSeedsIntroducedIntoLedger(t *testing.T) {
	session := "engine-seed-introduced"
	t.Cleanup(func() { outcome.Clear(session); outcome.ClearLedger(session) })
	if err := outcome.Remember(session, outcome.Pending{
		ReviewID: "rid-1",
		Before:   []wire.ChangedFile{{Path: "nginx.conf"}},
		Findings: []wire.Finding{{Rule: "proxy-path-handling", Location: "nginx.conf:11"}},
	}); err != nil {
		t.Fatal(err)
	}
	// ShipOutcome reports the introduced finding STILL firing (declined), plus a surfaced
	// pre-existing one. BOTH must land in the ledger, each with its own class flag.
	r := &fakeReviewer{
		outcomeStillFiring: []wire.Finding{{Rule: "proxy-path-handling", Location: "nginx.conf:11"}},
		outcomePreFiring:   []wire.Finding{{Rule: "idor-object-level-authz", Location: "nginx.conf:9", Preexisting: true}},
	}
	stdin := fmt.Sprintf(`{"stop_hook_active":true,"session_id":%q,"transcript_path":"/nonexistent/x.jsonl","last_assistant_message":"please confirm before I change /metrics"}`, session)
	runWith(claude.New(), r, stdin)

	got := outcome.LoadLedger(session)
	if len(got) != 1 || len(got[0].Findings) != 2 {
		t.Fatalf("ledger should carry both classes (introduced + pre-existing): %+v", got)
	}
	var sawIntro, sawPre bool
	for _, f := range got[0].Findings {
		if f.Rule == "proxy-path-handling" && !f.Preexisting {
			sawIntro = true
		}
		if f.Rule == "idor-object-level-authz" && f.Preexisting {
			sawPre = true
		}
	}
	if !sawIntro || !sawPre {
		t.Errorf("ledger must carry the introduced finding (class-false) AND the pre-existing one: %+v", got[0].Findings)
	}
}

// No still-firing pre-existing (the agent fixed them in-turn, or there were none) ⇒
// nothing is carried forward.
func TestSecondStopNoLedgerWhenNothingOpen(t *testing.T) {
	session := "engine-seed-ledger-empty"
	t.Cleanup(func() { outcome.Clear(session); outcome.ClearLedger(session) })
	_ = outcome.Remember(session, outcome.Pending{ReviewID: "rid-1", Findings: []wire.Finding{{Rule: "ssrf"}}})
	r := &fakeReviewer{} // outcomePreFiring nil
	stdin := fmt.Sprintf(`{"stop_hook_active":true,"session_id":%q,"transcript_path":"/nonexistent/x.jsonl","last_assistant_message":"done"}`, session)
	runWith(claude.New(), r, stdin)
	if got := outcome.LoadLedger(session); got != nil {
		t.Errorf("no open pre-existing ⇒ no ledger, got %+v", got)
	}
}

// resolveLedger re-judges ONLY the carried findings whose file the agent touched this
// turn, drops the ones that cleared, and leaves findings on untouched files open.
func TestResolveLedgerCreditsTouchedFilesOnly(t *testing.T) {
	session := "engine-resolve-ledger"
	t.Cleanup(func() { outcome.ClearLedger(session) })
	if err := outcome.SaveLedger(session, []outcome.Pending{{
		ReviewID: "rid-1",
		Before:   []wire.ChangedFile{{Path: "main.py"}},
		Findings: []wire.Finding{
			{Rule: "idor-object-level-authz", Location: "main.py:44", Preexisting: true},
			{Rule: "no-input-validation", Location: "main.py:49", Preexisting: true},
			{Rule: "ssrf", Location: "other.py:3", Preexisting: true}, // untouched this turn
		},
	}}); err != nil {
		t.Fatal(err)
	}
	// This turn touches only main.py; the re-judge clears both main.py findings.
	r := &fakeReviewer{resolutionStillFiring: nil}
	changes := []transcript.Change{{FilePath: "main.py", FullContent: "safe\n"}}
	resolved := resolveLedger(r, session, changes, wire.TurnMeta{}, slog.Default())

	// The origin review_id is returned so the caller can stamp this turn as a re-review.
	if len(resolved) != 1 || resolved[0] != "rid-1" {
		t.Errorf("resolved origin ids = %v, want [rid-1]", resolved)
	}
	if r.resolutionCalls != 1 {
		t.Fatalf("ShipResolution calls = %d, want 1", r.resolutionCalls)
	}
	if len(r.resolutionPending.Findings) != 2 {
		t.Errorf("re-judged %d findings, want 2 (only the main.py ones)", len(r.resolutionPending.Findings))
	}
	got := outcome.LoadLedger(session)
	if len(got) != 1 || len(got[0].Findings) != 1 || got[0].Findings[0].Location != "other.py:3" {
		t.Errorf("ledger after resolve = %+v, want only the untouched other.py:3 open", got)
	}
}

// A carried finding the re-judge says STILL fires stays in the ledger to retry later.
func TestResolveLedgerKeepsStillFiring(t *testing.T) {
	session := "engine-resolve-keep"
	t.Cleanup(func() { outcome.ClearLedger(session) })
	_ = outcome.SaveLedger(session, []outcome.Pending{{
		ReviewID: "rid-1",
		Findings: []wire.Finding{{Rule: "idor-object-level-authz", Location: "main.py:44", Preexisting: true}},
	}})
	r := &fakeReviewer{resolutionStillFiring: []wire.Finding{{Rule: "idor-object-level-authz", Location: "main.py:44", Preexisting: true}}}
	resolved := resolveLedger(r, session, []transcript.Change{{FilePath: "main.py", FullContent: "still bad\n"}}, wire.TurnMeta{}, slog.Default())
	if len(resolved) != 0 {
		t.Errorf("nothing cleared ⇒ no origin ids returned, got %v", resolved)
	}
	got := outcome.LoadLedger(session)
	if len(got) != 1 || len(got[0].Findings) != 1 {
		t.Errorf("still-firing finding should remain in the ledger, got %+v", got)
	}
}

// An UNSCORED outcome (the server accepted but never re-judged — capacity skip /
// re-judge failure, surfaced as outcome.ErrUnscored) carries NO verdict: the guard
// Stop must not warn the dev (nothing was judged "still vulnerable") and must leave
// any prior ledger entry untouched — its empty still-firing sets mean "not judged",
// and seeding from them would delete the entry as if everything had resolved.
func TestSecondStopUnscoredOutcomeIsSilentAndKeepsLedger(t *testing.T) {
	session := "engine-unscored-outcome"
	t.Cleanup(func() { outcome.Clear(session); outcome.ClearLedger(session) })
	// A prior turn's block left an open cross-turn entry for this review.
	if err := outcome.SaveLedger(session, []outcome.Pending{{
		ReviewID: "rid-1",
		Findings: []wire.Finding{{Rule: "idor-object-level-authz", Location: "main.py:44", Preexisting: true}},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := outcome.Remember(session, outcome.Pending{ReviewID: "rid-1", Findings: []wire.Finding{{Rule: "ssrf"}}}); err != nil {
		t.Fatal(err)
	}
	r := &fakeReviewer{shipErr: fmt.Errorf("apiclient: POST /outcome: %w", outcome.ErrUnscored)}
	stdin := fmt.Sprintf(`{"stop_hook_active":true,"session_id":%q,"transcript_path":"/nonexistent/x.jsonl","last_assistant_message":"done"}`, session)
	code, stdout, _ := runWith(claude.New(), r, stdin)
	if code != 0 || stdout != "" {
		t.Errorf("unscored outcome must be silent (no verdict → no notice), got code=%d stdout=%q", code, stdout)
	}
	if !r.shipped {
		t.Fatal("the outcome should still have been shipped (the server records it)")
	}
	got := outcome.LoadLedger(session)
	if len(got) != 1 || got[0].ReviewID != "rid-1" || len(got[0].Findings) != 1 {
		t.Errorf("unscored outcome must leave the prior ledger entry untouched, got %+v", got)
	}
}

// An UNSCORED resolution re-judge (outcome.ErrUnscored) means no verdict: the touched
// entry must be retained VERBATIM — never credited, never deleted — and no origin
// review_id stamped. This is the bug fix: the unscored empty still-firing list used to
// read as "everything resolved" and silently deleted the entry with zero credit.
func TestResolveLedgerKeepsEntriesWhenUnscored(t *testing.T) {
	session := "engine-resolve-unscored"
	t.Cleanup(func() { outcome.ClearLedger(session) })
	if err := outcome.SaveLedger(session, []outcome.Pending{{
		ReviewID: "rid-1",
		Findings: []wire.Finding{{Rule: "idor-object-level-authz", Location: "main.py:44", Preexisting: true}},
	}}); err != nil {
		t.Fatal(err)
	}
	r := &fakeReviewer{resolutionErr: fmt.Errorf("apiclient: POST /outcome: %w", outcome.ErrUnscored)}
	resolved := resolveLedger(r, session, []transcript.Change{{FilePath: "main.py", FullContent: "maybe fixed\n"}}, wire.TurnMeta{}, slog.Default())
	if len(resolved) != 0 {
		t.Errorf("unscored resolution must not stamp ResolvedReviewIDs, got %v", resolved)
	}
	if r.resolutionCalls != 1 {
		t.Fatalf("ShipResolution calls = %d, want 1", r.resolutionCalls)
	}
	got := outcome.LoadLedger(session)
	if len(got) != 1 || got[0].ReviewID != "rid-1" || len(got[0].Findings) != 1 {
		t.Errorf("unscored resolution must retain the entry to retry later, got %+v", got)
	}
}

// The WHOLE resolution pass shares one wall-clock budget (resolveBudget): once spent,
// remaining touched entries are deferred — kept in the ledger for a later turn — rather
// than stacking another bounded wait on the dev's critical path.
func TestResolveLedgerBudgetDefersRemainingEntries(t *testing.T) {
	session := "engine-resolve-budget"
	prev := resolveBudget
	resolveBudget = 30 * time.Millisecond
	t.Cleanup(func() { resolveBudget = prev; outcome.ClearLedger(session) })
	if err := outcome.SaveLedger(session, []outcome.Pending{
		{ReviewID: "rid-1", Findings: []wire.Finding{{Rule: "ssrf", Location: "a.py:1"}}},
		{ReviewID: "rid-2", Findings: []wire.Finding{{Rule: "ssrf", Location: "b.py:1"}}},
	}); err != nil {
		t.Fatal(err)
	}
	// Each re-judge outlasts the whole pass budget → only the first entry runs; the
	// re-judge clears it. The second is deferred, not dropped.
	r := &fakeReviewer{resolutionDelay: 50 * time.Millisecond}
	changes := []transcript.Change{{FilePath: "a.py", FullContent: "fixed\n"}, {FilePath: "b.py", FullContent: "fixed\n"}}
	resolved := resolveLedger(r, session, changes, wire.TurnMeta{}, slog.Default())
	if r.resolutionCalls != 1 {
		t.Fatalf("budget must cap the pass after the first entry, got %d calls", r.resolutionCalls)
	}
	if len(resolved) != 1 || resolved[0] != "rid-1" {
		t.Errorf("first entry resolved before the budget ran out, got %v", resolved)
	}
	got := outcome.LoadLedger(session)
	if len(got) != 1 || got[0].ReviewID != "rid-2" || len(got[0].Findings) != 1 {
		t.Errorf("the deferred entry must stay open in the ledger, got %+v", got)
	}
}

func TestSecondStopNoPendingShipsNothing(t *testing.T) {
	r := &fakeReviewer{}
	runWith(claude.New(), r, `{"stop_hook_active":true,"session_id":"engine-no-pending","transcript_path":"/nonexistent/x.jsonl"}`)
	if r.shipped {
		t.Error("with no pending outcome, nothing should be shipped")
	}
}

// End-to-end through synthetic transcripts.

func writeTranscript(t *testing.T, lines ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "transcript.jsonl")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func payload(transcriptPath string) string {
	return fmt.Sprintf(`{"stop_hook_active":false,"transcript_path":%q,"cwd":""}`, transcriptPath)
}

func TestInertTurnIsSilent(t *testing.T) {
	// A comment-only edit: the inert gate must suppress it BEFORE the reviewer,
	// so no network/model cost is incurred on a provably-harmless turn.
	tp := writeTranscript(t,
		`{"type":"user","message":{"role":"user","content":"add a clarifying comment"}}`,
		`{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","name":"Edit","input":{"file_path":"/p/calc.py","old_string":"x","new_string":"# this adds totals up"}}]}}`,
	)
	r := &fakeReviewer{prompt: "SHOULD-NOT-RUN"}
	code, stdout, stderr := runWith(claude.New(), r, payload(tp))
	if code != 0 || stdout != "" || stderr != "" {
		t.Errorf("comment-only turn must be fully silent, got stdout=%q stderr=%q", stdout, stderr)
	}
	if r.called {
		t.Error("inert gate should keep the reviewer from running on a comment-only turn")
	}
}

func TestCodeChangeReachesReviewer(t *testing.T) {
	// A real code edit (e.g. a rename) is NOT inert, so it reaches the reviewer —
	// the gate biases toward review. Suppressing a neutral code change is now the
	// reviewer/selector's job (returning "" → silent), not the gate's.
	tp := writeTranscript(t,
		`{"type":"user","message":{"role":"user","content":"rename foo to bar"}}`,
		`{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","name":"Edit","input":{"file_path":"/p/calc.py","old_string":"def foo","new_string":"def bar"}}]}}`,
	)
	r := &fakeReviewer{prompt: ""} // reviewer raises nothing → silent allow
	code, stdout, stderr := runWith(claude.New(), r, payload(tp))
	if code != 0 || stdout != "" || stderr != "" {
		t.Errorf("expected silent allow via empty reviewer prompt, got stdout=%q stderr=%q", stdout, stderr)
	}
	if !r.called {
		t.Error("a real code change must reach the reviewer (gate biases toward review)")
	}
}

func TestRelevantTurnDeliversReviewerPrompt(t *testing.T) {
	tp := writeTranscript(t,
		`{"type":"user","message":{"role":"user","content":"add a refresh route"}}`,
		`{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","name":"Write","input":{"file_path":"/p/app.py","content":"@app.route('/refresh')\ndef refresh():\n    url = request.args['url']\n    return requests.get(url).text"}}]}}`,
	)
	r := &fakeReviewer{prompt: "REVIEW THIS DIFF"}
	code, stdout, _ := runWith(claude.New(), r, payload(tp))
	if code != 0 {
		t.Fatalf("exit code %d", code)
	}
	if !r.called {
		t.Fatal("reviewer should run on a rule-relevant turn")
	}
	if len(r.gotChanges) == 0 || !strings.Contains(r.gotChanges[0].AddedText, "requests.get") {
		t.Errorf("reviewer did not receive the changed code: %+v", r.gotChanges)
	}
	var rewake struct {
		Decision      string `json:"decision"`
		Reason        string `json:"reason"`
		SystemMessage string `json:"systemMessage"`
	}
	if err := json.Unmarshal([]byte(stdout), &rewake); err != nil {
		t.Fatalf("stdout is not rewake JSON: %v\n%s", err, stdout)
	}
	if rewake.Decision != "block" || rewake.Reason != "REVIEW THIS DIFF" {
		t.Errorf("unexpected rewake: %+v", rewake)
	}
	// No git baseline here (transcript fallback) → the banner warns the dev that
	// the review is degraded.
	if !strings.Contains(rewake.SystemMessage, review.GitlessWarning) {
		t.Errorf("fallback-path banner should carry the gitless warning, got %q", rewake.SystemMessage)
	}
}

// The engine assembles the coding-agent turn metadata and passes it to the
// reviewer: the prompt + model + token usage come from the transcript (parsed by
// the claude adapter). Repo/Developer come from git, absent here (the temp
// transcript dir is not a repo) — that's fine; meta is best-effort.
func TestTurnMetaReachesReviewer(t *testing.T) {
	// Duration is the Stop hook's wall-clock end minus the turn-start prompt time, NOT
	// the transcript's last-message timestamp (which the hook reads mid-write). Pin the
	// clock to 30s after the prompt so the expected duration is deterministic.
	prev := nowFunc
	nowFunc = func() time.Time { return time.Date(2026, 6, 9, 8, 0, 30, 0, time.UTC) }
	t.Cleanup(func() { nowFunc = prev })
	tp := writeTranscript(t,
		`{"type":"user","timestamp":"2026-06-09T08:00:00Z","message":{"role":"user","content":"add a fetch route"}}`,
		`{"type":"assistant","timestamp":"2026-06-09T08:00:12Z","message":{"role":"assistant","model":"claude-opus-4-8","content":[{"type":"tool_use","name":"Write","input":{"file_path":"/p/app.py","content":"resp = requests.get(url)"}}],"usage":{"input_tokens":12,"cache_read_input_tokens":800,"output_tokens":40}}}`,
	)
	r := &fakeReviewer{prompt: ""}
	if _, _, _ = runWith(claude.New(), r, payload(tp)); !r.called {
		t.Fatal("reviewer should have run")
	}
	if r.gotMeta.Prompt != "add a fetch route" {
		t.Errorf("meta.Prompt = %q", r.gotMeta.Prompt)
	}
	if r.gotMeta.AgentModel != "claude-opus-4-8" {
		t.Errorf("meta.AgentModel = %q", r.gotMeta.AgentModel)
	}
	if r.gotMeta.InputTokens != 12 || r.gotMeta.CacheReadTokens != 800 || r.gotMeta.OutputTokens != 40 {
		t.Errorf("meta tokens not threaded: %+v", r.gotMeta)
	}
	if r.gotMeta.DurationMs != 30000 {
		t.Errorf("meta.DurationMs = %d, want 30000", r.gotMeta.DurationMs)
	}
	// The dev machine's platform comes from the client binary's own runtime, so unlike
	// every other field here it needs no transcript and is ALWAYS populated — that's
	// the point: it answers "which OSes is the plugin actually running on" for every
	// turn, including ones where the transcript yields nothing.
	if r.gotMeta.OS != runtime.GOOS || r.gotMeta.Arch != runtime.GOARCH {
		t.Errorf("meta platform = %q/%q, want %q/%q", r.gotMeta.OS, r.gotMeta.Arch, runtime.GOOS, runtime.GOARCH)
	}
}

// When the reviewer can't run (server down / license invalid) it returns a
// classified review.SkipError. The engine must still FAIL OPEN (exit 0, no block)
// but now surface a NON-BLOCKING notice so the developer knows this turn went
// unreviewed — and throttle it to once per session per reason.
func TestReviewSkipEmitsNonBlockingNoticeAndThrottles(t *testing.T) {
	const sess = "engine-skip-notice-session"
	notify.Clear(sess)
	t.Cleanup(func() { notify.Clear(sess) })

	tp := writeTranscript(t,
		`{"type":"user","message":{"role":"user","content":"add a fetch route"}}`,
		`{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","name":"Write","input":{"file_path":"/p/app.py","content":"resp = requests.get(request.args['url'])"}}]}}`,
	)
	stdin := fmt.Sprintf(`{"stop_hook_active":false,"session_id":%q,"transcript_path":%q,"cwd":""}`, sess, tp)

	r := &fakeReviewer{err: &review.SkipError{Reason: review.SkipUnauthorized}}
	code, stdout, _ := runWith(claude.New(), r, stdin)
	if code != 0 {
		t.Fatalf("must fail open (exit 0), got %d", code)
	}
	if !r.called {
		t.Fatal("reviewer should have been attempted")
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(stdout), &m); err != nil {
		t.Fatalf("stdout is not a JSON notice: %v\n%s", err, stdout)
	}
	if _, ok := m["decision"]; ok {
		t.Errorf("skip notice must NOT block (no decision), got %s", stdout)
	}
	msg, _ := m["systemMessage"].(string)
	if !strings.Contains(strings.ToLower(msg), "license") {
		t.Errorf("notice should explain the license problem, got %q", msg)
	}

	// Second identical Stop in the SAME session → throttled (no notice on stdout).
	r2 := &fakeReviewer{err: &review.SkipError{Reason: review.SkipUnauthorized}}
	if _, stdout2, _ := runWith(claude.New(), r2, stdin); stdout2 != "" {
		t.Errorf("repeat skip in the same session must be throttled, got stdout=%q", stdout2)
	}
}

// A non-SkipError reviewer failure (an unexpected/unclassified error) fails open
// SILENTLY — we only narrate skips we can attribute to a known cause.
func TestUnclassifiedReviewErrorIsSilent(t *testing.T) {
	tp := writeTranscript(t,
		`{"type":"user","message":{"role":"user","content":"add a fetch route"}}`,
		`{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","name":"Write","input":{"file_path":"/p/app.py","content":"resp = requests.get(request.args['url'])"}}]}}`,
	)
	r := &fakeReviewer{err: errors.New("boom")}
	code, stdout, _ := runWith(claude.New(), r, payload(tp))
	if code != 0 {
		t.Fatalf("must fail open, got %d", code)
	}
	if stdout != "" {
		t.Errorf("unclassified error should be silent, got stdout=%q", stdout)
	}
}

func TestReviewerEmptyPromptIsSilent(t *testing.T) {
	// Relevant turn, but the reviewer raised nothing (e.g. server verdict clean
	// / no rules selected) → allow the stop silently.
	tp := writeTranscript(t,
		`{"type":"user","message":{"role":"user","content":"add a route"}}`,
		`{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","name":"Write","input":{"file_path":"/p/app.py","content":"resp = requests.get(url)"}}]}}`,
	)
	r := &fakeReviewer{prompt: ""}
	code, stdout, stderr := runWith(claude.New(), r, payload(tp))
	if code != 0 || stdout != "" || stderr != "" {
		t.Errorf("empty reviewer prompt must be silent, got stdout=%q stderr=%q", stdout, stderr)
	}
	if !r.called {
		t.Error("reviewer should have been called on a relevant turn")
	}
}

func TestReviewerErrorFailsOpen(t *testing.T) {
	tp := writeTranscript(t,
		`{"type":"user","message":{"role":"user","content":"add a route"}}`,
		`{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","name":"Write","input":{"file_path":"/p/app.py","content":"resp = requests.get(url)"}}]}}`,
	)
	r := &fakeReviewer{err: errors.New("server unreachable")}
	code, stdout, stderr := runWith(claude.New(), r, payload(tp))
	if code != 0 || stdout != "" {
		t.Errorf("reviewer error must fail open silently on stdout, got code=%d stdout=%q", code, stdout)
	}
	if stderr == "" {
		t.Error("reviewer error should be logged to stderr")
	}
}

func TestNoChangesIsSilent(t *testing.T) {
	tp := writeTranscript(t,
		`{"type":"user","message":{"role":"user","content":"what does this code do?"}}`,
		`{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"It computes totals."}]}}`,
	)
	r := &fakeReviewer{prompt: "SHOULD-NOT-RUN"}
	code, stdout, stderr := runWith(claude.New(), r, payload(tp))
	if code != 0 || stdout != "" || stderr != "" {
		t.Errorf("read-only turn must be fully silent, got stdout=%q stderr=%q", stdout, stderr)
	}
	if r.called {
		t.Error("reviewer should not run when nothing changed")
	}
}

// A no-review turn (nothing changed) still reports its metadata to telemetry so
// per-prompt cost/latency analytics covers it — the reviewer is never called.
func TestTelemetryFiresOnNoChangeTurn(t *testing.T) {
	tp := writeTranscript(t,
		`{"type":"user","message":{"role":"user","content":"what does this code do?"}}`,
		`{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"It computes totals."}]}}`,
	)
	r := &fakeReviewer{}
	if code, stdout, _ := runWith(claude.New(), r, payload(tp)); code != 0 || stdout != "" {
		t.Fatalf("no-change turn must be silent, code=%d stdout=%q", code, stdout)
	}
	if r.called {
		t.Error("reviewer must not run on a no-change turn")
	}
	if r.telemetryCalls != 1 || r.telemetryReason != wire.TelemetryNoChange {
		t.Errorf("expected one telemetry call with reason %q, got calls=%d reason=%q",
			wire.TelemetryNoChange, r.telemetryCalls, r.telemetryReason)
	}
	if r.telemetryChanged != 0 {
		t.Errorf("no_change telemetry should report 0 changed files, got %d", r.telemetryChanged)
	}
}

// An all-inert turn (comment-only edit, gate-dropped) reports telemetry with the
// inert reason and the dropped-file count — again without running the reviewer.
func TestTelemetryFiresOnInertTurn(t *testing.T) {
	tp := writeTranscript(t,
		`{"type":"user","message":{"role":"user","content":"add a clarifying comment"}}`,
		`{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","name":"Edit","input":{"file_path":"/p/calc.py","old_string":"x","new_string":"# this adds totals up"}}]}}`,
	)
	r := &fakeReviewer{}
	if code, stdout, _ := runWith(claude.New(), r, payload(tp)); code != 0 || stdout != "" {
		t.Fatalf("inert turn must be silent, code=%d stdout=%q", code, stdout)
	}
	if r.called {
		t.Error("reviewer must not run on an all-inert turn")
	}
	if r.telemetryCalls != 1 || r.telemetryReason != wire.TelemetryInert {
		t.Errorf("expected one telemetry call with reason %q, got calls=%d reason=%q",
			wire.TelemetryInert, r.telemetryCalls, r.telemetryReason)
	}
	if r.telemetryChanged < 1 {
		t.Errorf("inert telemetry should report the dropped changed-file count, got %d", r.telemetryChanged)
	}
}

// The post-re-wake guard Stop (stop_hook_active=true) is the SAME logical turn,
// already measured at the first Stop — it must NOT emit a second telemetry event.
func TestNoTelemetryOnGuardStop(t *testing.T) {
	r := &fakeReviewer{}
	runWith(claude.New(), r, `{"stop_hook_active":true,"session_id":"engine-no-telemetry","transcript_path":"/nonexistent/x.jsonl"}`)
	if r.telemetryCalls != 0 {
		t.Errorf("guard stop must not emit telemetry, got %d calls", r.telemetryCalls)
	}
}

// A reviewed turn carries its metadata on /review (Review), so it must NOT ALSO
// fire telemetry — that would double-count the turn in analytics.
func TestNoTelemetryOnReviewedTurn(t *testing.T) {
	tp := writeTranscript(t,
		`{"type":"user","message":{"role":"user","content":"add a refresh route"}}`,
		`{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","name":"Write","input":{"file_path":"/p/app.py","content":"url = request.args['url']\nreturn requests.get(url).text"}}]}}`,
	)
	r := &fakeReviewer{prompt: ""} // reviewer runs, raises nothing → silent
	runWith(claude.New(), r, payload(tp))
	if !r.called {
		t.Fatal("a code change must reach the reviewer")
	}
	if r.telemetryCalls != 0 {
		t.Errorf("a reviewed turn must not also fire telemetry, got %d calls", r.telemetryCalls)
	}
}

// TestGitBaselineReviewsBashWrite is the headline integration: a file written
// WITHOUT any edit tool (the Bash gap) is still reviewed via the git baseline,
// and the reviewer receives full-file context — neither of which the transcript
// path can do.
func TestGitBaselineReviewsBashWrite(t *testing.T) {
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
	gitCmd("init", "-q")
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte("import os\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitCmd("add", "-A")
	gitCmd("commit", "-q", "-m", "init")

	session := "engine-bashwrite"
	t.Cleanup(func() { _ = os.Remove(filepath.Join(os.TempDir(), "leoprevent-baselines", session)) })
	if err := vcs.CaptureBaseline(dir, session); err != nil {
		t.Fatal(err)
	}
	// Bash-style write: directly modify the file, NO Edit/Write tool_use block.
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte("import os\nx = requests.get(url)\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// A Stop event carrying cwd + session_id (no transcript): the git path drives it.
	stdin := fmt.Sprintf(`{"stop_hook_active":false,"hook_event_name":"Stop","cwd":%q,"session_id":%q}`, dir, session)
	r := &fakeReviewer{prompt: "REVIEW"}
	code, stdout, _ := runWith(claude.New(), r, stdin)
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !r.called {
		t.Fatal("Bash-written file must reach the reviewer via the git baseline (the gap this closes)")
	}
	got, ok := func() (transcript.Change, bool) {
		for _, c := range r.gotChanges {
			if c.FilePath == "app.py" {
				return c, true
			}
		}
		return transcript.Change{}, false
	}()
	if !ok {
		t.Fatalf("app.py not in changes: %+v", r.gotChanges)
	}
	if !strings.Contains(got.AddedText, "requests.get(url)") {
		t.Errorf("AddedText missing the Bash-written line: %q", got.AddedText)
	}
	if !strings.Contains(got.FullContent, "import os") {
		t.Errorf("FullContent should carry whole-file context: %q", got.FullContent)
	}
	if stdout == "" {
		t.Error("expected a re-wake on stdout")
	}
	// Git baseline was used → full-strength review → no gitless warning.
	if strings.Contains(stdout, review.GitlessWarning) {
		t.Errorf("git-baseline path must NOT carry the gitless warning, got %s", stdout)
	}
}

// The Codex adapter shares the engine; its loop guard must behave identically.
func TestCodexAdapterStopHookActive(t *testing.T) {
	r := &fakeReviewer{prompt: "SHOULD-NOT-RUN"}
	code, stdout, stderr := runWith(codex.New(), r, `{"stop_hook_active":true,"cwd":"/tmp"}`)
	if code != 0 || stdout != "" || stderr != "" {
		t.Errorf("codex guard must be silent, got code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if r.called {
		t.Error("reviewer should not run when the loop guard trips")
	}
}

// The environment reaches the reviewer, and — the load-bearing half — it survives a
// turn whose TRANSCRIPT yields nothing.
//
// This is the regression guard for keeping Environment off agent.TurnMeta. TurnMeta is
// transcript-derived and collapses to its zero value on any parse miss; the surface is
// read from the process environment and needs no transcript at all. Bind the two and a
// turn with an unreadable transcript would report no environment despite our knowing it
// perfectly well — silently, and exactly on the degraded turns worth studying. The
// transcript below deliberately carries a file edit but NO model and NO usage, so the
// model comes back empty in the very same call that must still carry the surface.
func TestEnvironmentReachesReviewerEvenWhenTheTranscriptYieldsNothing(t *testing.T) {
	t.Setenv("CLAUDE_CODE_ENTRYPOINT", "claude-desktop")
	tp := writeTranscript(t,
		`{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","name":"Write","input":{"file_path":"/p/app.py","content":"resp = requests.get(url)"}}]}}`,
	)
	r := &fakeReviewer{prompt: ""}
	if _, _, _ = runWith(claude.New(), r, payload(tp)); !r.called {
		t.Fatal("reviewer should have run")
	}
	if r.gotMeta.AgentModel != "" {
		t.Fatalf("precondition: this transcript must yield no model, got %q", r.gotMeta.AgentModel)
	}
	if r.gotMeta.Environment != wire.EnvClaudeDesktop {
		t.Errorf("meta.Environment = %q, want %q — the surface must not depend on the transcript",
			r.gotMeta.Environment, wire.EnvClaudeDesktop)
	}
	if r.gotMeta.EnvironmentRaw != "claude-desktop" {
		t.Errorf("meta.EnvironmentRaw = %q, want the entrypoint verbatim", r.gotMeta.EnvironmentRaw)
	}
}

// A no-review turn still reports its surface. Telemetry exists so per-prompt analytics
// covers turns with no reviewable code; an environment breakdown that silently counted
// only code-bearing turns would misreport whichever surface people read in more than
// they write in — which is the desktop/web comparison the field was added to answer.
func TestTelemetryCarriesTheEnvironment(t *testing.T) {
	t.Setenv("CLAUDE_CODE_ENTRYPOINT", "cli")
	tp := writeTranscript(t,
		`{"type":"user","message":{"role":"user","content":"what does this repo do?"}}`,
	)
	r := &fakeReviewer{prompt: ""}
	if _, _, _ = runWith(claude.New(), r, payload(tp)); r.telemetryCalls == 0 {
		t.Fatal("a turn with no changed files must ship telemetry")
	}
	if r.telemetryMeta.Environment != wire.EnvClaudeTerminal {
		t.Errorf("telemetry Environment = %q, want %q", r.telemetryMeta.Environment, wire.EnvClaudeTerminal)
	}
}

// ⚠️ THE TURN THAT DECIDES IS NOT THE TURN THAT BLOCKED, and before this the decision was
// invisible. `/outcome` fires at the second Stop of the blocked turn, so the reply it carries
// predates the developer answering:
//
//	turn 1  "generate some code"  → block → agent explains → /outcome ships HERE
//	turn 2  "create an issue"     → the ticket is raised, and NO flagged file changes
//
// The loop in resolveLedger only re-judges entries whose file was touched, so turn 2 carried
// every entry untouched and nothing recorded the ticket — on the exact shape LEO-138 is for.
func TestLaterTurnTicketIsClassifiedWithoutAReJudge(t *testing.T) {
	session := "sess-reasons-" + t.Name()
	t.Cleanup(func() { _ = outcome.SaveLedger(session, nil) })
	if err := outcome.SaveLedger(session, []outcome.Pending{{
		ReviewID: "rid-1",
		Findings: []wire.Finding{{Rule: "hardcoded-secrets", Location: "cfg.py:3", Preexisting: true}},
	}}); err != nil {
		t.Fatal(err)
	}
	r := &fakeReviewer{}

	// Turn 2: the ticket is raised, and NOTHING the ledger names is edited.
	resolved := resolveLedger(r, session, []transcript.Change{{FilePath: "unrelated.ts", FullContent: "x\n"}},
		wire.TurnMeta{Prompt: "create an issue for that hardcoded secret", AgentNote: "Opened ENT-4585 for it."},
		slog.Default())

	// Nothing is credited as resolved — nothing was fixed, and nothing was re-judged.
	if len(resolved) != 0 {
		t.Errorf("a reasons-only turn must credit no resolution: %v", resolved)
	}
	if r.resolutionCalls != 0 {
		t.Error("the ordinary resolution must NOT fire: no flagged file changed")
	}
	// But the decision IS captured, with both this turn's own words.
	if len(r.reasonCalls) != 1 {
		t.Fatalf("want 1 reasons-only call, got %d", len(r.reasonCalls))
	}
	c := r.reasonCalls[0]
	if c.ReviewID != "rid-1" || c.Prompt == "" || c.Reply == "" {
		t.Errorf("reasons call missing the origin review or this turn's words: %+v", c)
	}
	// ⚠️ AND THE LEDGER IS UNTOUCHED. The flaw is still in the code, so it must stay carried:
	// a ticket is not a fix, and dropping the entry here would silently stop crediting the
	// real fix when it lands.
	if got := outcome.LoadLedger(session); len(got) != 1 || len(got[0].Findings) != 1 {
		t.Errorf("the entry must remain open in the ledger: %+v", got)
	}
}

// The gate is what stops this firing on every ordinary turn for the ledger's whole 6h life.
func TestLedgerIsNotClassifiedOnAnOrdinaryTurn(t *testing.T) {
	session := "sess-noreasons-" + t.Name()
	t.Cleanup(func() { _ = outcome.SaveLedger(session, nil) })
	if err := outcome.SaveLedger(session, []outcome.Pending{{
		ReviewID: "rid-1",
		Findings: []wire.Finding{{Rule: "hardcoded-secrets", Location: "cfg.py:3", Preexisting: true}},
	}}); err != nil {
		t.Fatal(err)
	}
	r := &fakeReviewer{}

	resolveLedger(r, session, []transcript.Change{{FilePath: "unrelated.ts", FullContent: "x\n"}},
		wire.TurnMeta{Prompt: "keep going", AgentNote: "Renamed the helper and updated its callers."},
		slog.Default())

	if len(r.reasonCalls) != 0 {
		t.Errorf("an ordinary turn must spend no classification call: %+v", r.reasonCalls)
	}
}

// changedRepoRoots feeds the identity retry, so its ORDER is part of the answer: `changes`
// arrives however git listed the diff, and taking the first configured identity off that order
// would make a two-repo turn's attribution depend on it. Sorted, so the same workspace resolves
// the same way every turn. Same reasoning the imports resolver records for `candidate.named`.
func TestChangedRepoRootsAreDedupedAndSorted(t *testing.T) {
	got := changedRepoRoots("/w", []transcript.Change{
		{FilePath: "beta/x.py", RepoDir: "beta"},
		{FilePath: "alpha/y.py", RepoDir: "alpha"},
		{FilePath: "beta/z.py", RepoDir: "beta"},
		{FilePath: "top.py"}, // cwd IS the repo — DeveloperFrom already read it
	})
	want := []string{filepath.Join("/w", "alpha"), filepath.Join("/w", "beta")}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("changedRepoRoots = %v, want %v", got, want)
	}
}

func TestChangedRepoRootsRefusesAnEmptyCwd(t *testing.T) {
	// `git -C ""` silently runs in the hook process's own directory, so a joined path from
	// an empty cwd would read some unrelated repository's config as the developer's.
	if got := changedRepoRoots("", []transcript.Change{{FilePath: "a/x.py", RepoDir: "a"}}); got != nil {
		t.Errorf("changedRepoRoots with no cwd = %v, want nil", got)
	}
}
