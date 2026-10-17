package engine

import (
	"fmt"
	"testing"
	"time"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/agent/claude"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/outcome"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

// These tests pin the engine's turn-end wall-clock (nowFunc) so the agent's turn
// DURATION is deterministic, then assert it across every shape of turn. In each
// fixture the prompt is at 08:00:00 and the clock is pinned to 08:00:50, so the
// correct duration is ALWAYS 50_000ms — regardless of where the last assistant
// message sits. Asserting 50_000 (never the last-message offset) proves the
// duration is the Stop hook's wall-clock end minus the turn-start prompt — the
// "crunched for X" interval the developer sees — not the mid-write transcript end.

func pinClock(t *testing.T, rfc3339 string) {
	t.Helper()
	at, err := time.Parse(time.RFC3339, rfc3339)
	if err != nil {
		t.Fatal(err)
	}
	prev := nowFunc
	nowFunc = func() time.Time { return at }
	t.Cleanup(func() { nowFunc = prev })
}

// Scenario: run leoprevent on a code change, review comes back CLEAN (and the same
// path covers "fixed the pre-existing vulns" — a turn whose edits are themselves
// safe). Duration rides the /review meta. Last assistant message is at +20s; the
// answer must still be 50s (wall-clock), proving it's not lastAssistant-prompt.
func TestDuration_CleanCodeTurn_IsWallClock(t *testing.T) {
	pinClock(t, "2026-06-09T08:00:50Z")
	tp := writeTranscript(t,
		`{"type":"user","timestamp":"2026-06-09T08:00:00Z","message":{"role":"user","content":"add a fetch route"}}`,
		`{"type":"assistant","timestamp":"2026-06-09T08:00:20Z","message":{"role":"assistant","model":"claude-opus-4-8","content":[{"type":"tool_use","name":"Write","input":{"file_path":"/p/app.py","content":"resp = safe_get(url)"}}],"usage":{"input_tokens":5,"output_tokens":5}}}`,
	)
	r := &fakeReviewer{prompt: ""} // clean: nothing to raise
	runWith(claude.New(), r, payload(tp))
	if !r.called {
		t.Fatal("a code change must reach the reviewer")
	}
	if r.gotMeta.DurationMs != 50000 {
		t.Errorf("clean code turn duration = %d, want 50000 (now-prompt, NOT lastAssistant=20000)", r.gotMeta.DurationMs)
	}
}

// Scenario: run leoprevent, get BLOCKED, fix it. The authoritative full-turn meta
// rides /outcome at the FINAL stop and must span the ENTIRE turn — from the
// ORIGINAL prompt, across the "Stop hook feedback:" re-wake, to now. The re-wake
// user message is at +20s (must be ignored as a turn start) and the fix's last
// message is at +45s; the answer must be 50s — proving BOTH that it scopes from
// the original prompt (else 30s) and uses the wall-clock end (else 45s).
func TestDuration_BlockedTurn_OutcomeSpansRewake(t *testing.T) {
	session := "engine-dur-blocked"
	t.Cleanup(func() { outcome.Clear(session) })
	if err := outcome.Remember(session, outcome.Pending{ReviewID: "rid-x"}); err != nil {
		t.Fatal(err)
	}
	pinClock(t, "2026-06-09T08:00:50Z")
	tp := writeTranscript(t,
		`{"type":"user","timestamp":"2026-06-09T08:00:00Z","message":{"role":"user","content":"add a delete-profile route"}}`,
		`{"type":"assistant","timestamp":"2026-06-09T08:00:10Z","message":{"role":"assistant","model":"claude-opus-4-8","content":[{"type":"text","text":"added"}],"usage":{"input_tokens":5,"output_tokens":5}}}`,
		`{"type":"user","timestamp":"2026-06-09T08:00:20Z","message":{"role":"user","content":"Stop hook feedback: fix the broken authorization"}}`,
		`{"type":"assistant","timestamp":"2026-06-09T08:00:45Z","message":{"role":"assistant","model":"claude-opus-4-8","content":[{"type":"tool_use","name":"Write","input":{"file_path":"/p/app.py","content":"if user!=caller: abort(403)"}}],"usage":{"input_tokens":5,"output_tokens":5}}}`,
	)
	r := &fakeReviewer{}
	stdin := fmt.Sprintf(`{"stop_hook_active":true,"session_id":%q,"transcript_path":%q,"cwd":"","last_assistant_message":"fixed"}`, session, tp)
	runWith(claude.New(), r, stdin)
	if !r.shipped {
		t.Fatal("a blocked turn must ship its outcome at the final stop")
	}
	if r.shippedMeta.DurationMs != 50000 {
		t.Errorf("blocked-turn outcome duration = %d, want 50000 (now - ORIGINAL prompt, spanning the re-wake; not 30000 from the re-wake, not 45000 lastAssistant)", r.shippedMeta.DurationMs)
	}
}

// Scenario: a BLOCKED turn where LeoPrevent's first Stop hook sat blocked on /review
// for 12s (recorded as Pending.ReviewBlockMs). The full-turn wall-clock is 50s, but
// 12s of that was the agent idle waiting on us — so the recorded latency must be the
// agent's OWN time, 50s − 12s = 38s. This is the latency fix: blocked turns excluded
// the wait-on-LeoPrevent, matching the clean-turn baseline.
func TestDuration_BlockedTurn_SubtractsReviewWait(t *testing.T) {
	session := "engine-dur-blocked-wait"
	t.Cleanup(func() { outcome.Clear(session) })
	if err := outcome.Remember(session, outcome.Pending{ReviewID: "rid-x", ReviewBlockMs: 12000}); err != nil {
		t.Fatal(err)
	}
	pinClock(t, "2026-06-09T08:00:50Z")
	tp := writeTranscript(t,
		`{"type":"user","timestamp":"2026-06-09T08:00:00Z","message":{"role":"user","content":"add a delete-profile route"}}`,
		`{"type":"assistant","timestamp":"2026-06-09T08:00:45Z","message":{"role":"assistant","model":"claude-opus-4-8","content":[{"type":"tool_use","name":"Write","input":{"file_path":"/p/app.py","content":"if user!=caller: abort(403)"}}],"usage":{"input_tokens":5,"output_tokens":5}}}`,
	)
	r := &fakeReviewer{}
	stdin := fmt.Sprintf(`{"stop_hook_active":true,"session_id":%q,"transcript_path":%q,"cwd":"","last_assistant_message":"fixed"}`, session, tp)
	runWith(claude.New(), r, stdin)
	if !r.shipped {
		t.Fatal("a blocked turn must ship its outcome at the final stop")
	}
	if r.shippedMeta.DurationMs != 38000 {
		t.Errorf("blocked-turn duration = %d, want 38000 (50s wall-clock − 12s LeoPrevent review wait)", r.shippedMeta.DurationMs)
	}
}

// Scenario: someone just chats about the weather — no code change at all. The turn
// emits a no_change TELEMETRY ping; its duration must still be the real wall-clock
// (a chat turn has cost + latency worth recording), even though there are no edits.
func TestDuration_ChatTurn_TelemetryIsWallClock(t *testing.T) {
	pinClock(t, "2026-06-09T08:00:50Z")
	tp := writeTranscript(t,
		`{"type":"user","timestamp":"2026-06-09T08:00:00Z","message":{"role":"user","content":"what is the weather like today?"}}`,
		`{"type":"assistant","timestamp":"2026-06-09T08:00:08Z","message":{"role":"assistant","model":"claude-opus-4-8","content":[{"type":"text","text":"I can't check live weather."}],"usage":{"input_tokens":5,"output_tokens":5}}}`,
	)
	r := &fakeReviewer{}
	runWith(claude.New(), r, payload(tp))
	if r.called {
		t.Fatal("a no-code chat turn must NOT reach the reviewer")
	}
	if r.telemetryCalls != 1 || r.telemetryReason != wire.TelemetryNoChange {
		t.Fatalf("expected one no_change telemetry ping, got calls=%d reason=%q", r.telemetryCalls, r.telemetryReason)
	}
	if r.telemetryMeta.DurationMs != 50000 {
		t.Errorf("chat-turn telemetry duration = %d, want 50000", r.telemetryMeta.DurationMs)
	}
}

// Scenario: a comment-only (inert) edit — suppressed before review, emits an inert
// TELEMETRY ping. Its duration must also be the wall-clock, and PromptTime is set
// from the user message even though the lone assistant message carries no usage.
func TestDuration_InertTurn_TelemetryIsWallClock(t *testing.T) {
	pinClock(t, "2026-06-09T08:00:50Z")
	tp := writeTranscript(t,
		`{"type":"user","timestamp":"2026-06-09T08:00:00Z","message":{"role":"user","content":"add a clarifying comment"}}`,
		`{"type":"assistant","timestamp":"2026-06-09T08:00:09Z","message":{"role":"assistant","content":[{"type":"tool_use","name":"Edit","input":{"file_path":"/p/calc.py","old_string":"x","new_string":"# totals up"}}]}}`,
	)
	r := &fakeReviewer{}
	runWith(claude.New(), r, payload(tp))
	if r.called {
		t.Fatal("a comment-only inert turn must NOT reach the reviewer")
	}
	if r.telemetryCalls != 1 || r.telemetryReason != wire.TelemetryInert {
		t.Fatalf("expected one inert telemetry ping, got calls=%d reason=%q", r.telemetryCalls, r.telemetryReason)
	}
	if r.telemetryMeta.DurationMs != 50000 {
		t.Errorf("inert-turn telemetry duration = %d, want 50000", r.telemetryMeta.DurationMs)
	}
}
