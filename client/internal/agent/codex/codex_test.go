package codex

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/agent"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

func TestParseEvent(t *testing.T) {
	ev, err := New().ParseEvent([]byte(`{"stop_hook_active":true,"transcript_path":"/t/x.jsonl","cwd":"/work","turn_id":"abc","model":"gpt"}`))
	if err != nil {
		t.Fatal(err)
	}
	if !ev.StopHookActive || ev.TranscriptPath != "/t/x.jsonl" {
		t.Errorf("unexpected event: %+v", ev)
	}
}

func TestParseEventGarbage(t *testing.T) {
	if _, err := New().ParseEvent([]byte("{bad")); err == nil {
		t.Error("expected error on garbage stdin")
	}
}

func TestChangedFilesNoTranscript(t *testing.T) {
	// No transcript path → nil (engine treats as silent).
	changes, err := New().ChangedFiles(agent.Event{TranscriptPath: ""})
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 0 {
		t.Errorf("expected no changes without transcript, got %+v", changes)
	}
}

func TestDeliverReviewIsBlockDecision(t *testing.T) {
	banner := "🔒 LeoPrevent: security review (1 file)"
	out, err := New().DeliverReview("review this", banner, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	var d struct {
		Decision      string `json:"decision"`
		Reason        string `json:"reason"`
		SystemMessage string `json:"systemMessage"`
	}
	if err := json.Unmarshal(out, &d); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if d.Decision != "block" {
		t.Errorf("Codex re-wake should be {decision:block}, got %+v", d)
	}
	if d.SystemMessage != banner {
		t.Errorf("systemMessage = %q, want banner %q", d.SystemMessage, banner)
	}
}

// DeliverNotice is the fail-open counterpart: a systemMessage with NO decision,
// so the developer sees it but the turn still yields (never trapped on an outage).
func TestDeliverNoticeIsNonBlocking(t *testing.T) {
	out, err := New().DeliverNotice("⚠️ server unreachable")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if _, ok := m["decision"]; ok {
		t.Errorf("notice must NOT block (no decision), got %s", out)
	}
	if m["systemMessage"] != "⚠️ server unreachable" {
		t.Errorf("systemMessage = %v, want the message", m["systemMessage"])
	}
}

func TestName(t *testing.T) {
	if New().Name() != "codex" {
		t.Errorf("Name = %q", New().Name())
	}
}

// TestParseEventBaselineFields pins SessionID/Cwd (drive the git baseline) and
// Name (UserPromptSubmit vs Stop routing) — parity with the Claude adapter test.
func TestParseEventBaselineFields(t *testing.T) {
	ev, err := New().ParseEvent([]byte(`{"hook_event_name":"UserPromptSubmit","session_id":"sess-9","cwd":"/repo2","transcript_path":"/t/r.jsonl"}`))
	if err != nil {
		t.Fatal(err)
	}
	if ev.Name != "UserPromptSubmit" || !ev.IsUserPromptSubmit() {
		t.Errorf("UserPromptSubmit routing field not parsed: %+v", ev)
	}
	if ev.SessionID != "sess-9" || ev.Cwd != "/repo2" {
		t.Errorf("SessionID/Cwd not parsed: %+v", ev)
	}
}

// TestTurnMetaFromRollout covers the Stop-hook (B) wiring: the adapter parses the
// rollout the Stop event points at into agent.TurnMeta (model + token lanes +
// duration). The detailed token math lives in the transcript pkg's tests; this
// guards that the adapter actually reads the path and maps the fields.
func TestTurnMetaFromRollout(t *testing.T) {
	lines := []string{
		`{"timestamp":"2026-06-16T10:00:00.000Z","type":"turn_context","payload":{"model":"gpt-5.5"}}`,
		`{"timestamp":"2026-06-16T10:00:01.000Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"text","text":"do it"}]}}`,
		`{"timestamp":"2026-06-16T10:00:09.000Z","type":"event_msg","payload":{"type":"token_count","info":{"last_token_usage":{"input_tokens":5000,"cached_input_tokens":4000,"output_tokens":120}}}}`,
	}
	p := filepath.Join(t.TempDir(), "rollout.jsonl")
	if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m, err := (&Adapter{}).TurnMeta(agent.Event{TranscriptPath: p})
	if err != nil {
		t.Fatal(err)
	}
	if m.AgentModel != "gpt-5.5" || m.InputTokens != 1000 || m.CacheReadTokens != 4000 ||
		m.OutputTokens != 120 || m.CacheCreationTokens != 0 || m.Speed != "" || m.DurationMs != 8000 {
		t.Errorf("adapter TurnMeta wrong: %+v", m)
	}
	// Empty transcript path → zero meta, no error (best-effort).
	if z, err := (&Adapter{}).TurnMeta(agent.Event{}); err != nil || z != (agent.TurnMeta{}) {
		t.Errorf("empty path should give zero meta, got %+v err=%v", z, err)
	}
}

// TestTurnMetaFromRealRollout_0_140 is a REGRESSION GUARD against a Codex rollout-format
// change. The fixture (testdata/rollout-codex-0.140.jsonl) holds records CAPTURED from a
// real Codex CLI 0.140.0 TUI session on 2026-06-18 — the same run that verified the Codex
// Stop-hook path end-to-end. The format is "not a stable
// interface" per Codex's own docs, so if a future CLI changes it this test fails loudly
// instead of the adapter silently producing zero meta. Token mapping: Codex's input_tokens
// INCLUDES the cached portion, so uncached input = input − cached → our input lane, cached →
// cache-read lane, no cache-write; duration = last token_count − first user message.
func TestTurnMetaFromRealRollout_0_140(t *testing.T) {
	m, err := (&Adapter{}).TurnMeta(agent.Event{TranscriptPath: "testdata/rollout-codex-0.140.jsonl"})
	if err != nil {
		t.Fatal(err)
	}
	// Real captured values: model gpt-5.5; last_token_usage input 18084 / cached 15232 /
	// output 83; timestamps 10:24:21.679 → 10:25:17.342 (55663 ms).
	if m.AgentModel != "gpt-5.5" {
		t.Errorf("model = %q, want gpt-5.5", m.AgentModel)
	}
	if m.InputTokens != 18084-15232 { // uncached input = input − cached
		t.Errorf("input = %d, want %d (uncached)", m.InputTokens, 18084-15232)
	}
	if m.CacheReadTokens != 15232 {
		t.Errorf("cache-read = %d, want 15232", m.CacheReadTokens)
	}
	if m.OutputTokens != 83 {
		t.Errorf("output = %d, want 83", m.OutputTokens)
	}
	if m.CacheCreationTokens != 0 { // Codex has no cache-write lane
		t.Errorf("cache-write = %d, want 0", m.CacheCreationTokens)
	}
	if m.Speed != "" { // Codex has no Fast tier
		t.Errorf("speed = %q, want empty", m.Speed)
	}
	if m.DurationMs != 55663 {
		t.Errorf("duration = %d ms, want 55663", m.DurationMs)
	}
}

// Codex must stay on the PREVIOUS systemMessage-only update nag: the injected-context
// half is verified on Claude Code ONLY, and Codex's handling of an additionalContext
// hookSpecificOutput is untested. This guards against "tidying up" the seam by
// pointing all three adapters at review.PromptNoticeJSON — which would silently
// change an unverified platform. Delete this only with a live Codex verification.
func TestDeliverPromptNoticeStaysSystemMessageOnly(t *testing.T) {
	out, err := (&Adapter{}).DeliverPromptNotice("⚠️  update available", "tell the developer")
	if err != nil {
		t.Fatalf("DeliverPromptNotice: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := m["hookSpecificOutput"]; ok {
		t.Errorf("codex must NOT emit hookSpecificOutput (unverified runtime); got %s", out)
	}
	if m["systemMessage"] != "⚠️  update available" {
		t.Errorf("systemMessage = %v, want the verbatim message", m["systemMessage"])
	}
	if len(m) != 1 {
		t.Errorf("codex prompt notice must carry exactly systemMessage; got %s", out)
	}
}

// Reaching this adapter at all IS the classification: it only ever runs from the
// Codex CLI's own Stop hook. The headless path never arrives here — `leoprevent exec`
// drives Codex itself and attributes to wire.EnvCodexExec — so the two surfaces stay
// distinguishable without this adapter having to tell them apart.
func TestEnvironmentIsCodexCLI(t *testing.T) {
	if env := New().Environment(agent.Event{}); env.Name != wire.EnvCodexCLI {
		t.Errorf("Environment().Name = %q, want %q", env.Name, wire.EnvCodexCLI)
	}
}

// Raw stays EMPTY. Codex exports no entrypoint we have verified, and a raw value is
// meant to be a quotation of what the vendor told us — synthesising one (echoing
// "codex-cli" back into it) would be indistinguishable in the log from a real reading
// and would mask the day Codex starts reporting a surface for real.
func TestEnvironmentCarriesNoInventedRawSignal(t *testing.T) {
	if env := New().Environment(agent.Event{}); env.Raw != "" {
		t.Errorf("Environment().Raw = %q, want empty — there is no vendor signal to quote", env.Raw)
	}
}
