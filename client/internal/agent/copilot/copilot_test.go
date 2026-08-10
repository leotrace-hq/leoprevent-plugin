package copilot

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/agent"
)

// TestParseEventSnakeCase covers the VS Code / Claude-compat dialect.
func TestParseEventSnakeCase(t *testing.T) {
	a := New()
	ev, err := a.ParseEvent([]byte(`{
		"session_id": "s1-snake",
		"transcript_path": "/tmp/t.jsonl",
		"hook_event_name": "Stop",
		"stop_hook_active": true,
		"cwd": "/work",
		"last_assistant_message": "done"
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if ev.Name != "Stop" || ev.SessionID != "s1-snake" || ev.Cwd != "/work" ||
		ev.TranscriptPath != "/tmp/t.jsonl" || !ev.StopHookActive || ev.LastAssistantMessage != "done" {
		t.Fatalf("bad event: %+v", ev)
	}
}

// TestParseEventCamelCase covers the Copilot CLI native dialect: no event-name
// field, camelCase ids, stopReason marks the Stop.
func TestParseEventCamelCase(t *testing.T) {
	a := New()
	ev, err := a.ParseEvent([]byte(`{
		"sessionId": "s2-camel",
		"transcriptPath": "/tmp/rollout.json",
		"cwd": "/work",
		"stopReason": "end_turn"
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if ev.IsUserPromptSubmit() {
		t.Fatal("stopReason payload must route to the review path")
	}
	if ev.SessionID != "s2-camel" || ev.TranscriptPath != "/tmp/rollout.json" || ev.Cwd != "/work" {
		t.Fatalf("camelCase fields not mapped: %+v", ev)
	}
}

// TestParseEventNormalizesNames maps both runtimes' event names onto the seam
// contract.
func TestParseEventNormalizesNames(t *testing.T) {
	a := New()
	for name, wantUPS := range map[string]bool{
		"userPromptSubmitted": true,  // CLI spelling
		"UserPromptSubmit":    true,  // VS Code / Claude-compat spelling
		"agentStop":           false, // CLI spelling → review path
		"Stop":                false, // VS Code spelling → review path
	} {
		ev, err := a.ParseEvent([]byte(`{"session_id":"sn","hook_event_name":"` + name + `"}`))
		if err != nil {
			t.Fatal(err)
		}
		if got := ev.IsUserPromptSubmit(); got != wantUPS {
			t.Errorf("%s: IsUserPromptSubmit=%v, want %v", name, got, wantUPS)
		}
	}
}

// TestParseEventInfersPromptSubmit: no event name + a prompt body (and no
// stop_reason) is a turn start, not a Stop.
func TestParseEventInfersPromptSubmit(t *testing.T) {
	a := New()
	ev, err := a.ParseEvent([]byte(`{"sessionId":"s3","cwd":"/w","prompt":"add a route"}`))
	if err != nil {
		t.Fatal(err)
	}
	if !ev.IsUserPromptSubmit() {
		t.Fatal("prompt-carrying payload without stop_reason must route to baseline capture")
	}
}

// TestParseEventAmbiguousDefaultsToStop: with neither event name, stop_reason,
// nor prompt, ambiguity must fail toward review (a skipped Stop is a silent
// unreviewed turn; a reviewed turn start is a no-op).
func TestParseEventAmbiguousDefaultsToStop(t *testing.T) {
	a := New()
	ev, err := a.ParseEvent([]byte(`{"sessionId":"s4","cwd":"/w"}`))
	if err != nil {
		t.Fatal(err)
	}
	if ev.IsUserPromptSubmit() {
		t.Fatal("ambiguous payload must route to the review path")
	}
}

// TestLoopGuardRoundTrip is the load-bearing test: Copilot CLI stdin has no
// stop_hook_active, so DeliverReview must arm a marker that the NEXT Stop parse
// consumes as the per-turn guard — once.
func TestLoopGuardRoundTrip(t *testing.T) {
	sid := "guard-" + sanitize(t.Name())
	clearGuard(sid)
	t.Cleanup(func() { clearGuard(sid) })
	stop := []byte(`{"sessionId":"` + sid + `","stopReason":"end_turn"}`)

	a := New()
	ev, err := a.ParseEvent(stop)
	if err != nil {
		t.Fatal(err)
	}
	if ev.StopHookActive {
		t.Fatal("first Stop must not be the guard turn")
	}
	if _, err := a.DeliverReview("fix it", "banner", 1, nil); err != nil {
		t.Fatal(err)
	}

	// The post-re-wake Stop: marker present → guard turn, consumed.
	ev, err = New().ParseEvent(stop)
	if err != nil {
		t.Fatal(err)
	}
	if !ev.StopHookActive {
		t.Fatal("Stop after a delivered block must carry the self-managed guard")
	}
	ev, err = New().ParseEvent(stop)
	if err != nil {
		t.Fatal(err)
	}
	if ev.StopHookActive {
		t.Fatal("guard marker must be consume-once")
	}
}

// TestLoopGuardClearedByPromptSubmit: a new turn start invalidates a stale
// marker (e.g. the runtime ignored our block), so the next real Stop is reviewed.
func TestLoopGuardClearedByPromptSubmit(t *testing.T) {
	sid := "guard-" + sanitize(t.Name())
	clearGuard(sid)
	t.Cleanup(func() { clearGuard(sid) })

	a := New()
	if _, err := a.ParseEvent([]byte(`{"sessionId":"` + sid + `","stopReason":"end_turn"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := a.DeliverReview("fix it", "banner", 1, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := New().ParseEvent([]byte(`{"sessionId":"` + sid + `","hook_event_name":"userPromptSubmitted","prompt":"next task"}`)); err != nil {
		t.Fatal(err)
	}
	ev, err := New().ParseEvent([]byte(`{"sessionId":"` + sid + `","stopReason":"end_turn"}`))
	if err != nil {
		t.Fatal(err)
	}
	if ev.StopHookActive {
		t.Fatal("UserPromptSubmit must clear a stale guard marker")
	}
}

// TestParseEventHonorsNativeGuard: VS Code documents stop_hook_active — it must
// pass through without needing the marker.
func TestParseEventHonorsNativeGuard(t *testing.T) {
	a := New()
	ev, err := a.ParseEvent([]byte(`{"session_id":"native","hook_event_name":"Stop","stop_hook_active":true}`))
	if err != nil {
		t.Fatal(err)
	}
	if !ev.StopHookActive {
		t.Fatal("native stop_hook_active must be honored")
	}
}

// TestDeliverReviewDualDialect: the block output must satisfy BOTH runtimes —
// top-level decision/reason (CLI) and hookSpecificOutput (VS Code).
func TestDeliverReviewDualDialect(t *testing.T) {
	out, err := New().DeliverReview("the prompt", "the banner", 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Decision           string `json:"decision"`
		Reason             string `json:"reason"`
		SystemMessage      string `json:"systemMessage"`
		HookSpecificOutput struct {
			HookEventName string `json:"hookEventName"`
			Decision      string `json:"decision"`
			Reason        string `json:"reason"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if got.Decision != "block" || got.Reason != "the prompt" || got.SystemMessage != "the banner" {
		t.Fatalf("CLI dialect wrong: %s", out)
	}
	h := got.HookSpecificOutput
	if h.HookEventName != "Stop" || h.Decision != "block" || h.Reason != "the prompt" {
		t.Fatalf("VS Code dialect wrong: %s", out)
	}
}

// TestDeliverNoticeIsNonBlocking: the notice must carry NO decision anywhere so
// the turn still yields.
func TestDeliverNoticeIsNonBlocking(t *testing.T) {
	out, err := New().DeliverNotice("server unreachable")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "decision") {
		t.Fatalf("notice must not block: %s", out)
	}
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if got["systemMessage"] != "server unreachable" {
		t.Fatalf("notice message missing: %s", out)
	}
}

// TestAgentInterface pins the compile-time contract.
var _ agent.Agent = (*Adapter)(nil)

// Copilot must stay on the PREVIOUS systemMessage-only update nag. Both Copilot
// runtimes are unverified here, and VS Code agent mode PARSES hookSpecificOutput
// (it is the field it reads for Stop decisions), so emitting a differently-shaped
// one is an untested risk. Guards the seam against being "completed" for all three
// adapters at once; delete only with a live VS Code verification.
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
		t.Errorf("copilot must NOT emit hookSpecificOutput (unverified runtime); got %s", out)
	}
	if m["systemMessage"] != "⚠️  update available" {
		t.Errorf("systemMessage = %v, want the verbatim message", m["systemMessage"])
	}
	if len(m) != 1 {
		t.Errorf("copilot prompt notice must carry exactly systemMessage; got %s", out)
	}
}
