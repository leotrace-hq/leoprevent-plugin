package copilot

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/agent"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
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

// Copilot exports no entrypoint variable, but it does not need to: its two runtimes
// speak DIFFERENT dialects of the same hook, so the payload already names its sender.
func TestEnvironmentFromStdinDialect(t *testing.T) {
	vscode := New()
	if _, err := vscode.ParseEvent([]byte(`{"session_id":"s1","hook_event_name":"Stop","cwd":"/w"}`)); err != nil {
		t.Fatal(err)
	}
	if env := vscode.Environment(agent.Event{}); env.Name != wire.EnvCopilotVSCode {
		t.Errorf("snake_case dialect = %q, want %q", env.Name, wire.EnvCopilotVSCode)
	}

	cli := New()
	if _, err := cli.ParseEvent([]byte(`{"sessionId":"s2","stopReason":"end_turn","cwd":"/w"}`)); err != nil {
		t.Fatal(err)
	}
	if env := cli.Environment(agent.Event{}); env.Name != wire.EnvCopilotCLI {
		t.Errorf("camelCase dialect = %q, want %q", env.Name, wire.EnvCopilotCLI)
	}
}

// The signal here is STRUCTURAL — which spelling the keys used — not a value the
// vendor handed us. Quoting "the keys were snake_case" into Raw as though it were a
// vendor string would misrepresent where the answer came from.
func TestEnvironmentRawIsEmptyForAStructuralSignal(t *testing.T) {
	a := New()
	if _, err := a.ParseEvent([]byte(`{"session_id":"s1","hook_event_name":"Stop"}`)); err != nil {
		t.Fatal(err)
	}
	if env := a.Environment(agent.Event{}); env.Raw != "" {
		t.Errorf("Environment().Raw = %q, want empty", env.Raw)
	}
}

// A payload carrying BOTH dialects resolves to VS Code, matching the per-field
// snake_case-wins precedence in hookPayload. The value matters less than the fact that
// it is fixed: an ambiguous payload must not classify differently run to run.
func TestEnvironmentAmbiguousDialectIsDeterministic(t *testing.T) {
	const both = `{"session_id":"s1","sessionId":"s1","hook_event_name":"Stop","hookEventName":"agentStop"}`
	for i := 0; i < 3; i++ {
		a := New()
		if _, err := a.ParseEvent([]byte(both)); err != nil {
			t.Fatal(err)
		}
		if env := a.Environment(agent.Event{}); env.Name != wire.EnvCopilotVSCode {
			t.Fatalf("both-dialect payload = %q, want %q (snake_case wins, as it does per-field)", env.Name, wire.EnvCopilotVSCode)
		}
	}
}

// Before ParseEvent — and after one that recognised neither dialect — the answer is
// unknown, NOT a default runtime. Defaulting to the CLI would be the worst option
// available: it is the unverified path, so a wrong answer there is the one least
// likely to be noticed.
func TestEnvironmentWithoutADialectIsUnknown(t *testing.T) {
	if env := New().Environment(agent.Event{}); env.Name != wire.EnvUnknown {
		t.Errorf("un-parsed adapter = %q, want %q", env.Name, wire.EnvUnknown)
	}

	a := New()
	if _, err := a.ParseEvent([]byte(`{"cwd":"/w"}`)); err != nil {
		t.Fatal(err)
	}
	if env := a.Environment(agent.Event{}); env.Name != wire.EnvUnknown {
		t.Errorf("dialect-free payload = %q, want %q", env.Name, wire.EnvUnknown)
	}
}

// --- agent reply (LEO-156) ---

// stopStdin builds a Stop payload with encoding/json rather than by concatenating into a
// string literal. A transcript path is an OS path, and on Windows it is `C:\Users\...` —
// pasted into a JSON literal that is an invalid `\U` escape, so the four tests below failed
// on windows-latest only. Marshalling is the fix that cannot regress; `dialect` picks which
// spelling, since the adapter infers the runtime from it.
func stopStdin(t *testing.T, dialect, sid, transcriptPath string, nativeGuard bool) []byte {
	t.Helper()
	m := map[string]any{}
	switch dialect {
	case "camel": // Copilot CLI
		m["sessionId"] = sid
		m["stopReason"] = "end_turn"
		if transcriptPath != "" {
			m["transcriptPath"] = transcriptPath
		}
	default: // snake_case, VS Code agent mode
		m["session_id"] = sid
		m["hook_event_name"] = "Stop"
		if transcriptPath != "" {
			m["transcript_path"] = transcriptPath
		}
		if nativeGuard {
			m["stop_hook_active"] = true
		}
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// copilotTurn is a Copilot transcript spanning a block: one pre-block message, then the
// two the agent emitted after our re-wake. The timestamps are what the parser splits on,
// so they are set relative to the test's own clock rather than hardcoded.
func copilotTurn(t *testing.T, before, after time.Time) string {
	t.Helper()
	body := `{"type":"user.message","data":{"content":"do the thing"},"timestamp":"` + before.Format(time.RFC3339Nano) + `"}
{"type":"assistant.message","data":{"messageId":"pre","content":"Added the feature."},"timestamp":"` + before.Format(time.RFC3339Nano) + `"}
{"type":"assistant.message","data":{"messageId":"post","content":"That is a false positive: the input is already validated upstream."},"timestamp":"` + after.Format(time.RFC3339Nano) + `"}
`
	p := filepath.Join(t.TempDir(), "transcript.jsonl")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestAgentReplyReadsThePostBlockProse walks the whole plumbing the way a real turn does:
// the first Stop delivers a block (which stamps the guard), the second Stop parses, and
// AgentReply resolves the reply from the marker's stamp. It is the CLI dialect, where
// ParseEvent also CONSUMES the marker — so this is what pins reading the stamp before the
// consume rather than inside AgentReply, which would find the file gone.
func TestAgentReplyReadsThePostBlockProse(t *testing.T) {
	sid := "reply-" + sanitize(t.Name())
	clearGuard(sid)
	t.Cleanup(func() { clearGuard(sid) })

	a := New()
	if _, err := a.ParseEvent([]byte(`{"sessionId":"` + sid + `","stopReason":"end_turn"}`)); err != nil {
		t.Fatal(err)
	}
	before := time.Now().UTC().Add(-time.Minute)
	if _, err := a.DeliverReview("fix the SSRF", "banner", 1, nil); err != nil {
		t.Fatal(err)
	}
	tp := copilotTurn(t, before, time.Now().UTC().Add(time.Minute))

	second := New()
	ev, err := second.ParseEvent(stopStdin(t, "camel", sid, tp, false))
	if err != nil {
		t.Fatal(err)
	}
	if !ev.StopHookActive {
		t.Fatal("the post-block Stop must still be the guard turn")
	}
	got, err := second.AgentReply(ev)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "false positive") {
		t.Errorf("want the agent's push-back, got %q", got)
	}
	if strings.Contains(got, "Added the feature") {
		t.Errorf("pre-block commentary must not be reported as the reply: %q", got)
	}
}

// TestAgentReplyUnderTheNativeGuard is the VS Code path, and it is the one the short-circuit
// would have broken silently. `!ev.StopHookActive && consumeGuard(...)` never calls the
// consume when the payload carries a native stop_hook_active, so a stamp read from inside
// that branch would leave the VERIFIED runtime with no boundary and no reply — the exact bug
// this ticket is about, still present but now invisible.
func TestAgentReplyUnderTheNativeGuard(t *testing.T) {
	sid := "native-" + sanitize(t.Name())
	clearGuard(sid)
	t.Cleanup(func() { clearGuard(sid) })

	a := New()
	if _, err := a.ParseEvent([]byte(`{"session_id":"` + sid + `","hook_event_name":"Stop"}`)); err != nil {
		t.Fatal(err)
	}
	before := time.Now().UTC().Add(-time.Minute)
	if _, err := a.DeliverReview("fix it", "banner", 1, nil); err != nil {
		t.Fatal(err)
	}
	tp := copilotTurn(t, before, time.Now().UTC().Add(time.Minute))

	second := New()
	ev, err := second.ParseEvent(stopStdin(t, "snake", sid, tp, true))
	if err != nil {
		t.Fatal(err)
	}
	got, err := second.AgentReply(ev)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "false positive") {
		t.Errorf("a natively-guarded Stop must still resolve the reply, got %q", got)
	}
}

// TestALegacyGuardMarkerStillGuardsTheLoop: an unstamped marker is what an in-flight session
// upgraded mid-turn leaves behind. The loop guard reads PRESENCE, so it must still fire — a
// missed guard blocks the agent forever, where a missing stamp costs that one turn its reply.
func TestALegacyGuardMarkerStillGuardsTheLoop(t *testing.T) {
	sid := "legacy-" + sanitize(t.Name())
	clearGuard(sid)
	t.Cleanup(func() { clearGuard(sid) })

	p := guardPath(sid)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("1"), 0o600); err != nil { // the pre-LEO-156 content
		t.Fatal(err)
	}
	tp := copilotTurn(t, time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Minute))

	a := New()
	ev, err := a.ParseEvent(stopStdin(t, "camel", sid, tp, false))
	if err != nil {
		t.Fatal(err)
	}
	if !ev.StopHookActive {
		t.Fatal("an unstamped marker must still stop the loop")
	}
	got, err := a.AgentReply(ev)
	if err != nil {
		t.Fatal(err)
	}
	if got != "" {
		t.Errorf("an unstamped marker gives no boundary, so no reply may be claimed; got %q", got)
	}
}

// TestAgentReplyWithoutABlockIsEmpty: a Stop that follows no block of ours has no marker, so
// there is nothing to answer and nothing to anchor on. Returning the turn's prose here would
// invent a reply to a review that never happened.
func TestAgentReplyWithoutABlockIsEmpty(t *testing.T) {
	sid := "noblock-" + sanitize(t.Name())
	clearGuard(sid)
	t.Cleanup(func() { clearGuard(sid) })
	tp := copilotTurn(t, time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Minute))

	a := New()
	ev, err := a.ParseEvent(stopStdin(t, "camel", sid, tp, false))
	if err != nil {
		t.Fatal(err)
	}
	got, err := a.AgentReply(ev)
	if err != nil {
		t.Fatal(err)
	}
	if got != "" {
		t.Errorf("no block means no reply, got %q", got)
	}
}

// TestArmGuardStampsATimestamp pins the marker's CONTENT, because nothing else does: the loop
// guard only looks at presence, so armGuard could regress to writing "1" with every guard test
// still green and only the reply quietly gone.
func TestArmGuardStampsATimestamp(t *testing.T) {
	sid := "stamp-" + sanitize(t.Name())
	clearGuard(sid)
	t.Cleanup(func() { clearGuard(sid) })

	a := New()
	if _, err := a.ParseEvent([]byte(`{"sessionId":"` + sid + `","stopReason":"end_turn"}`)); err != nil {
		t.Fatal(err)
	}
	start := time.Now().UTC().Add(-time.Second)
	if _, err := a.DeliverReview("fix it", "banner", 1, nil); err != nil {
		t.Fatal(err)
	}
	at, ok := guardStamp(sid)
	if !ok {
		t.Fatal("DeliverReview must stamp the marker with the delivery time")
	}
	if at.Before(start) || at.After(time.Now().UTC().Add(time.Second)) {
		t.Errorf("stamp %s is not the delivery time", at)
	}
}

// TestStopStdinHandlesAWindowsPath pins the reason stopStdin exists. The four tests above
// originally built their payload by concatenating the transcript path into a JSON string
// literal, which is fine for a POSIX temp path and invalid JSON for a Windows one
// (`C:\Users\...` opens a `\U` escape) — so they passed on macOS and Linux and failed on
// windows-latest only, in CI, after review. Marshalling is the fix; this asserts it, in both
// stdin dialects, against a path shaped like the runner's real one.
func TestStopStdinHandlesAWindowsPath(t *testing.T) {
	const win = `C:\Users\runneradmin\AppData\Local\Temp\TestAgentReply\transcript.jsonl`
	for _, dialect := range []string{"camel", "snake"} {
		b := stopStdin(t, dialect, "sid-1", win, false)
		var back map[string]any
		if err := json.Unmarshal(b, &back); err != nil {
			t.Fatalf("%s: payload is not valid JSON: %v", dialect, err)
		}
		ev, err := New().ParseEvent(b)
		if err != nil {
			t.Fatalf("%s: ParseEvent: %v", dialect, err)
		}
		if ev.TranscriptPath != win {
			t.Errorf("%s: path came back mangled: %q", dialect, ev.TranscriptPath)
		}
	}
}
