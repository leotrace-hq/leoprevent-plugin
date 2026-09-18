package transcript

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// writeRollout writes Codex rollout JSONL lines to a temp file.
func writeRollout(t *testing.T, lines ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rollout.jsonl")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// These mirror the real rollout shape: response_item payloads, user messages
// as {type:message, role:user, content:[{type:input_text,text}]}, and edits as
// {type:custom_tool_call, name:apply_patch, input:<patch>}.
const (
	codexEnvMsg  = `{"type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"<environment_context>\n  <cwd>/p</cwd>\n</environment_context>"}]}}`
	codexUserMsg = `{"type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"add a refresh route"}]}}`
)

func codexApplyPatch(patch string) string {
	return `{"type":"response_item","payload":{"type":"custom_tool_call","name":"apply_patch","input":` + jsonString(patch) + `}}`
}

// jsonString minimally JSON-encodes a string for embedding in a test literal.
func jsonString(s string) string {
	b := &strings.Builder{}
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\t':
			b.WriteString(`\t`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func TestParseCodexChangesApplyPatch(t *testing.T) {
	patch := `*** Begin Patch
*** Update File: /p/app.py
@@
 @app.route("/preview")
 def preview():
     return "ok"

+@app.route("/refresh")
+def refresh():
+    url = request.args.get("url", "")
+    return requests.get(url).text

 if __name__ == "__main__":
     app.run()
*** End Patch`

	tp := writeRollout(t, codexEnvMsg, codexUserMsg, codexApplyPatch(patch))
	changes, err := ParseCodexChanges(tp)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 1 || changes[0].FilePath != "/p/app.py" {
		t.Fatalf("unexpected changes: %+v", changes)
	}
	// Only added (+) lines, no context/removed lines.
	if !strings.Contains(changes[0].AddedText, "/refresh") || !strings.Contains(changes[0].AddedText, "requests.get(url)") {
		t.Errorf("added text missing edit lines: %q", changes[0].AddedText)
	}
	if strings.Contains(changes[0].AddedText, `@app.route("/preview")`) {
		t.Error("context lines leaked into added text")
	}
}

func TestParseCodexAddFile(t *testing.T) {
	patch := "*** Begin Patch\n*** Add File: /p/new.py\n+import os\n+print(os.getcwd())\n*** End Patch"
	tp := writeRollout(t, codexUserMsg, codexApplyPatch(patch))
	changes, err := ParseCodexChanges(tp)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 1 || changes[0].FilePath != "/p/new.py" || !strings.Contains(changes[0].AddedText, "import os") {
		t.Fatalf("unexpected: %+v", changes)
	}
}

func TestCodexEnvWrapperIsNotTurnStart(t *testing.T) {
	// A prior-turn edit, then the env wrapper + genuine prompt + this-turn edit.
	prior := codexApplyPatch("*** Begin Patch\n*** Update File: /p/old.py\n+stale\n*** End Patch")
	cur := codexApplyPatch("*** Begin Patch\n*** Update File: /p/app.py\n+fresh\n*** End Patch")
	tp := writeRollout(t, codexUserMsg, prior, codexEnvMsg, codexUserMsg, cur)
	changes, err := ParseCodexChanges(tp)
	if err != nil {
		t.Fatal(err)
	}
	// Turn starts at the LAST genuine user msg → only /p/app.py, not /p/old.py.
	if len(changes) != 1 || changes[0].FilePath != "/p/app.py" {
		t.Fatalf("turn-start scoping wrong: %+v", changes)
	}
}

func TestParseCodexMissingTranscript(t *testing.T) {
	if _, err := ParseCodexChanges("/nonexistent/rollout.jsonl"); err == nil {
		t.Error("expected error for missing transcript")
	}
}

// TestCodexReWakeIsNotTurnStart is the regression for the reWakeMarker bug: when
// Codex surfaces leoprevent's own review prompt as a user message, it must NOT be
// treated as a turn start — otherwise the parser scopes the turn to only the
// post-re-wake edits and silently drops the original work that triggered review.
// The marker text MUST stay a prefix of review.BuildPrompt's first line (the
// review package's TestPromptPrefixMatchesCodexMarker pins the other side).
func TestCodexReWakeIsNotTurnStart(t *testing.T) {
	rewakeText := "🔒 LeoPrevent: security review required — run in a FRESH SUBAGENT via the Task tool (subagent_type: general-purpose).\n\n## Changed code this turn"
	rewakeMsg := `{"type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":` + jsonString(rewakeText) + `}]}}`
	work := codexApplyPatch("*** Begin Patch\n*** Update File: /p/app.py\n+url = request.args.get('url')\n*** End Patch")
	fix := codexApplyPatch("*** Begin Patch\n*** Update File: /p/app.py\n+# applied fix\n*** End Patch")

	tp := writeRollout(t, codexUserMsg, work, rewakeMsg, fix)
	changes, err := ParseCodexChanges(tp)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 1 || changes[0].FilePath != "/p/app.py" {
		t.Fatalf("unexpected changes: %+v", changes)
	}
	// The original pre-re-wake work must still be in scope. If the re-wake were
	// mis-detected as a turn start, this line would be gone.
	if !strings.Contains(changes[0].AddedText, "request.args") {
		t.Errorf("pre-re-wake work dropped — re-wake mis-detected as turn start: %q", changes[0].AddedText)
	}
}

// TestReWakeMarkerExcludesBothPrompts checks the marker is a prefix of BOTH
// review-prompt openings (local "…required" and cloud "…found issues"). Hardcoded
// here (review imports transcript, so transcript can't import review); the review
// package pins its side so the two can't silently drift apart.
func TestReWakeMarkerExcludesBothPrompts(t *testing.T) {
	for _, first := range []string{
		"🔒 LeoPrevent: security review required — run in a FRESH SUBAGENT.",
		"🔒 LeoPrevent: security review found issues that must be fixed before finishing this turn.",
	} {
		if !strings.HasPrefix(first, reWakeMarker) {
			t.Errorf("reWakeMarker %q is not a prefix of prompt opening %q", reWakeMarker, first)
		}
	}
}

// tokenCount builds a Codex `token_count` event_msg line.
func tokenCount(ts string, in, cached, out int) string {
	return `{"timestamp":"` + ts + `","type":"event_msg","payload":{"type":"token_count","info":{"last_token_usage":{"input_tokens":` +
		itoa(in) + `,"cached_input_tokens":` + itoa(cached) + `,"output_tokens":` + itoa(out) + `}}}}`
}
func codexUser(ts, text string) string {
	return `{"timestamp":"` + ts + `","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"text","text":` + jsonString(text) + `}]}}`
}
func itoa(n int) string { return strconv.Itoa(n) }

// TestParseCodexTurnMeta covers the real rollout shape: model from turn_context,
// per-request last_token_usage summed, the input/cached split, duration, and — the
// important one — turn scoping (a PRIOR turn's tokens must not be counted).
func TestParseCodexTurnMeta(t *testing.T) {
	tp := writeRollout(t,
		`{"timestamp":"2026-06-12T21:00:00.000Z","type":"turn_context","payload":{"model":"gpt-5.5"}}`,
		codexUser("2026-06-12T21:00:01.000Z", "first turn"),
		tokenCount("2026-06-12T21:00:02.000Z", 1000, 200, 50), // PRIOR turn — must be excluded
		codexUser("2026-06-12T21:05:00.000Z", "second turn please"),
		tokenCount("2026-06-12T21:05:02.000Z", 3000, 2000, 100),
		tokenCount("2026-06-12T21:05:05.000Z", 3500, 2500, 150),
	)
	m, err := ParseCodexTurnMeta(tp)
	if err != nil {
		t.Fatal(err)
	}
	if m.AgentModel != "gpt-5.5" {
		t.Errorf("model = %q, want gpt-5.5", m.AgentModel)
	}
	if m.Prompt != "second turn please" {
		t.Errorf("prompt = %q (turn scope wrong)", m.Prompt)
	}
	// Only turn-2 token_counts: input 3000+3500=6500, cached 2000+2500=4500, out 250.
	// Uncached input = 6500-4500 = 2000; the prior turn's 1000/200/50 must NOT appear.
	if m.InputTokens != 2000 {
		t.Errorf("InputTokens = %d, want 2000 (uncached, this turn only)", m.InputTokens)
	}
	if m.CacheReadTokens != 4500 {
		t.Errorf("CacheReadTokens = %d, want 4500", m.CacheReadTokens)
	}
	if m.OutputTokens != 250 {
		t.Errorf("OutputTokens = %d, want 250", m.OutputTokens)
	}
	if m.CacheCreationTokens != 0 || m.Speed != "" {
		t.Errorf("OpenAI has no cache-write/fast tier: cw=%d speed=%q", m.CacheCreationTokens, m.Speed)
	}
	if m.DurationMs != 5000 { // 21:05:00 → 21:05:05
		t.Errorf("DurationMs = %d, want 5000", m.DurationMs)
	}
}

// Exec case: one user input, whole run is one turn — mirrors the real measured
// numbers (sum-of-last == session total: input 49508, cached 40064, output 951).
func TestParseCodexTurnMetaExecWholeRun(t *testing.T) {
	tp := writeRollout(t,
		`{"timestamp":"2026-06-12T21:32:39.000Z","type":"turn_context","payload":{"model":"gpt-5.5"}}`,
		codexUser("2026-06-12T21:32:40.000Z", "do the task"),
		tokenCount("2026-06-12T21:32:48.000Z", 14387, 10624, 285),
		tokenCount("2026-06-12T21:32:55.000Z", 15633, 14208, 353),
		tokenCount("2026-06-12T21:33:03.000Z", 19488, 15232, 313),
	)
	m, _ := ParseCodexTurnMeta(tp)
	// input 49508, cached 40064 → uncached 9444; output 951.
	if m.InputTokens != 9444 || m.CacheReadTokens != 40064 || m.OutputTokens != 951 {
		t.Errorf("got in=%d cacheR=%d out=%d, want 9444/40064/951", m.InputTokens, m.CacheReadTokens, m.OutputTokens)
	}
}
