package transcript

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeTranscript writes JSONL lines to a temp file and returns its path.
func writeTranscript(t *testing.T, lines ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "transcript.jsonl")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

const (
	userMsg = `{"type":"user","message":{"role":"user","content":"add a refresh route"}}`
	// A Write tool_use in an assistant entry.
	writeTool = `{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","name":"Write","input":{"file_path":"/p/app.py","content":"resp = requests.get(url)"}}]}}`
	// An Edit tool_use.
	editTool = `{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","name":"Edit","input":{"file_path":"/p/db.py","old_string":"x","new_string":"cursor.execute(q)"}}]}}`
	// A tool_result user entry (must NOT count as a turn start).
	toolResult = `{"type":"user","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"x","content":"ok"}]}}`
	// A re-wake injection (must NOT count as a turn start).
	stopFeedback = `{"type":"user","message":{"role":"user","content":"Stop hook feedback:\nreview your changes"}}`
)

func TestParseTurnMeta(t *testing.T) {
	// A full turn: a genuine user prompt (with a timestamp), two assistant
	// messages carrying model + usage + timestamps. Tokens sum across both; the
	// model is the last non-empty; duration = last assistant ts − prompt ts (60s).
	lines := []string{
		`{"type":"user","timestamp":"2026-06-09T08:00:00Z","message":{"role":"user","content":"add a fetch route"}}`,
		`{"type":"assistant","timestamp":"2026-06-09T08:00:20Z","message":{"role":"assistant","model":"claude-opus-4-8","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":10,"cache_creation_input_tokens":100,"cache_read_input_tokens":900,"output_tokens":50}}}`,
		`{"type":"assistant","timestamp":"2026-06-09T08:01:00Z","message":{"role":"assistant","model":"claude-opus-4-8","content":[{"type":"text","text":"done"}],"usage":{"input_tokens":5,"cache_creation_input_tokens":0,"cache_read_input_tokens":1000,"output_tokens":20}}}`,
	}
	m, err := ParseTurnMeta(writeTranscript(t, lines...))
	if err != nil {
		t.Fatal(err)
	}
	if m.Prompt != "add a fetch route" {
		t.Errorf("prompt = %q", m.Prompt)
	}
	if m.AgentModel != "claude-opus-4-8" {
		t.Errorf("model = %q", m.AgentModel)
	}
	if m.InputTokens != 15 || m.CacheCreationTokens != 100 || m.CacheReadTokens != 1900 || m.OutputTokens != 70 {
		t.Errorf("token sums wrong: %+v", m)
	}
	if m.DurationMs != 60000 {
		t.Errorf("duration = %d ms, want 60000", m.DurationMs)
	}
}

// Only the CURRENT turn counts: a prior turn's prompt/tokens are excluded, and a
// "Stop hook feedback:" re-wake does not start a new turn (so the figures still
// belong to the genuine prompt that began the turn).
func TestParseTurnMetaScopedToCurrentTurn(t *testing.T) {
	lines := []string{
		`{"type":"user","timestamp":"2026-06-09T07:00:00Z","message":{"role":"user","content":"OLD TURN"}}`,
		`{"type":"assistant","timestamp":"2026-06-09T07:00:10Z","message":{"role":"assistant","model":"claude-sonnet-4-6","content":[{"type":"text","text":"x"}],"usage":{"input_tokens":999,"output_tokens":999}}}`,
		`{"type":"user","timestamp":"2026-06-09T08:00:00Z","message":{"role":"user","content":"NEW TURN"}}`,
		`{"type":"assistant","timestamp":"2026-06-09T08:00:30Z","message":{"role":"assistant","model":"claude-opus-4-8","content":[{"type":"text","text":"y"}],"usage":{"input_tokens":3,"output_tokens":4}}}`,
		stopFeedback,
		`{"type":"assistant","timestamp":"2026-06-09T08:00:45Z","message":{"role":"assistant","model":"claude-opus-4-8","content":[{"type":"text","text":"z"}],"usage":{"input_tokens":1,"output_tokens":2}}}`,
	}
	m, err := ParseTurnMeta(writeTranscript(t, lines...))
	if err != nil {
		t.Fatal(err)
	}
	if m.Prompt != "NEW TURN" {
		t.Errorf("prompt = %q, want the current turn's", m.Prompt)
	}
	// Tokens span the genuine prompt through the post-re-wake assistant messages
	// (the re-wake is NOT a turn start), excluding the OLD turn's 999s.
	if m.InputTokens != 4 || m.OutputTokens != 6 {
		t.Errorf("tokens leaked across turns: %+v", m)
	}
}

func TestParseChangesBasic(t *testing.T) {
	path := writeTranscript(t, userMsg, writeTool, toolResult, editTool, toolResult)
	changes, err := ParseChanges(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 2 {
		t.Fatalf("expected 2 changed files, got %d: %+v", len(changes), changes)
	}
	if changes[0].FilePath != "/p/app.py" || !strings.Contains(changes[0].AddedText, "requests.get(url)") {
		t.Errorf("unexpected first change: %+v", changes[0])
	}
	if changes[1].FilePath != "/p/db.py" || !strings.Contains(changes[1].AddedText, "cursor.execute") {
		t.Errorf("unexpected second change: %+v", changes[1])
	}
}

func TestTurnStartsAtLastGenuineUserMessage(t *testing.T) {
	// Changes from a previous turn must not be picked up.
	prevTurnWrite := `{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","name":"Write","input":{"file_path":"/p/old.py","content":"old stuff"}}]}}`
	path := writeTranscript(t, userMsg, prevTurnWrite, userMsg, writeTool)
	changes, err := ParseChanges(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 1 || changes[0].FilePath != "/p/app.py" {
		t.Fatalf("expected only current-turn change, got %+v", changes)
	}
}

func TestStopHookFeedbackIsNotATurnStart(t *testing.T) {
	// The re-wake injection and tool_results come after the real user message;
	// changes before them still belong to the same turn.
	path := writeTranscript(t, userMsg, writeTool, stopFeedback, editTool)
	changes, err := ParseChanges(path)
	if err != nil {
		t.Fatal(err)
	}
	// Both changes belong to the turn started by userMsg.
	if len(changes) != 2 {
		t.Fatalf("expected 2 changes (turn start = genuine user msg), got %+v", changes)
	}
}

func TestGarbledLinesTolerated(t *testing.T) {
	path := writeTranscript(t, "not json at all", userMsg, "{broken", writeTool)
	changes, err := ParseChanges(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 1 {
		t.Fatalf("expected 1 change, got %+v", changes)
	}
}

func TestMissingTranscript(t *testing.T) {
	if _, err := ParseChanges("/nonexistent/transcript.jsonl"); err == nil {
		t.Error("expected error for missing transcript")
	}
}

// REGRESSION (the 1.85× over-count): Claude logs the SAME assistant message more
// than once — identical `id` + `usage` (streamed partials + final, plus re-renders).
// ParseTurnMeta must count each id ONCE, or tokens double/triple-count. This mirrors
// the real test4 transcript that logged 305k for a turn /cost said was ~165k.
func TestParseTurnMetaDedupesDuplicateMessageIDs(t *testing.T) {
	asst := func(id string, in, cacheR, out int) string {
		return `{"type":"assistant","timestamp":"2026-06-16T08:00:10Z","message":{"id":"` + id +
			`","role":"assistant","model":"claude-opus-4-8","content":[{"type":"text","text":"x"}],"usage":{"input_tokens":` +
			itoa(in) + `,"cache_read_input_tokens":` + itoa(cacheR) + `,"output_tokens":` + itoa(out) + `}}}`
	}
	lines := []string{
		`{"type":"user","timestamp":"2026-06-16T08:00:00Z","message":{"role":"user","content":"do it"}}`,
		asst("M1", 3000, 18000, 80),
		asst("M1", 3000, 18000, 80), // duplicate of M1 — must NOT be re-counted
		asst("M2", 2, 22000, 300),
		asst("M2", 2, 22000, 300), // duplicate
		asst("M2", 2, 22000, 300), // triple
		asst("M3", 1, 23000, 500),
	}
	m, err := ParseTurnMeta(writeTranscript(t, lines...))
	if err != nil {
		t.Fatal(err)
	}
	// Each unique id once: in 3000+2+1=3003, cacheR 18000+22000+23000=63000, out 880.
	if m.InputTokens != 3003 || m.CacheReadTokens != 63000 || m.OutputTokens != 880 {
		t.Errorf("dedup failed (counted duplicates): in=%d cacheR=%d out=%d, want 3003/63000/880",
			m.InputTokens, m.CacheReadTokens, m.OutputTokens)
	}
}
