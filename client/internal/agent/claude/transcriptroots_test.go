package claude

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeClaudeTranscript writes a one-turn transcript that edits /p/app.py and carries a
// prompt, so a read of it is visible in ChangedFiles and TurnMeta alike.
func writeClaudeTranscript(t *testing.T, path string) {
	t.Helper()
	lines := []string{
		`{"type":"user","message":{"role":"user","content":"add a route"},"timestamp":"2026-10-29T10:00:00Z"}`,
		`{"type":"assistant","message":{"role":"assistant","model":"claude-x","content":[{"type":"tool_use","name":"Write","input":{"file_path":"/p/app.py","content":"x = 1"}}]}}`,
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// stopPayload marshals rather than concatenates, so a Windows path stays valid JSON.
func stopPayload(path string) []byte {
	b, _ := json.Marshal(map[string]any{"hook_event_name": "Stop", "session_id": "s", "transcript_path": path})
	return b
}

// TestATranscriptOutsideClaudesRootsIsNeverRead pins LEO-334: the hook's transcript_path is
// stdin, and a path outside Claude Code's own transcript roots is dropped in ParseEvent, so
// no reader opens it. Dropping is fail-open: every seam returns its empty value, no error.
func TestATranscriptOutsideClaudesRootsIsNeverRead(t *testing.T) {
	t.Setenv("CLAUDE_CONFIG_DIR", t.TempDir())
	outside := filepath.Join(t.TempDir(), "elsewhere", "s.jsonl")
	writeClaudeTranscript(t, outside)

	a := New()
	ev, err := a.ParseEvent(stopPayload(outside))
	if err != nil {
		t.Fatal(err)
	}
	if ev.TranscriptPath != "" {
		t.Fatalf("a transcript outside the roots was kept: %q", ev.TranscriptPath)
	}
	changes, err := a.ChangedFiles(ev)
	if err != nil || len(changes) != 0 {
		t.Errorf("ChangedFiles read a rejected transcript: %+v, %v", changes, err)
	}
	meta, err := a.TurnMeta(ev)
	if err != nil || meta.Prompt != "" || meta.AgentModel != "" {
		t.Errorf("TurnMeta read a rejected transcript: %+v, %v", meta, err)
	}
	if reply, err := a.AgentReply(ev); err != nil || reply != "" {
		t.Errorf("AgentReply read a rejected transcript: %q, %v", reply, err)
	}
}

func TestATranscriptUnderClaudesRootsIsRead(t *testing.T) {
	cfg := t.TempDir()
	t.Setenv("CLAUDE_CONFIG_DIR", cfg)
	inside := filepath.Join(cfg, "projects", "-repo", "s.jsonl")
	writeClaudeTranscript(t, inside)

	a := New()
	ev, err := a.ParseEvent(stopPayload(inside))
	if err != nil {
		t.Fatal(err)
	}
	want, err := filepath.EvalSymlinks(inside)
	if err != nil {
		t.Fatal(err)
	}
	if ev.TranscriptPath != want {
		t.Fatalf("a transcript under CLAUDE_CONFIG_DIR/projects was dropped: %q", ev.TranscriptPath)
	}
	changes, err := a.ChangedFiles(ev)
	if err != nil || len(changes) != 1 {
		t.Errorf("ChangedFiles = %+v, %v; want the one edit", changes, err)
	}
}
