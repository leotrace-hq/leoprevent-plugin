package codex

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// copyRollout places the captured 0.140 rollout fixture (model + prompt + tokens) at path.
func copyRollout(t *testing.T, path string) {
	t.Helper()
	b, err := os.ReadFile("testdata/rollout-codex-0.140.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func stopPayload(path string) []byte {
	b, _ := json.Marshal(map[string]any{"hook_event_name": "Stop", "session_id": "s", "transcript_path": path})
	return b
}

// TestARolloutOutsideCodexsRootsIsNeverRead pins LEO-334 for Codex: a transcript_path
// outside $CODEX_HOME/sessions and ~/.codex/sessions is dropped in ParseEvent, and every
// seam then fails open with its empty value.
func TestARolloutOutsideCodexsRootsIsNeverRead(t *testing.T) {
	t.Setenv("CODEX_HOME", t.TempDir())
	outside := filepath.Join(t.TempDir(), "rollout.jsonl")
	copyRollout(t, outside)

	a := New()
	ev, err := a.ParseEvent(stopPayload(outside))
	if err != nil {
		t.Fatal(err)
	}
	if ev.TranscriptPath != "" {
		t.Fatalf("a rollout outside the roots was kept: %q", ev.TranscriptPath)
	}
	if changes, err := a.ChangedFiles(ev); err != nil || len(changes) != 0 {
		t.Errorf("ChangedFiles read a rejected rollout: %+v, %v", changes, err)
	}
	if meta, err := a.TurnMeta(ev); err != nil || meta.AgentModel != "" || meta.Prompt != "" {
		t.Errorf("TurnMeta read a rejected rollout: %+v, %v", meta, err)
	}
	if reply, err := a.AgentReply(ev); err != nil || reply != "" {
		t.Errorf("AgentReply read a rejected rollout: %q, %v", reply, err)
	}
}

func TestARolloutUnderCodexHomeIsRead(t *testing.T) {
	home := t.TempDir()
	t.Setenv("CODEX_HOME", home)
	inside := filepath.Join(home, "sessions", "2026", "10", "29", "rollout.jsonl")
	copyRollout(t, inside)

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
		t.Fatalf("a rollout under CODEX_HOME/sessions was dropped: %q", ev.TranscriptPath)
	}
	if meta, err := a.TurnMeta(ev); err != nil || meta.AgentModel == "" {
		t.Errorf("TurnMeta = %+v, %v; want the rollout's model", meta, err)
	}
}
