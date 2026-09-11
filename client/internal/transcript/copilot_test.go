package transcript

import (
	"os"
	"path/filepath"
	"testing"
)

// A trimmed but structurally-faithful chatSessions journal. Per request VS Code writes a
// "details" object (the UI label "Raptor mini • N credits") and a separate object with
// tokens + the internal "resolvedModel" codename. Two requests; the parser must report
// the LAST turn's DISPLAY name ("Raptor mini") and its tokens — NOT the "oswe-vscode-prime"
// codename in resolvedModel.
const copilotChatSession = `{"kind":0,"v":{"requests":[` +
	`{"result":{"details":"Claude Haiku 4.5 • 0.3 credits","metadata":{"resolvedModel":"claude-haiku-4-5-20251001","promptTokens":30002,"outputTokens":184}}},` +
	`{"result":{"details":"Raptor mini • 0.5 credits","metadata":{"resolvedModel":"oswe-vscode-prime","promptTokens":31759,"outputTokens":236}}}` +
	`]}}
`

// writeSession lays out <wsHash>/chatSessions/<sid>.jsonl + the sibling transcript path
// so both the transcript-derived and glob lookups can be exercised.
func writeSession(t *testing.T, sid, body string) (chatPath, transcriptPath string) {
	t.Helper()
	ws := filepath.Join(t.TempDir(), "wshash")
	cs := filepath.Join(ws, "chatSessions")
	tr := filepath.Join(ws, "GitHub.copilot-chat", "transcripts")
	for _, d := range []string{cs, tr} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	chatPath = filepath.Join(cs, sid+".jsonl")
	if err := os.WriteFile(chatPath, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	transcriptPath = filepath.Join(tr, sid+".jsonl")
	if err := os.WriteFile(transcriptPath, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return chatPath, transcriptPath
}

func TestParseCopilotTurnMeta_ModelAndTokensFromSibling(t *testing.T) {
	sid := "069ee64d-ab05-4004-a754-54137b897c5f"
	_, tp := writeSession(t, sid, copilotChatSession)
	m, err := ParseCopilotTurnMeta(sid, tp)
	if err != nil {
		t.Fatal(err)
	}
	if m.AgentModel != "Raptor mini" {
		t.Errorf("AgentModel=%q, want the LATEST turn's DISPLAY name %q (not the resolvedModel codename)", m.AgentModel, "Raptor mini")
	}
	if m.InputTokens != 31759 || m.OutputTokens != 236 {
		t.Errorf("tokens=%d/%d, want 31759/236", m.InputTokens, m.OutputTokens)
	}
}

func TestParseCopilotTurnMeta_MissingIsZeroNotError(t *testing.T) {
	// No such session anywhere → best-effort zero meta, nil error (review must not break).
	m, err := ParseCopilotTurnMeta("does-not-exist-uuid", "/nope/GitHub.copilot-chat/transcripts/x.jsonl")
	if err != nil || m.AgentModel != "" || m.InputTokens != 0 {
		t.Fatalf("want zero meta + nil err, got %+v err=%v", m, err)
	}
}
