package cursor

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/agent"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/scratch"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

type Adapter struct {
	sessionID string
	model     string
}

type continuation struct {
	Digest string    `json:"digest"`
	At     time.Time `json:"at"`
}

func New() *Adapter           { return &Adapter{} }
func (*Adapter) Name() string { return "cursor" }
func (*Adapter) Environment(
	agent.Event,
) agent.Environment {
	return agent.Environment{Name: wire.EnvCursorIDE}
}

func (a *Adapter) ParseEvent(
	stdin []byte,
) (agent.Event, error) {
	var p struct {
		Name      string         `json:"hook_event_name"`
		SessionID string         `json:"conversation_id"`
		Roots     []string       `json:"workspace_roots"`
		Cwd       string         `json:"cwd"`
		Prompt    string         `json:"prompt"`
		Model     string         `json:"model"`
		ModelID   string         `json:"model_id"`
		Status    string         `json:"status"`
		Input     map[string]any `json:"tool_input"`
	}
	if err := json.Unmarshal(stdin, &p); err != nil {
		return agent.Event{}, err
	}
	a.sessionID, a.model = p.SessionID, p.ModelID
	if a.model == "" {
		a.model = p.Model
	}
	if p.Cwd == "" && len(p.Roots) > 0 {
		p.Cwd = p.Roots[0]
	}
	ev := agent.Event{SessionID: p.SessionID, Cwd: nativePath(p.Cwd)}
	switch p.Name {
	case "beforeSubmitPrompt":
		ev.Name = agent.EventUserPromptSubmit
	case "preToolUse":
		ev.Name = agent.EventPreToolUse
		ev.EditPaths = agent.EditPathsFromToolInput(p.Input)
	case "stop":
		if p.Status != "completed" {
			return agent.Event{}, fmt.Errorf("Cursor stop status %q is not completed", p.Status)
		}
		ev.Name = "Stop"
	default:
		return agent.Event{}, fmt.Errorf("unsupported Cursor event %q", p.Name)
	}
	state, ok := readContinuation(p.SessionID)
	if ev.IsUserPromptSubmit() {
		ev.ReviewContinuation = ok && state.Digest == digest(p.Prompt)
		if !ev.ReviewContinuation {
			_ = os.Remove(continuationPath(p.SessionID))
		}
	} else if ev.Name == "Stop" {
		ev.StopHookActive = ok
		_ = os.Remove(continuationPath(p.SessionID))
	}
	return ev, nil
}

func (*Adapter) ChangedFiles(
	agent.Event,
) ([]transcript.Change, error) {
	return nil, nil
}
func (a *Adapter) TurnMeta(
	agent.Event,
) (agent.TurnMeta, error) {
	return agent.TurnMeta{AgentModel: a.model}, nil
}
func (*Adapter) AgentReply(
	agent.Event,
) (string, error) {
	return "", nil
}
func (a *Adapter) DeliverReview(
	prompt, banner string,
	_ int,
	_ []wire.Finding,
	_ string,
) ([]byte, error) {
	followup := strings.TrimSpace(banner + "\n\n" + prompt)
	if a.sessionID == "" {
		return nil, fmt.Errorf("Cursor conversation_id is missing")
	}
	path := continuationPath(a.sessionID)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	data, err := json.Marshal(continuation{Digest: digest(followup), At: time.Now()})
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return nil, err
	}
	return json.Marshal(map[string]string{"followup_message": followup})
}
func (*Adapter) DeliverNotice(
	message string,
) ([]byte, error) {
	slog.Info("Cursor Stop notice recorded in plugin log", "message", message)
	return []byte("{}"), nil
}
func (*Adapter) DeliverPromptNotice(
	message, _ string,
) ([]byte, error) {
	return json.Marshal(map[string]any{"continue": true, "user_message": message})
}

// nativePath undoes the URI-style form Cursor on Windows gives workspace_roots
// ("/e:/src/app"): git cannot open it, so every Stop reported "not a git repo".
func nativePath(
	path string,
) string {
	if len(path) >= 3 && path[0] == '/' && path[2] == ':' && (len(path) == 3 || path[3] == '/') {
		if c := path[1] | 0x20; c >= 'a' && c <= 'z' {
			return filepath.Clean(path[1:] + "/")
		}
	}
	return path
}

func digest(
	text string,
) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(text)))
}
func continuationPath(
	session string,
) string {
	return filepath.Join(scratch.Dir("cursor-guard"), digest(session)+".json")
}
func readContinuation(
	session string,
) (continuation, bool) {
	var state continuation
	if session == "" {
		return state, false
	}
	path := continuationPath(session)
	data, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(data, &state) != nil {
		return state, false
	}
	if state.At.IsZero() || time.Since(state.At) > 6*time.Hour {
		_ = os.Remove(path)
		return state, false
	}
	return state, true
}
