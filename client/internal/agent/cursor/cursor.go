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
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/review"
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
		Text      string         `json:"text"`
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
	case "afterAgentResponse":
		if _, ok := readContinuation(p.SessionID); ok {
			recordReply(p.SessionID, p.Text)
		}
		ev.Name = agent.EventAgentResponse
		return ev, nil
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
	ev agent.Event,
) (string, error) {
	if ev.SessionID == "" {
		return "", nil
	}
	data, err := os.ReadFile(replyPath(ev.SessionID))
	if os.IsNotExist(err) {
		return "", nil
	}
	return strings.TrimSpace(string(data)), err
}
func (a *Adapter) DeliverReview(
	prompt, banner string,
	_ int,
	_ []wire.Finding,
	_ string,
) ([]byte, error) {
	return a.followUp(strings.TrimSpace(banner + "\n\n" + prompt))
}

// followUp continues the conversation with followup, recording its digest so its prompt is known
// as the continuation and its Stop as the one after it (see ParseEvent).
func (a *Adapter) followUp(followup string) ([]byte, error) {
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
	_ = os.Remove(replyPath(a.sessionID))
	return json.Marshal(map[string]string{"followup_message": followup})
}

// WakeForDependencies continues the conversation with the dependency check's instructions
// (LEO-620): after the review's follow-up, which stays as it is, or on their own.
func (a *Adapter) WakeForDependencies(out []byte, prompt string) ([]byte, error) {
	var hook struct {
		Followup string `json:"followup_message"`
	}
	if len(strings.TrimSpace(string(out))) > 0 {
		if err := json.Unmarshal(out, &hook); err != nil {
			return out, err
		}
	}
	return a.followUp(review.WithDependencies(hook.Followup, prompt))
}

// RelayForDeveloper asks the agent to print a notice meant only for the developer (LEO-662).
// Cursor's stop hook has no field shown to the user, only followup_message, which it submits as
// the next user message straight away. So the notice goes there: on its own, or added to a
// review's or the dependency check's follow-up, whose instructions stay as they are. Its digest
// is recorded, so the relay's own Stop is known as the one after it and never wakes again.
func (a *Adapter) RelayForDeveloper(out []byte, notice, markdown string) ([]byte, string, error) {
	var hook struct {
		Followup string `json:"followup_message"`
	}
	if len(strings.TrimSpace(string(out))) > 0 {
		if err := json.Unmarshal(out, &hook); err != nil {
			return out, "", err
		}
	}
	if strings.TrimSpace(markdown) == "" {
		markdown = notice
	}
	printed := review.DeveloperMarkdown(markdown)
	final, err := a.followUp(review.RelayReason(hook.Followup, printed))
	if err != nil {
		return out, "", err
	}
	return final, printed, nil
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

// replyPath holds the assistant messages Cursor reported since the last follow-up: the
// agent's answer to the review, which its Stop payload does not carry.
func replyPath(
	session string,
) string {
	return filepath.Join(scratch.Dir("cursor-guard"), digest(session)+".reply")
}

// recordReply appends one assistant message, best-effort and bounded, so a long
// conversation cannot grow the file without limit.
func recordReply(
	session, text string,
) {
	text = strings.TrimSpace(text)
	if session == "" || text == "" {
		return
	}
	path := replyPath(session)
	if fi, err := os.Stat(path); err == nil && fi.Size() > maxReplyBytes {
		return
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.WriteString(text + "\n\n")
}

const maxReplyBytes = 64 << 10

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
