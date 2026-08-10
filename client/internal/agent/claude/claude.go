// Package claude is the Claude Code adapter.
//
// Stop-hook stdin carries session_id, transcript_path, cwd, hook_event_name,
// stop_hook_active, …; ParseEvent normalizes them (SessionID/Cwd drive the git
// baseline).
//
// Changed-file discovery is PRIMARILY the git-baseline path (engine → vcs;
// agent-agnostic, sees Bash writes, full-file context). ChangedFiles below is the
// FALLBACK used only when there is no git baseline (not a git repo / no commits):
// it parses the transcript JSONL (Write/Edit/MultiEdit/NotebookEdit tool_use
// blocks) since the last genuine user message — the files the agent edited via its
// own tools this turn. That fallback retains the old Bash gap (files mutated via
// Bash aren't tool_use blocks → skipped); the git path does not.
//
// Re-wake is {"decision":"block","reason":…}, injected as a user message
// prefixed "Stop hook feedback:".
package claude

import (
	"encoding/json"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/agent"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/review"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

// Adapter implements agent.Agent for Claude Code.
type Adapter struct{}

// New returns a Claude adapter.
func New() *Adapter { return &Adapter{} }

// Name identifies the adapter.
func (*Adapter) Name() string { return "claude" }

// hookPayload is the Claude hook stdin JSON (verified fields). The same shape
// covers both the UserPromptSubmit and Stop events we register for; cwd +
// session_id are present on both.
type hookPayload struct {
	SessionID            string `json:"session_id"`
	TranscriptPath       string `json:"transcript_path"`
	HookEventName        string `json:"hook_event_name"`
	StopHookActive       bool   `json:"stop_hook_active"`
	Cwd                  string `json:"cwd"`
	LastAssistantMessage string `json:"last_assistant_message"`
}

// ParseEvent decodes Claude's hook stdin (UserPromptSubmit or Stop).
func (*Adapter) ParseEvent(stdin []byte) (agent.Event, error) {
	var p hookPayload
	if err := json.Unmarshal(stdin, &p); err != nil {
		return agent.Event{}, err
	}
	return agent.Event{
		Name:                 p.HookEventName,
		StopHookActive:       p.StopHookActive,
		TranscriptPath:       p.TranscriptPath,
		SessionID:            p.SessionID,
		Cwd:                  p.Cwd,
		LastAssistantMessage: p.LastAssistantMessage,
	}, nil
}

// ChangedFiles returns ONLY the files the agent edited via its file tools this
// turn (from the transcript). See the package doc for the Bash-write limitation.
func (*Adapter) ChangedFiles(ev agent.Event) ([]transcript.Change, error) {
	if ev.TranscriptPath == "" {
		return nil, nil
	}
	return transcript.ParseChanges(ev.TranscriptPath)
}

// AgentReply returns the agent's prose after our re-wake, from the transcript —
// the reply the Stop stdin's last_assistant_message truncates to its final message.
// Best-effort: no transcript path or no re-wake in it yields "", and the engine
// falls back.
func (*Adapter) AgentReply(ev agent.Event) (string, error) {
	if ev.TranscriptPath == "" {
		return "", nil
	}
	return transcript.ParseAgentReply(ev.TranscriptPath)
}

// TurnMeta extracts the coding agent's own turn activity (model, prompt, token
// usage, wall-clock) from the Claude transcript JSONL. Best-effort: no transcript
// path → zero meta; a read/parse error surfaces for the engine to log and ignore.
func (*Adapter) TurnMeta(ev agent.Event) (agent.TurnMeta, error) {
	if ev.TranscriptPath == "" {
		return agent.TurnMeta{}, nil
	}
	m, err := transcript.ParseTurnMeta(ev.TranscriptPath)
	if err != nil {
		return agent.TurnMeta{}, err
	}
	return agent.TurnMeta{
		AgentModel:          m.AgentModel,
		Prompt:              m.Prompt,
		InputTokens:         m.InputTokens,
		CacheCreationTokens: m.CacheCreationTokens,
		CacheReadTokens:     m.CacheReadTokens,
		OutputTokens:        m.OutputTokens,
		DurationMs:          m.DurationMs,
		Speed:               m.Speed,
		PromptTime:          m.PromptTime, // set → engine derives duration from the wall-clock end
	}, nil
}

// DeliverReview wraps the prompt as Claude's in-turn re-wake, carrying the banner
// on BOTH the terminal systemMessage and the Stop context channel.
//
// The second channel is why the desktop app / claude.ai see a review at all: a
// systemMessage is not forwarded over stream-json, so on those surfaces a review
// that fires and force-fixes is otherwise indistinguishable from the agent just
// editing code (verified — see review.RewakeWithContextJSON). Claude ONLY: the
// Codex and Copilot adapters keep the plain re-wake, since neither runtime is
// verified for a Stop-path additionalContext and both have tests asserting they
// emit no hookSpecificOutput.
func (*Adapter) DeliverReview(prompt, banner string, fileCount int, findings []wire.Finding) ([]byte, error) {
	ctx := review.ReviewContextMessage(fileCount, findings, review.ForceFixedCount(findings))
	return review.RewakeWithContextJSON(prompt, banner, ctx)
}

// DeliverNotice wraps a non-blocking developer notice as Claude's Stop-hook
// output: a systemMessage with no decision, so it's shown but the turn yields.
func (*Adapter) DeliverNotice(message string) ([]byte, error) {
	return review.NoticeJSON(message)
}

// DeliverPromptNotice carries the notice both as a terminal systemMessage and as
// injected turn context, so it also reaches the desktop app / web UI (which never
// receive a systemMessage — see review.PromptNoticeJSON).
func (*Adapter) DeliverPromptNotice(message, context string) ([]byte, error) {
	return review.PromptNoticeJSON(message, context)
}
