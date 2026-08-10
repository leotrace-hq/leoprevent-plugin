// Package codex is the OpenAI Codex CLI adapter.
//
// Codex's Stop hook is near-identical to Claude's: stdin carries session_id,
// transcript_path, cwd, hook_event_name, stop_hook_active, last_assistant_message
// (plus turn_id, model), and the re-wake contract is the SAME
// {"decision":"block","reason":…} — so DeliverReview reuses the shared helper.
//
// Changed-file discovery is PRIMARILY the git-baseline path (engine → vcs;
// agent-agnostic). ChangedFiles below is the FALLBACK (no git baseline): it parses
// the rollout transcript (apply_patch custom_tool_call entries) — a different
// on-disk format from Claude's tool_use blocks, same intent. See
// transcript.ParseCodexChanges. Codex's docs call the rollout format "not a stable
// interface", so the fallback parser is defensive and the hook fails open.
//
// FALLBACK LIMITATION (identical to Claude's fallback): files mutated via the
// exec_command shell tool are not apply_patch calls and skip review. The git path
// has no such gap; see plan-later §C.
package codex

import (
	"encoding/json"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/agent"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/review"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

// Adapter implements agent.Agent for the Codex CLI.
type Adapter struct{}

// New returns a Codex adapter.
func New() *Adapter { return &Adapter{} }

// Name identifies the adapter.
func (*Adapter) Name() string { return "codex" }

// hookPayload is the Codex hook stdin JSON. The fields we use match Claude's;
// Codex extras (turn_id/model) are simply not declared.
type hookPayload struct {
	SessionID            string `json:"session_id"`
	TranscriptPath       string `json:"transcript_path"`
	HookEventName        string `json:"hook_event_name"`
	StopHookActive       bool   `json:"stop_hook_active"`
	Cwd                  string `json:"cwd"`
	LastAssistantMessage string `json:"last_assistant_message"`
}

// ParseEvent decodes Codex's hook stdin (UserPromptSubmit or Stop). The Stop hook +
// git-baseline path is VERIFIED LIVE (Codex CLI 0.140.0, 2026-06-18, over a PTY: the
// Stop hook fired, the baseline was captured, change detection found the edit, and the
// server reviewed it). If a future CLI ever stops firing
// the baseline hook, no git baseline is recorded and ChangedFiles falls back to the
// rollout parser — same Bash-gap behaviour as before, no regression.
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

// ChangedFiles returns ONLY the files the agent edited via apply_patch this
// turn (from the rollout transcript). See the package doc for the Bash
// (exec_command) limitation.
func (*Adapter) ChangedFiles(ev agent.Event) ([]transcript.Change, error) {
	if ev.TranscriptPath == "" {
		return nil, nil
	}
	return transcript.ParseCodexChanges(ev.TranscriptPath)
}

// AgentReply returns the agent's prose after our re-wake, from the rollout — the
// reply the Stop stdin's last_assistant_message truncates to its final message.
// Mirrors the Claude adapter; the boundary marker differs because Codex surfaces a
// block as a plain user message rather than a "Stop hook feedback:" injection.
// Best-effort: no rollout path, or a rollout whose format has shifted, yields "".
func (*Adapter) AgentReply(ev agent.Event) (string, error) {
	if ev.TranscriptPath == "" {
		return "", nil
	}
	return transcript.ParseCodexAgentReply(ev.TranscriptPath)
}

// TurnMeta returns the coding agent's turn activity (model, prompt, tokens,
// wall-clock) parsed from the Codex rollout the Stop event points at. Best-effort,
// like the rollout-based ChangedFiles fallback: a parse error or an unset transcript
// path yields zero meta (review is unaffected). Empirically Codex's rollout carries
// clean, structured `token_count` records + a `turn_context` model, so we mine them;
// if the format shifts the unmarshal tolerates it (zero meta, never an error path).
func (*Adapter) TurnMeta(ev agent.Event) (agent.TurnMeta, error) {
	if ev.TranscriptPath == "" {
		return agent.TurnMeta{}, nil
	}
	m, err := transcript.ParseCodexTurnMeta(ev.TranscriptPath)
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
		PromptTime:          m.PromptTime, // zero (settled rollout) → engine keeps DurationMs above
	}, nil
}

// DeliverReview wraps the prompt as Codex's in-turn re-wake (same shape as
// Claude's: {"decision":"block","reason":…}). fileCount is unused here: Codex is
// not verified for a Stop-path additionalContext, so it emits no context channel
// (TestDeliverReviewOmitsHookSpecificOutput pins that).
func (*Adapter) DeliverReview(prompt, banner string, _ int, _ []wire.Finding) ([]byte, error) {
	return review.RewakeJSON(prompt, banner)
}

// DeliverNotice wraps a non-blocking developer notice as Codex's Stop-hook output
// (same shape as Claude's: systemMessage only, no decision). NOTE: Codex's Stop
// contract matches Claude's, but whether its TUI renders a bare systemMessage on a
// non-blocking stop is unverified — fail-open is unaffected either way (the turn
// still yields; at worst the notice isn't shown).
func (*Adapter) DeliverNotice(message string) ([]byte, error) {
	return review.NoticeJSON(message)
}

// DeliverPromptNotice keeps Codex on the PREVIOUS systemMessage-only output: the
// injected-context half (which is what reaches non-terminal surfaces) is verified
// on Claude Code ONLY, and Codex's handling of an additionalContext hookSpecificOutput
// is untested. Deliberately identical to DeliverNotice — context is accepted and
// ignored so the seam stays uniform. Switch to review.PromptNoticeJSON once a live
// Codex run confirms it.
func (*Adapter) DeliverPromptNotice(message, _ string) ([]byte, error) {
	return review.NoticeJSON(message)
}
