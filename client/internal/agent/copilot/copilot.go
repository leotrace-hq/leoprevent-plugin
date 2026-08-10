// Package copilot is the GitHub Copilot adapter (Copilot CLI + VS Code agent mode).
//
// VS Code agent mode is VERIFIED LIVE end-to-end (2026-07-15/16, VS Code 1.126).
// The Copilot CLI path and Windows remain
// UNVERIFIED. The adapter is deliberately defensive about every documented-but-
// unconfirmed detail; on any shape mismatch it fails open.
//
// Copilot is ONE adapter but TWO hook runtimes with diverging dialects:
//
//   - Copilot CLI (GA): event `agentStop`, stdin camelCase ({sessionId, cwd,
//     transcriptPath, stopReason}), re-wake via top-level
//     {"decision":"block","reason":…} — the Claude contract.
//   - VS Code agent mode (Preview): event `Stop`, stdin snake_case
//     (hook_event_name/session_id/…, incl. stop_hook_active), re-wake via
//     {"hookSpecificOutput":{"hookEventName":"Stop","decision":"block",…}}.
//
// ParseEvent accepts BOTH spellings; DeliverReview emits BOTH output shapes in
// one JSON object (each runtime reads its own field and tolerates the other).
//
// LOOP GUARD: the CLI stdin documents NO stop_hook_active, so the per-turn
// guard that stops an infinite block→re-wake→block loop cannot rely on the
// payload alone. The adapter self-manages one: DeliverReview drops a per-session
// marker file (the vcs/outcome/notify scratch pattern), and the NEXT Stop parse
// consumes it as StopHookActive. A native stop_hook_active (VS Code) is honored
// when present. Fail-open bias: a spuriously-consumed marker costs one missed
// review; a missed guard would loop the agent forever — so the marker always
// errs toward "this Stop is the guard turn".
//
// Changed-file discovery is the git-baseline path ONLY (engine → vcs). Copilot's
// transcript format is undocumented, so there is no transcript fallback and no
// TurnMeta yet: outside a git repo the review is skipped (fail open), and turn
// analytics are zero until the format is reverse-engineered. Both are deliberate
// gaps, not oversights.
package copilot

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/agent"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/review"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

// Adapter implements agent.Agent for GitHub Copilot. It carries the session ID
// from ParseEvent to DeliverReview (same process, one hook invocation) so the
// self-managed loop-guard marker can be keyed per session.
type Adapter struct {
	sessionID string
}

// New returns a Copilot adapter.
func New() *Adapter { return &Adapter{} }

// Name identifies the adapter.
func (*Adapter) Name() string { return "copilot" }

// hookPayload declares BOTH documented stdin spellings: snake_case (VS Code /
// Claude-compat form) and camelCase (Copilot CLI native form). Per field the
// snake_case value wins when both are set (arbitrary but deterministic).
type hookPayload struct {
	SessionID            string `json:"session_id"`
	SessionIDCamel       string `json:"sessionId"`
	TranscriptPath       string `json:"transcript_path"`
	TranscriptPathCamel  string `json:"transcriptPath"`
	HookEventName        string `json:"hook_event_name"`
	HookEventNameCamel   string `json:"hookEventName"`
	StopHookActive       bool   `json:"stop_hook_active"`
	Cwd                  string `json:"cwd"`
	LastAssistantMessage string `json:"last_assistant_message"`
	// StopReason/Prompt are only read to INFER the event when no event-name field
	// is present (the CLI's camelCase payload documents none): a stop_reason marks
	// a Stop, a prompt marks a UserPromptSubmit.
	StopReason      string `json:"stop_reason"`
	StopReasonCamel string `json:"stopReason"`
	Prompt          string `json:"prompt"`
}

// ParseEvent decodes Copilot's hook stdin (either dialect) into the normalized
// Event. NB it has one deliberate side effect: on a Stop it consumes the
// self-managed loop-guard marker (see the package doc), and on a UserPromptSubmit
// it clears any stale marker (a new turn start means the previous block's guard
// can no longer apply — clearing fails toward reviewing).
func (a *Adapter) ParseEvent(stdin []byte) (agent.Event, error) {
	var p hookPayload
	if err := json.Unmarshal(stdin, &p); err != nil {
		return agent.Event{}, err
	}
	a.sessionID = firstNonEmpty(p.SessionID, p.SessionIDCamel)
	ev := agent.Event{
		Name:                 normalizeEventName(p),
		StopHookActive:       p.StopHookActive,
		TranscriptPath:       firstNonEmpty(p.TranscriptPath, p.TranscriptPathCamel),
		SessionID:            a.sessionID,
		Cwd:                  p.Cwd,
		LastAssistantMessage: p.LastAssistantMessage, // undocumented for Copilot; kept in case it appears
	}
	if ev.IsUserPromptSubmit() {
		clearGuard(a.sessionID)
		return ev, nil
	}
	// Stop: honor a native stop_hook_active (VS Code documents one); otherwise the
	// self-managed marker from the block we delivered last invocation IS the guard.
	if !ev.StopHookActive && consumeGuard(a.sessionID) {
		ev.StopHookActive = true
	}
	return ev, nil
}

// normalizeEventName maps Copilot's event names onto the seam's contract:
// UserPromptSubmit routes to baseline capture, anything else to review. The CLI's
// camelCase payload documents no event-name field at all, so when both spellings
// are absent the event is INFERRED: a stop_reason ⇒ Stop; a prompt body ⇒
// UserPromptSubmit; neither ⇒ Stop (reviewing a turn start is a no-op — the
// baseline usually doesn't exist yet — while skipping a real Stop would be a
// silent unreviewed turn, so ambiguity fails toward review).
func normalizeEventName(p hookPayload) string {
	name := firstNonEmpty(p.HookEventName, p.HookEventNameCamel)
	switch name {
	case "userPromptSubmitted", agent.EventUserPromptSubmit:
		return agent.EventUserPromptSubmit
	case "":
		if firstNonEmpty(p.StopReason, p.StopReasonCamel) == "" && p.Prompt != "" {
			return agent.EventUserPromptSubmit
		}
		return "Stop"
	default:
		return name // agentStop, Stop, … — all route to the review path
	}
}

// ChangedFiles has NO transcript fallback: Copilot's transcript format is
// undocumented, so changed-file discovery is the git-baseline path only. Outside
// a git repo the engine finds no changes and the turn goes unreviewed (fail
// open, with the gitless warning path unavailable — deliberate until the format
// is reverse-engineered).
func (*Adapter) ChangedFiles(agent.Event) ([]transcript.Change, error) {
	return nil, nil
}

// TurnMeta recovers the coding agent's model + token usage. Copilot's transcript
// doesn't carry the model, but VS Code persists it (plus tokens) in a SIBLING
// chatSessions file keyed by session id — transcript.ParseCopilotTurnMeta reads it
// (see there for the layout + the fragility caveat). Best-effort per the seam
// contract: a miss yields zero meta, never an error that touches review. No
// PromptTime (Copilot's chat session is settled state, not a mid-flush transcript),
// so the engine keeps whatever DurationMs we have (currently none — wall-clock isn't
// recovered from Copilot yet).
func (*Adapter) TurnMeta(ev agent.Event) (agent.TurnMeta, error) {
	m, err := transcript.ParseCopilotTurnMeta(ev.SessionID, ev.TranscriptPath)
	if err != nil {
		return agent.TurnMeta{}, err
	}
	return agent.TurnMeta{
		AgentModel:   m.AgentModel,
		InputTokens:  m.InputTokens,
		OutputTokens: m.OutputTokens,
	}, nil
}

// AgentReply is NOT recovered for Copilot, so the engine falls back to the Stop
// stdin's last_assistant_message.
//
// Same gap as ChangedFiles and the turn metadata: Copilot's transcript format is
// undocumented and the chat-session file it does write is flushed AFTER the Stop
// hook reads it (see TurnMeta). Returning "" is the honest answer — a reply parsed
// out of a half-written file would be worse than the truncated-but-real fallback.
func (*Adapter) AgentReply(agent.Event) (string, error) { return "", nil }

// rewakeDual is the block output in BOTH dialects at once: the Copilot CLI (GA)
// reads the top-level decision/reason (Claude's contract); VS Code agent mode
// (Preview) reads hookSpecificOutput. Each parser ignores the other's field.
type rewakeDual struct {
	Decision           string             `json:"decision"`
	Reason             string             `json:"reason"`
	SystemMessage      string             `json:"systemMessage,omitempty"`
	HookSpecificOutput hookSpecificOutput `json:"hookSpecificOutput"`
}

type hookSpecificOutput struct {
	HookEventName string `json:"hookEventName"`
	Decision      string `json:"decision"`
	Reason        string `json:"reason"`
}

// DeliverReview wraps the prompt as Copilot's in-turn re-wake (dual-dialect, see
// rewakeDual) and arms the self-managed loop guard for this session so the
// re-wake's own Stop is allowed through instead of blocking forever.
// fileCount is unused: Copilot's hookSpecificOutput carries its re-wake DECISION,
// not a context channel, and the runtime is unverified for additionalContext.
func (a *Adapter) DeliverReview(prompt, banner string, _ int, _ []wire.Finding) ([]byte, error) {
	out, err := json.Marshal(rewakeDual{
		Decision:      "block",
		Reason:        prompt,
		SystemMessage: banner,
		HookSpecificOutput: hookSpecificOutput{
			HookEventName: "Stop",
			Decision:      "block",
			Reason:        prompt,
		},
	})
	if err != nil {
		return nil, err
	}
	armGuard(a.sessionID) // best-effort: a write failure risks a loop only if Copilot also lacks a native guard
	return out, nil
}

// DeliverNotice wraps a non-blocking developer notice as Copilot's Stop-hook
// output (systemMessage only, no decision — the shape VS Code documents as its
// common output; whether either Copilot runtime RENDERS it is unverified, and
// fail-open is unaffected either way: the turn still yields).
func (*Adapter) DeliverNotice(message string) ([]byte, error) {
	return review.NoticeJSON(message)
}

// DeliverPromptNotice keeps Copilot on the PREVIOUS systemMessage-only output. Both
// Copilot runtimes are unverified here, and VS Code agent mode PARSES
// hookSpecificOutput (it is the field it reads for Stop decisions), so emitting a
// differently-shaped one is an untested risk for no confirmed gain. context is
// accepted and ignored; revisit once a live VS Code run confirms the behaviour.
func (*Adapter) DeliverPromptNotice(message, _ string) ([]byte, error) {
	return review.NoticeJSON(message)
}

// --- self-managed loop guard (per-session scratch, vcs/outcome/notify pattern) ---

// guardPath is the per-session marker file. Present ⇒ the next Stop for this
// session is the post-re-wake guard turn.
func guardPath(sessionID string) string {
	return filepath.Join(os.TempDir(), "leoprevent-copilot-guard", sanitize(sessionID))
}

// armGuard records that a block was just delivered for this session. Best-effort.
func armGuard(sessionID string) {
	cleanupStale()
	if sessionID == "" {
		return
	}
	p := guardPath(sessionID)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return
	}
	_ = os.WriteFile(p, []byte("1"), 0o600)
}

// consumeGuard reports whether a marker exists for this session, removing it
// (consume-once, like outcome.Take). An empty sessionID or a stat error reads as
// "no marker".
func consumeGuard(sessionID string) bool {
	cleanupStale()
	if sessionID == "" {
		return false
	}
	p := guardPath(sessionID)
	if _, err := os.Stat(p); err != nil {
		return false
	}
	_ = os.Remove(p)
	return true
}

// clearGuard drops any stale marker at turn start (UserPromptSubmit): a new
// prompt means the previous block's re-wake cycle is over, so a leftover marker
// (e.g. the runtime ignored our block) must not swallow this turn's review.
func clearGuard(sessionID string) {
	if sessionID == "" {
		return
	}
	_ = os.Remove(guardPath(sessionID))
}

// cleanupStale best-effort removes guard markers older than the standard 6h
// scratch TTL (same sweep as vcs/outcome/notify).
func cleanupStale() {
	dir := filepath.Join(os.TempDir(), "leoprevent-copilot-guard")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-6 * time.Hour)
	for _, e := range entries {
		info, err := e.Info()
		if err == nil && info.ModTime().Before(cutoff) {
			_ = os.Remove(filepath.Join(dir, e.Name()))
		}
	}
}

// sanitize maps a session ID to a safe filename (same rule vcs/outcome/notify use).
func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			return r
		default:
			return '_'
		}
	}, s)
}

// firstNonEmpty returns the first non-empty string.
func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
