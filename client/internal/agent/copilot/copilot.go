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
// Changed-file discovery is the git-baseline path ONLY (engine → vcs): outside a git
// repo the review is skipped (fail open). Copilot's transcript format is undocumented,
// so what we read out of it is only what has been confirmed by inspection — the prose
// (see AgentReply), not the tool calls a changed-file fallback would need. Turn
// analytics are partial for the same reason (see TurnMeta). Deliberate gaps, not
// oversights, and narrowing rather than fixed: LEO-156 closed the agent reply.
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
	// environment is the runtime inferred from the stdin dialect at ParseEvent (see
	// Environment). Carried on the struct for the same reason sessionID is: it is
	// only knowable while the payload is in hand, and the seam hands the later calls
	// an Event, not the raw bytes.
	environment string
	// rewakeAt is when we delivered the block this Stop is the guard turn for, read
	// off the guard marker at ParseEvent. It is AgentReply's boundary (see there):
	// Copilot records no injected message, so the delivery time is the only thing
	// separating the agent's reply from its own pre-block commentary. Zero when this
	// Stop follows no block of ours, or when the marker predates the stamp.
	//
	// On the struct for a THIRD reason beyond sessionID's: ParseEvent CONSUMES the
	// marker on the CLI dialect, so by the time AgentReply runs the file may be gone.
	rewakeAt time.Time
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
	// ToolName/ToolInput are the PreToolUse half, in both dialects. Copilot's
	// PreToolUse payload is UNVERIFIED — neither runtime documents one — so both
	// casings are read and an unrecognised shape simply yields no path.
	//
	// ⚠️ AND BOTH COPILOT HOOK MANIFESTS DELIBERATELY CARRY NO `matcher`, unlike
	// Claude's and Codex's. A matcher filters on the agent's own TOOL NAMES, and
	// Copilot's are not Claude's: "Write|Edit|MultiEdit|NotebookEdit" is a list of
	// tools Copilot does not have, so it would match nothing and the hook would never
	// fire — silently, which is precisely the failure mode the repo discovery exists to
	// remove. Unmatched is the cheap direction: a tool naming no file yields "" and
	// RecordEditedRepo returns immediately, and a tool that merely READS a file costs
	// one baseline for a repository we would otherwise not have seen, which can only
	// widen what a later Bash write is measured against. Narrow the manifest only once
	// the real tool names are verified against a live runtime.
	ToolName       string         `json:"tool_name"`
	ToolNameCamel  string         `json:"toolName"`
	ToolInput      map[string]any `json:"tool_input"`
	ToolInputCamel map[string]any `json:"toolInput"`
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
	a.environment = dialectEnvironment(p)
	ev := agent.Event{
		Name:                 normalizeEventName(p),
		StopHookActive:       p.StopHookActive,
		TranscriptPath:       firstNonEmpty(p.TranscriptPath, p.TranscriptPathCamel),
		SessionID:            a.sessionID,
		Cwd:                  p.Cwd,
		LastAssistantMessage: p.LastAssistantMessage, // undocumented for Copilot; kept in case it appears
		EditPaths:            agent.EditPathsFromToolInput(p.toolInput()),
	}
	if ev.IsUserPromptSubmit() {
		clearGuard(a.sessionID)
		return ev, nil
	}
	// ⚠️ RETURN BEFORE THE GUARD BLOCK BELOW IS REACHED. Copilot self-manages its loop
	// guard (the CLI documents no stop_hook_active), and consumeGuard is DESTRUCTIVE —
	// so letting a PreToolUse fall through would spend the marker armed by the block we
	// just delivered, and the post-re-wake Stop would then re-review and re-block. A
	// tool call is not a Stop and must not be read as one.
	if ev.IsPreToolUse() {
		return ev, nil
	}
	// Stop: read the marker's block-delivery stamp BEFORE anything can remove it, and
	// unconditionally — the consume below is short-circuited by a native
	// stop_hook_active, so a VS Code turn would otherwise never look at the file at all
	// and AgentReply would have no boundary on the one runtime that is verified.
	if at, ok := guardStamp(a.sessionID); ok {
		a.rewakeAt = at
	}
	// honor a native stop_hook_active (VS Code documents one); otherwise the
	// self-managed marker from the block we delivered last invocation IS the guard.
	if !ev.StopHookActive && consumeGuard(a.sessionID) {
		ev.StopHookActive = true
	}
	return ev, nil
}

// Environment reports which of Copilot's two runtimes this turn ran in, as inferred
// from the stdin dialect at ParseEvent.
//
// Copilot exports no entrypoint variable, but it does not need to: the two runtimes
// speak DIFFERENT dialects of the same hook, so the payload that reaches us already
// names its own sender. That makes this the one adapter whose signal is structural
// rather than a value — hence an empty Raw, since quoting "the keys were snake_case"
// as if it were a vendor string would misrepresent where it came from.
//
// Before ParseEvent (or after one that saw neither dialect) this is EnvUnknown, not
// a default runtime: the CLI path is the unverified one, so guessing it is exactly
// where a wrong answer would go unnoticed.
func (a *Adapter) Environment(agent.Event) agent.Environment {
	if a.environment == "" {
		return agent.Environment{Name: wire.EnvUnknown}
	}
	return agent.Environment{Name: a.environment}
}

// dialectEnvironment infers the runtime from which spelling the payload used.
// snake_case is VS Code agent mode (the Claude-compatible form, which also carries
// stop_hook_active); camelCase is the Copilot CLI's native form. Checked in that
// order to match the per-field precedence in hookPayload, so a payload carrying both
// resolves the same way everywhere rather than by whichever check ran first.
func dialectEnvironment(p hookPayload) string {
	switch {
	case p.SessionID != "" || p.TranscriptPath != "" || p.HookEventName != "" || p.StopReason != "":
		return wire.EnvCopilotVSCode
	case p.SessionIDCamel != "" || p.TranscriptPathCamel != "" || p.HookEventNameCamel != "" || p.StopReasonCamel != "":
		return wire.EnvCopilotCLI
	default:
		return wire.EnvUnknown
	}
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
	// ⚠️ EVERY SPELLING MUST LAND ON THE CONSTANT. An unrecognised name reaches the
	// `default` below, which hands it to the review path — so a missed spelling here is
	// not a lost baseline, it is a selector, a judge and a possible BLOCK on every tool
	// call the agent makes. Copilot documents no PreToolUse event at all, so all three
	// plausible spellings are accepted rather than guessed between.
	case "preToolUse", "pre_tool_use", agent.EventPreToolUse:
		return agent.EventPreToolUse
	case "":
		// No event-name field (the CLI's camelCase payload documents none), so infer.
		// Tool BEFORE prompt/stop: a PreToolUse payload names a tool, and reading it as
		// a Stop would review mid-turn.
		if p.toolInput() != nil || firstNonEmpty(p.ToolName, p.ToolNameCamel) != "" {
			return agent.EventPreToolUse
		}
		if firstNonEmpty(p.StopReason, p.StopReasonCamel) == "" && p.Prompt != "" {
			return agent.EventUserPromptSubmit
		}
		return "Stop"
	default:
		return name // agentStop, Stop, … — all route to the review path
	}
}

// toolInput returns whichever dialect carried the tool arguments.
func (p hookPayload) toolInput() map[string]any {
	if p.ToolInput != nil {
		return p.ToolInput
	}
	return p.ToolInputCamel
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

// AgentReply returns the agent's prose after our re-wake, read out of the transcript
// the hook handed us — transcript.ParseCopilotAgentReply, anchored on when we
// delivered the block (a.rewakeAt, off the guard marker).
//
// ⚠️ THE EARLIER "NOT RECOVERED FOR COPILOT" BEHAVIOUR NAMED THE WRONG FILE, which is
// why this looked impossible. The write-order race is real but belongs to
// chatSessions, where the MODEL lives (see TurnMeta); the transcript is an
// append-order journal whose assistant.message records carry the prose and land as
// they happen. So the reply was on disk all along and simply unread, which surfaced as
// every Copilot outcome recording an agent that never replied — on a declined fix, the
// one field that says why the flaw is still open.
//
// Best-effort per the seam contract: no marker (so no boundary), an unreadable
// transcript or a format change all yield "" and the engine falls back to
// last_assistant_message, which Copilot does not populate — i.e. exactly the previous
// behaviour, never worse.
func (a *Adapter) AgentReply(ev agent.Event) (string, error) {
	return transcript.ParseCopilotAgentReply(ev.TranscriptPath, a.rewakeAt)
}

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

// armGuard records that a block was just delivered for this session, stamping WHEN.
// Best-effort.
//
// The content is an RFC3339 delivery time rather than the old "1" because AgentReply
// needs that instant as its boundary and nothing else in the system knows it. The
// guard's own semantics are unchanged and deliberately do not read it: PRESENCE is the
// guard (see consumeGuard), so a marker left by an older build still stops the loop and
// only costs that turn its reply.
func armGuard(sessionID string) {
	cleanupStale()
	if sessionID == "" {
		return
	}
	p := guardPath(sessionID)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return
	}
	_ = os.WriteFile(p, []byte(time.Now().UTC().Format(time.RFC3339Nano)), 0o600)
}

// guardStamp reports when the block for this session was delivered, from the marker's
// contents. It does NOT remove the marker — the loop guard owns that lifecycle, and
// reading the stamp must not change which turn gets guarded.
//
// A missing marker, an unreadable one, or contents that are not a timestamp (an older
// build's "1") all report false, which leaves AgentReply with no boundary and so no
// reply. That is the direction to fail in: a wrong boundary would ship the agent's
// pre-block commentary as its answer to a finding it had not yet seen.
func guardStamp(sessionID string) (time.Time, bool) {
	if sessionID == "" {
		return time.Time{}, false
	}
	b, err := os.ReadFile(guardPath(sessionID)) //nolint:gosec // our own scratch path
	if err != nil {
		return time.Time{}, false
	}
	at, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(string(b)))
	if err != nil {
		return time.Time{}, false
	}
	return at, true
}

// consumeGuard reports whether a marker exists for this session, removing it
// (consume-once, like outcome.Take). An empty sessionID or a stat error reads as
// "no marker".
//
// PRESENCE ONLY — it never reads the contents. armGuard now stamps a delivery time in
// there for AgentReply, and the guard must not start depending on that parsing: an
// unstamped or corrupt marker has to keep stopping the loop, because a missed guard
// blocks the agent forever while a missing stamp costs one reply.
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
