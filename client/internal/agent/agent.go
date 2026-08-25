// Package agent defines the seam between leoprevent's agent-agnostic core
// (selector/gate/review) and a specific AI coding agent's hook
// integration.
//
// The interface is intentionally shaped by INTENT, not mechanism, so new
// agents drop in without touching the core:
//
//   - ChangedFiles, not "ParseTranscript" — Claude parses Write/Edit/MultiEdit/
//     NotebookEdit tool_use blocks; Codex parses apply_patch entries; a future
//     Cursor adapter would read afterFileEdit state. Same intent, different format.
//   - DeliverReview, not "EmitDecisionBlock" — Claude and Codex both re-wake
//     in-turn with {"decision":"block","reason":…}; a future Cursor adapter
//     would emit {"followup_message":…} instead (Cursor's stop hook can't block).
//
// Dependencies point inward: adapters import the core, never the reverse.
package agent

import (
	"time"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

// EventUserPromptSubmit is the hook_event_name fired at turn start, when the
// git-baseline snapshot is taken. Anything else is treated as the Stop event.
const EventUserPromptSubmit = "UserPromptSubmit"

// Event is the parsed hook invocation, normalized across agents. The same binary
// serves two hook events — UserPromptSubmit (snapshot the baseline) and Stop
// (review) — distinguished by Name.
type Event struct {
	// Name is the raw hook_event_name; EventUserPromptSubmit routes to baseline
	// capture, anything else to the review loop.
	Name string
	// StopHookActive is the per-turn loop guard: true on the Stop that follows
	// a re-wake (this turn was already reviewed → allow the stop).
	StopHookActive bool
	// TranscriptPath is the session transcript the fallback changed-file parser
	// reads when there is no git baseline.
	TranscriptPath string
	// SessionID keys the per-session git baseline (set at UserPromptSubmit, read
	// at Stop).
	SessionID string
	// Cwd is the agent's working directory — where the git-baseline capture runs.
	Cwd string
	// LastAssistantMessage is the agent's final message of the turn (from the Stop
	// stdin). On the post-re-wake Stop it is the agent's REACTION to leoprevent —
	// its agreement or push-back — captured as the /outcome agent_response.
	LastAssistantMessage string
}

// IsUserPromptSubmit reports whether this invocation is the turn-start baseline
// hook rather than the Stop review hook.
func (e Event) IsUserPromptSubmit() bool { return e.Name == EventUserPromptSubmit }

// TurnMeta is the coding agent's OWN activity for this turn — model, the dev's
// prompt, the agent's token usage, and how long the agent took — extracted from
// the agent's transcript. The shape is agent-specific (Claude's JSONL vs Codex's
// rollout), so extraction lives behind the seam. It is leoprevent-blind: captured
// at the first Stop, BEFORE our re-wake, so it reflects the agent's own cost, not
// ours. Repo + Developer are NOT here — they come from git (agent-independent) and
// are filled by the engine. Best-effort throughout: a parse miss yields zero
// values, never an error that breaks the fail-open review.
type TurnMeta struct {
	AgentModel          string
	Prompt              string
	InputTokens         int
	CacheCreationTokens int
	CacheReadTokens     int
	OutputTokens        int
	DurationMs          int64
	Speed               string    // "fast" when Claude Code Fast mode was on (price tier)
	PromptTime          time.Time // turn-start; when set, the engine derives duration from the
	// Stop hook's wall-clock end instead of DurationMs (the transcript end is read mid-write).
	// Set by Claude, left zero by Codex (settled rollout) — see engine.turnMeta.
}

// Environment is the PRODUCT SURFACE a turn ran in — terminal vs desktop app vs a
// web session — which Agent.Name (the vendor) cannot answer on its own.
//
// Name is the normalized wire.Env* value the dashboards group on; Raw is whatever
// the adapter actually read, verbatim and unmapped, so a surface the compiled-in
// vocabulary predates is still visible in the log. Raw may be empty when the signal
// is structural rather than a value (Copilot infers its surface from the stdin
// dialect — there is no string to quote).
type Environment struct {
	Name string
	Raw  string
}

// Agent abstracts one AI coding agent's Stop-hook integration.
type Agent interface {
	// Name identifies the agent (for stderr logging).
	Name() string

	// Environment reports which product surface this turn ran in (see Environment).
	//
	// It is behind the seam because the signal is per-vendor and structurally
	// different in each: Claude Code exports an entrypoint in the process
	// environment, while Copilot betrays its runtime through the hook dialect it
	// speaks — there is no shared mechanism for the core to reach for.
	//
	// Deliberately NOT folded into TurnMeta, which is transcript-derived and returns
	// its zero value on any parse failure. The environment needs no transcript, so
	// binding the two would blank a fact we reliably know whenever an unrelated
	// parse missed — precisely the silent-degradation this field exists to expose.
	//
	// Total, never failing: an adapter that cannot classify returns wire.EnvUnknown
	// (with Raw set when it saw something it did not recognize), so a caller never
	// has to decide what an error means for analytics.
	Environment(ev Event) Environment

	// ParseEvent decodes the agent's Stop-hook stdin payload.
	ParseEvent(stdin []byte) (Event, error)

	// ChangedFiles returns the files changed in this turn, with their added
	// text. How it discovers them is the adapter's concern.
	ChangedFiles(ev Event) ([]transcript.Change, error)

	// TurnMeta returns the coding agent's own activity for this turn (model,
	// prompt, token usage, wall-clock) parsed from the agent's transcript. Always
	// best-effort: on any failure it returns a zero TurnMeta (+ nil or an error the
	// engine logs and ignores), so analytics metadata never breaks review.
	TurnMeta(ev Event) (TurnMeta, error)

	// AgentReply returns the agent's prose AFTER our re-wake — its reaction to the
	// block — read from the agent's transcript.
	//
	// It exists because Event.LastAssistantMessage is the turn's last assistant
	// MESSAGE, and a turn is not one message: an agent that interleaves tool calls
	// with text emits several, so the reasoning sits in an earlier one and the last
	// is a sign-off. Where the re-wake boundary lives is agent-specific (Claude
	// injects "Stop hook feedback:", Codex surfaces our prompt as a user message,
	// and Copilot logs no injection at all so its adapter anchors on the moment the
	// block was delivered), which is why this is behind the seam rather than in the
	// engine.
	//
	// Best-effort, same contract as TurnMeta: an empty string means "could not
	// read it", and the engine falls back to LastAssistantMessage. An adapter that
	// cannot locate the boundary returns "" rather than guessing at one — reporting
	// the agent's pre-block commentary as its answer to a finding it had not been
	// shown is worse than recording no answer.
	AgentReply(ev Event) (string, error)

	// DeliverReview wraps the review prompt as this agent's re-wake output
	// (written to stdout). banner is the short, neutral console notice shown to
	// the developer (review.Banner) — selection is not detection, so it never
	// claims a violation; the verdict comes from the review subagent.
	//
	// fileCount is the number of reviewed files, passed SEPARATELY rather than
	// parsed back out of banner: the banner may carry a GitlessWarning suffix, and
	// an adapter that also states the notice in the model's turn (Claude) must be
	// able to describe what happened without repeating that diagnostic aside as if
	// it were a fact about the developer's repo.
	//
	// findings are the judged findings behind this re-wake (nil when the tier can't
	// enumerate them, e.g. local, where the agent's own model judges). An adapter
	// that states the notice needs them to say whether anything was actually FIXED:
	// only introduced findings are force-fixed, while suggest-only and pre-existing
	// ones are surfaced for the developer to decide.
	DeliverReview(prompt, banner string, fileCount int, findings []wire.Finding) ([]byte, error)

	// DeliverNotice wraps a NON-BLOCKING developer notice as this agent's
	// Stop-hook output (written to stdout): a systemMessage with no block
	// decision, so the developer sees the message but the turn still yields.
	// Used on the fail-open path to report that a turn went unreviewed (server
	// down, license invalid) instead of failing silently. message is review.SkipNotice.
	DeliverNotice(message string) ([]byte, error)

	// DeliverPromptNotice wraps a NON-BLOCKING developer notice as this agent's
	// UserPromptSubmit output. Unlike DeliverNotice it carries the notice on two
	// channels: message as a terminal-only systemMessage, and context injected into
	// the model's turn so the agent relays it in its reply — the only channel that
	// reaches the desktop app and web UI (a systemMessage is not forwarded over
	// stream-json). Used for the update nag; see review.PromptNoticeJSON.
	DeliverPromptNotice(message, context string) ([]byte, error)
}
