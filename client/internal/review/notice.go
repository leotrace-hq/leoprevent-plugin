package review

import (
	"encoding/json"
	"strings"

	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

// SkipReason classifies WHY a turn's security review could not run. It rides a
// typed SkipError from the reviewer (which talked to the server and knows the
// failure) up to the engine (which surfaces the developer notice), so the engine
// stays free of any HTTP/apiclient dependency — the agent-agnostic core only sees
// a review-skipped reason, never a status code.
type SkipReason int

const (
	// SkipUnknown is an unclassified failure — surfaced generically.
	SkipUnknown SkipReason = iota
	// SkipUnreachable: the server could not be reached or did not respond
	// (transport error / timeout) — it's down, or the URL/network is wrong.
	SkipUnreachable
	// SkipUnauthorized: the server rejected the license (401/403) — missing,
	// invalid, suspended, or not entitled to this tier.
	SkipUnauthorized
	// SkipServerError: the server was reached but failed (5xx / bad response).
	SkipServerError
	// SkipMisconfigured: the review could not even be attempted because the client
	// itself is misconfigured (unreadable/invalid leoprevent.json, reviewer init
	// failed). Unlike the other reasons this is decided locally, before any request.
	SkipMisconfigured
	// SkipTimedOut: the server was reachable but did not respond within the client
	// deadline (a slow / overloaded judge). Distinct from SkipUnreachable (never
	// connected) so the developer learns the turn TIMED OUT, not that the server is down.
	SkipTimedOut
)

// String is the stable, log-friendly label for a reason (plugin client.log).
func (r SkipReason) String() string {
	switch r {
	case SkipUnreachable:
		return "unreachable"
	case SkipUnauthorized:
		return "unauthorized"
	case SkipServerError:
		return "server_error"
	case SkipMisconfigured:
		return "misconfigured"
	case SkipTimedOut:
		return "timed_out"
	default:
		return "unknown"
	}
}

// SkipError wraps a review failure with its SkipReason. The reviewer (delivery)
// classifies the underlying apiclient error into one of these; the engine reads
// the Reason to choose the developer-facing notice, then still fails open. It
// unwraps to the original error so logging keeps the full cause.
type SkipError struct {
	Reason SkipReason
	Err    error
}

func (e *SkipError) Error() string {
	if e.Err == nil {
		return "review skipped: " + e.Reason.String()
	}
	return e.Err.Error()
}

func (e *SkipError) Unwrap() error { return e.Err }

// SkipNotice is the short, developer-facing message explaining that THIS turn was
// not security-reviewed and what to check. Deliberately calm and actionable — it
// is shown via a NON-BLOCKING Stop notice (systemMessage only, see NoticeJSON), so
// the turn still ends. leoprevent still fails open; it just stops being silent
// about an outage so the developer isn't falsely assured they were protected.
func SkipNotice(reason SkipReason) string {
	switch reason {
	case SkipUnreachable:
		return "⚠️ LeoPrevent: can't reach the security server — this turn was NOT reviewed (is it running / reachable?)."
	case SkipUnauthorized:
		return "⚠️ LeoPrevent: license invalid or not entitled — this turn was NOT reviewed (check your license_key / tier)."
	case SkipServerError:
		return "⚠️ LeoPrevent: the security server errored — this turn was NOT reviewed."
	case SkipMisconfigured:
		return "⚠️ LeoPrevent: misconfigured (check leoprevent.json) — this turn was NOT reviewed."
	case SkipTimedOut:
		return "⚠️ LeoPrevent: the security review timed out — this turn was NOT reviewed (server slow or overloaded)."
	default:
		return "⚠️ LeoPrevent: security review unavailable — this turn was NOT reviewed."
	}
}

// FixStillVulnerableNotice is the developer-facing message for the SYNCHRONOUS
// /outcome re-verify: after LeoPrevent blocked and the agent fixed, the re-judge found
// the agent's introduced fix is STILL vulnerable. Shown as a NON-BLOCKING Stop notice
// (the turn still yields) so the dev learns it in-turn — before closing the agent —
// instead of shipping a silently-bad fix. Each still-firing finding is listed by
// location + rule name AND the judge's reason (issue) + the suggested fix, so the
// developer/agent learns WHY it's still vulnerable, not just where (capped at `max`
// findings to keep the notice bounded). The issue/fix prose comes from the server
// already run through the rule-text exfil hardening (scrub/redact/cap).
func FixStillVulnerableNotice(findings []wire.Finding) string {
	const max = 3
	var b strings.Builder
	b.WriteString("⚠️ LeoPrevent: your fix is still vulnerable — the re-check after your change still flags:")
	for i, f := range findings {
		if i == max {
			break
		}
		name := f.Name
		if name == "" {
			name = f.Rule
		}
		b.WriteString("\n• ")
		if f.Location != "" {
			b.WriteString(f.Location + " (" + name + ")")
		} else {
			b.WriteString(name)
		}
		if f.Issue != "" {
			b.WriteString(": " + f.Issue)
		}
		if f.Fix != "" {
			b.WriteString(" — fix: " + f.Fix)
		}
	}
	if len(findings) > max {
		b.WriteString("\n• …")
	}
	b.WriteString("\nThis is a non-blocking warning; please review before you ship.")
	return b.String()
}

// notice is the NON-BLOCKING Stop-hook output: a systemMessage with NO decision
// field, so the developer sees the message but the stop proceeds. This is the
// fail-open counterpart to rewake (which blocks). The separate struct keeps the
// JSON to exactly {"systemMessage":…} — no empty decision/reason leaks in.
type notice struct {
	SystemMessage string `json:"systemMessage"`
}

// NoticeJSON builds the non-blocking Stop-hook notice (systemMessage only). Unlike
// RewakeJSON it sets NO decision, so the agent surfaces the message to the
// developer and the turn still yields — used on the fail-open path to report that
// a turn went unreviewed (server down, license invalid) instead of failing silently.
func NoticeJSON(message string) ([]byte, error) {
	return json.Marshal(notice{SystemMessage: message})
}

// promptNotice is the UserPromptSubmit output carrying a developer notice on TWO
// channels at once, because they reach DIFFERENT surfaces:
//
//   - SystemMessage renders in the terminal REPL, but is NOT forwarded over the
//     stream-json protocol — so the Claude desktop app and claude.ai (which run the
//     CLI as a stream-json subprocess) never receive it. Verified against CC 2.1.219
//     and 2.1.220: a systemMessage-only hook output produces zero wire records.
//   - AdditionalContext is injected into the model's context for this turn, so the
//     agent states the notice in its ordinary reply — and assistant text is the one
//     channel every surface renders. This is what makes the notice visible in the
//     app and web UI at all.
//
// The two are complementary, not redundant: the systemMessage is verbatim and
// deterministic (but terminal-only), while the context injection is model-mediated
// (it may be reworded or, rarely, skipped) but reaches every surface.
type promptNotice struct {
	SystemMessage      string                   `json:"systemMessage"`
	HookSpecificOutput promptHookSpecificOutput `json:"hookSpecificOutput"`
}

type promptHookSpecificOutput struct {
	HookEventName     string `json:"hookEventName"`
	AdditionalContext string `json:"additionalContext"`
}

// PromptNoticeJSON builds a NON-BLOCKING UserPromptSubmit notice that reaches both
// the terminal (message, verbatim) and the app/web UI (context, relayed by the
// agent). It sets no decision, so the prompt proceeds normally. context should tell
// the agent to state the notice to the developer; see update.ContextMessage.
func PromptNoticeJSON(message, context string) ([]byte, error) {
	return json.Marshal(promptNotice{
		SystemMessage: message,
		HookSpecificOutput: promptHookSpecificOutput{
			HookEventName:     "UserPromptSubmit",
			AdditionalContext: context,
		},
	})
}
