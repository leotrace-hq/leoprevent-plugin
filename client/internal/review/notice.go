package review

import (
	"encoding/json"
	"strconv"
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
		return "⚠️ LeoPrevent: can't reach the security server. This turn was NOT reviewed (is it running / reachable?)."
	case SkipUnauthorized:
		return "⚠️ LeoPrevent: license invalid or not entitled. This turn was NOT reviewed (check your license_key / tier)."
	case SkipServerError:
		return "⚠️ LeoPrevent: the security server errored. This turn was NOT reviewed."
	case SkipMisconfigured:
		return "⚠️ LeoPrevent: misconfigured (check leoprevent.json). This turn was NOT reviewed."
	case SkipTimedOut:
		return "⚠️ LeoPrevent: the security review timed out. This turn was NOT reviewed (server slow or overloaded)."
	default:
		return "⚠️ LeoPrevent: security review unavailable. This turn was NOT reviewed."
	}
}

// FixStillVulnerableNotice is the developer-facing message for the SYNCHRONOUS
// /outcome re-verify: after LeoPrevent blocked and the agent fixed, the re-judge found
// the agent's introduced fix is STILL vulnerable. Shown as a NON-BLOCKING Stop notice
// (the turn still yields) so the dev learns it in-turn — before closing the agent —
// instead of shipping a silently-bad fix.
//
// ⚠️ IT IS AN ALERT, NOT THE RECORD, AND THE LINE COUNT IS THE READABILITY COST.
// Claude Code renders a systemMessage by prefixing EVERY line with "Stop says: " and
// wrapping it in a narrow column, so N lines of judge prose become N labelled lines of
// chrome. It used to carry each finding's full issue AND fix verbatim: on a real turn
// with three still-firing findings (LEO-120) that rendered as ~40 prefixed lines,
// followed by a bare "• …" that didn't even say how many more there were. So the notice
// now states WHAT and WHERE only:
//
//   - grouped by rule NAME with the locations joined, the same shape (and the same
//     reason) as writeFindingGroups — several locations of one issue read as one line;
//   - the FIX prose is dropped entirely. The agent already had it verbatim in the
//     re-wake and botched it, so repeating it here helps nobody, and a shortened fix
//     recipe is worse than none: a developer who applies half of one has shipped an
//     incomplete guard believing they followed the advice;
//   - the WHY rides along ONLY when there is exactly ONE finding (first sentence of the
//     judge's issue). That is the ticket's "chevron to read more" in a surface that has
//     no chevron: expand when there is one thing, collapse when there are many. It is
//     the issue, never the fix, because an under-explained finding merely under-informs.
//
// Every part is bounded (maxGroups rule lines, maxLocs locations each, the remainder
// stated as a count) so the whole notice stays a handful of lines whatever it is handed.
// The full issue/fix prose still egresses on the /outcome response and is recorded on
// the outcome event; the dashboards remain the record. The prose comes from the server
// already run through the rule-text exfil hardening (scrub/redact/cap).
func FixStillVulnerableNotice(findings []wire.Finding) string {
	const (
		maxGroups = 4 // rule lines before the remainder count
		maxLocs   = 3 // locations named per rule before "+N more"
	)

	var b strings.Builder
	b.WriteString("⚠️ LeoPrevent: your fix is still vulnerable. The re-check after your change still flags " +
		count(len(findings), "finding") + ":")

	groups, order := groupLocations(findings)
	for i, label := range order {
		if i == maxGroups {
			b.WriteString("\n• …and " + count(len(order)-maxGroups, "more rule") + " flagged")
			break
		}
		b.WriteString("\n• " + label)
		switch locs := groups[label]; {
		case len(locs) > maxLocs:
			b.WriteString(": " + strings.Join(locs[:maxLocs], ", ") +
				" (+" + strconv.Itoa(len(locs)-maxLocs) + " more)")
		case len(locs) > 0:
			b.WriteString(": " + strings.Join(locs, ", "))
		}
	}

	// One finding: there is room to say why, so say it (first sentence only).
	if len(findings) == 1 {
		if why := onWordBoundary(firstSentence(stripTicks(strings.TrimSpace(findings[0].Issue)))); why != "" {
			b.WriteString("\n  why: " + why)
		}
	}

	b.WriteString("\nThis is a non-blocking warning; please review before you ship.")
	return b.String()
}

// onWordBoundary pulls a truncation back to the last whole word. firstSentence falls
// back to a hard rune cut when the prose has no sentence end, which lands mid-token on
// exactly the kind of text the judge writes (a JSON fragment, an expression) — the
// notice is one glanceable line, so a dangling half-token reads as a rendering bug.
func onWordBoundary(s string) string {
	if !strings.HasSuffix(s, "…") {
		return s
	}
	head := strings.TrimSuffix(s, "…")
	if i := strings.LastIndex(head, " "); i > 0 {
		return strings.TrimRight(head[:i], " ,;:") + "…"
	}
	return s
}

// groupLocations buckets findings by rule NAME (human name, falling back to the kebab
// ID only when the server sent none) and returns each bucket's locations plus the
// first-seen rule order, so the notice is deterministic rather than map-ordered. A
// finding with no location contributes nothing to its bucket's list — the rule name
// alone is still worth naming.
func groupLocations(findings []wire.Finding) (map[string][]string, []string) {
	groups := map[string][]string{}
	var order []string
	for _, f := range findings {
		label := stripTicks(strings.TrimSpace(f.Name))
		if label == "" {
			label = stripTicks(strings.TrimSpace(f.Rule))
		}
		if _, seen := groups[label]; !seen {
			order = append(order, label)
			groups[label] = nil
		}
		if loc := stripTicks(strings.TrimSpace(f.Location)); loc != "" {
			groups[label] = append(groups[label], loc)
		}
	}
	return groups, order
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
