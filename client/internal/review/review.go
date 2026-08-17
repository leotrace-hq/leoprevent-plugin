// Package review builds the reviewer instruction injected back into the agent
// via the Stop-hook re-wake.
package review

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
	"github.com/leotrace-hq/leoprevent-plugin/rulespec"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

// rewake is the Stop-hook output that blocks the yield and re-wakes the agent.
type rewake struct {
	Decision           string                  `json:"decision"`
	Reason             string                  `json:"reason"`
	SystemMessage      string                  `json:"systemMessage,omitempty"`
	HookSpecificOutput *stopHookSpecificOutput `json:"hookSpecificOutput,omitempty"`
}

// stopHookSpecificOutput carries the Stop-path context channel. It is a POINTER
// on rewake so an adapter that doesn't set it emits no key at all (Codex and
// Copilot must not — see their adapter tests).
type stopHookSpecificOutput struct {
	HookEventName     string `json:"hookEventName"`
	AdditionalContext string `json:"additionalContext"`
}

// BuildPrompt renders the LOCAL-tier reviewer instruction: changed code +
// candidate rules (content fetched from /rules) with one-line descriptions and
// fix suggestions + meta-policy header + output contract. The agent's own model
// does the judging locally. Designed to fit in a few screenfuls.
func BuildPrompt(changes []transcript.Change, selected []rulespec.Rule, metaPolicy string) string {
	var b strings.Builder

	b.WriteString("🔒 LeoPrevent: security review required. Run in a FRESH SUBAGENT via the Task tool (subagent_type: general-purpose).\n\n")

	b.WriteString("## Changed code this turn\n\n")
	for _, c := range changes {
		b.WriteString(renderChange(c.FilePath, c.AddedText, c.FullContent))
	}

	b.WriteString("## Candidate rules to check\n\n")
	b.WriteString("These are heuristic candidates from a lexical pre-filter, not findings. Verify each against the code above and discard any that don't apply. Your verdict (specific violations, or **CLEAN**) is the result, not this list.\n\n")
	for _, r := range selected {
		severity := ""
		if r.Severity != "" {
			severity = fmt.Sprintf(" [%s]", r.Severity)
		}
		// One-line what-to-look-for (first sentence only).
		lookFor := firstSentence(r.LookFor)
		// Full suggestion — this is the fix recipe, keep it verbatim.
		suggestion := strings.TrimSpace(r.Suggestion)
		// Show the human rule NAME ("Server-Side Request Forgery"), not the kebab ID.
		label := r.Name
		if label == "" {
			label = r.ID
		}
		b.WriteString(fmt.Sprintf("**%s**%s: %s\n", label, severity, lookFor))
		// does_not_apply_when is the precision lever — render it verbatim so the
		// local judge can prune false positives, matching the server-side judge.
		if dna := strings.TrimSpace(r.DoesNotApplyWhen); dna != "" {
			b.WriteString(fmt.Sprintf("→ does NOT apply when: %s\n", dna))
		}
		b.WriteString(fmt.Sprintf("→ fix: %s\n", suggestion))
		// auto_fix:false rules are suggest-only: their fix carries high regression
		// risk (e.g. proxy/server config), so the local judge must surface them for
		// the developer to decide, not auto-apply like the rest.
		if !r.AutoFixAllowed() {
			b.WriteString("→ SUGGEST-ONLY: do NOT auto-apply this fix. Report the issue + fix and let the developer decide (high-regression-risk change, e.g. server/proxy config).\n")
		}
		b.WriteString("\n")
	}

	// Meta-policy: rendered VERBATIM from the server's /rules response. The client
	// ships NO rule or policy content of its own — baking even a paraphrase here would
	// put corpus-derived text in the shipped binary, violating the IP non-negotiable
	// ("the client ships no rule content"). Empty when the server sent none.
	if mp := strings.TrimSpace(metaPolicy); mp != "" {
		b.WriteString("## Meta-policy\n\n")
		b.WriteString(mp)
		b.WriteString("\n\n")
	}

	b.WriteString("## Output contract\n\n")
	b.WriteString("- Flag violations with file:line + the concrete fix above.\n")
	b.WriteString("- If no violations: report exactly **CLEAN**.\n")
	b.WriteString("- Apply every fix without asking, EXCEPT rules marked SUGGEST-ONLY. For those, report the issue + fix and let the developer decide; do not change the code.\n")
	b.WriteString("- Summarize what changed.\n")

	return b.String()
}

// BuildFindingsPrompt renders the CLOUD-tier reviewer instruction. The server's
// strong model has ALREADY judged the diff, so the agent doesn't re-review — it
// just applies each fix in-turn. Deliberately minimal: only location + issue +
// fix, which is all the agent needs. The RULE ID is omitted on purpose — it adds
// nothing to the fix and is one less thing about the rule corpus to expose in the
// agent-/developer-visible text. (The issue/fix are code-specific, not rule
// wording — the judge is prompted never to echo rule text.)
//
// The first line MUST start with the Codex re-wake marker (transcript.reWakeMarker;
// see TestPromptPrefixMatchesCodexMarker) — keep "🔒 LeoPrevent: security review".
func BuildFindingsPrompt(findings []wire.Finding) string {
	// Split into three groups by how each finding may be remediated:
	//   - introduced: a vuln the agent added THIS turn whose rule permits auto-fix →
	//     force-fixed in-turn ("don't ask").
	//   - suggestOnly: the rule is marked auto_fix:false (high-regression-risk fix,
	//     e.g. proxy/server config) → surfaced for manual review, never auto-applied,
	//     EVEN IF introduced this turn. Checked first so it wins over the provenance
	//     split (an introduced finding on a suggest-only rule must NOT be force-fixed).
	//   - preexisting: in code that already existed → surfaced to the developer to
	//     fix-or-not (scope creep to auto-fix code the agent didn't touch). One carve-out
	//     in the copy: when the agent's OWN added lines route through the old sink, it may
	//     rewire those added lines to a safe sibling — pre-existing lines stay untouched
	//     either way, and "when unsure, leave it" keeps the default conservative.
	// Absent flags ⇒ introduced + auto-fix allowed (the safe historical default).
	var introduced, suggestOnly, preexisting []wire.Finding
	for _, f := range findings {
		switch {
		case f.SuggestOnly:
			suggestOnly = append(suggestOnly, f)
		case f.Preexisting:
			preexisting = append(preexisting, f)
		default:
			introduced = append(introduced, f)
		}
	}

	var b strings.Builder
	switch {
	case len(introduced) > 0:
		b.WriteString("🔒 LeoPrevent: security review: fix before finishing this turn. Apply each directly, don't ask.\n\n")
		writeFindingGroups(&b, introduced)
	case len(suggestOnly) > 0 || len(preexisting) > 0:
		// Nothing to force-fix, but there are items to surface. Keep the marker prefix.
		b.WriteString("🔒 LeoPrevent: security review: nothing to auto-fix; review the items below.\n\n")
	default:
		// Genuinely clean; keep the Codex re-wake marker prefix either way.
		b.WriteString("🔒 LeoPrevent: security review: your change itself is clean.\n\n")
	}
	if len(suggestOnly) > 0 {
		b.WriteString("These need a fix, but LeoPrevent does NOT auto-apply it, because the fix carries high regression risk (e.g. reverse-proxy / web-server config). Review each, apply manually only if correct, and confirm with the developer before changing shared config:\n\n")
		writeFindingGroups(&b, suggestOnly)
	}
	if len(preexisting) > 0 {
		b.WriteString("Pre-existing issues NOT introduced by your change this turn. Do NOT edit these pre-existing lines. If code YOU added this turn routes through one of them, make your added code safe without touching the old lines (e.g. wire it to a safe sibling helper), but only when that stays compatible with existing data and flows; when unsure, leave it. Once you're done, tell the developer these exist and ask whether they want them fixed:\n\n")
		writeFindingGroups(&b, preexisting)
	}
	// The assumptions ask goes LAST, after every finding, so it never competes with
	// the fix instruction that is this prompt's actual job. Cloud only: the local tier
	// never reaches the server, so asking there would collect an answer with nowhere to
	// put it, at the cost of noise in the developer's reply. See AssumptionsAsk.
	b.WriteString(AssumptionsAsk)
	return b.String()
}

// writeFindingGroups renders findings grouped by rule NAME (the human name, e.g.
// "Server-Side Request Forgery", never the kebab ID) so multiple locations of the
// same issue read as one block. NO MARKDOWN: the agent injects this as a plain-text
// Stop re-wake, so backticks/bold would render literally — strip backticks too.
func writeFindingGroups(b *strings.Builder, findings []wire.Finding) {
	var order []string
	byRule := map[string][]wire.Finding{}
	for _, f := range findings {
		label := f.Name
		if label == "" {
			label = f.Rule // server fills Name; bare ID only as a last-resort fallback
		}
		if _, seen := byRule[label]; !seen {
			order = append(order, label)
		}
		byRule[label] = append(byRule[label], f)
	}
	for _, label := range order {
		b.WriteString(stripTicks(label) + "\n")
		for _, f := range byRule[label] {
			loc := stripTicks(strings.TrimSpace(f.Location))
			if issue := stripTicks(strings.TrimSpace(f.Issue)); issue != "" {
				fmt.Fprintf(b, "• %s: %s\n", loc, issue)
			} else {
				fmt.Fprintf(b, "• %s\n", loc)
			}
			// Best-effort heads-up: the agent's added code this turn appears to route
			// into this pre-existing sink. Make the NEW call site safe — still don't
			// edit the old line.
			if f.NewlyReached {
				b.WriteString("  ⚠️ your code added this turn routes into this existing vulnerable helper. Make your NEW call site safe (don't edit the old line)\n")
			}
			if fix := stripTicks(strings.TrimSpace(f.Fix)); fix != "" {
				fmt.Fprintf(b, "  → fix: %s\n", fix)
			}
		}
		b.WriteString("\n")
	}
}

// stripTicks removes backticks — Claude Code renders the Stop re-wake as plain
// text, so a model's markdown ticks (`url`, `request.args`) would show literally.
func stripTicks(s string) string { return strings.ReplaceAll(s, "`", "") }

// renderChange formats one changed file for a review prompt. When fullContent is
// present (git-baseline capture) the judge sees the WHOLE file for context, with
// the lines added this turn called out separately so it still knows what changed.
// When it's empty (transcript fallback) it shows only the added text — the legacy
// snippet-only view.
func renderChange(path, addedText, fullContent string) string {
	added := strings.TrimSpace(addedText)
	if full := strings.TrimSpace(fullContent); full != "" {
		return fmt.Sprintf("### %s (full file for context)\n```\n%s\n```\nlines added this turn:\n```\n%s\n```\n\n", path, full, added)
	}
	return fmt.Sprintf("### %s\n```\n%s\n```\n\n", path, added)
}

// RewakeJSON wraps the review prompt as the Stop-hook block decision. The
// prompt is embedded directly in reason (compact enough for inline display);
// banner is the short, neutral console notice shown to the developer.
func RewakeJSON(prompt, banner string) ([]byte, error) {
	return json.Marshal(rewake{
		Decision:      "block",
		SystemMessage: banner,
		Reason:        prompt,
	})
}

// RewakeWithContextJSON is RewakeJSON plus the Stop-path CONTEXT channel, so the
// developer learns a review fired on a surface where systemMessage is invisible.
//
// WHY this exists: systemMessage is terminal-only — it is not forwarded over the
// stream-json protocol, so the desktop app and claude.ai never receive it. That is
// the same limitation the UserPromptSubmit update nag works around
// (PromptNoticeJSON), and it applies to the Stop banner too: on the desktop app a
// review that fires and force-fixes is INVISIBLE unless the agent says so.
//
// Measured on CC 2.1.221 (stream-json, the mode the desktop app runs the CLI in):
// a Stop output carrying BOTH a block decision and hookSpecificOutput.
// additionalContext delivers the context to the model (it acted on it), while the
// same output's systemMessage produced ZERO wire records. So the Stop path DOES
// have a context channel when it blocks — contrary to the earlier assumption that
// it had none, which reasoned "no block ⇒ no model turn to speak in": true of the
// NON-blocking notice, but not of a block.
//
// Same trade as the update nag: the context half is model-mediated (it may be
// reworded and can occasionally be skipped), so it is a VISIBILITY layer, never
// the record — the dashboards remain the source of truth. The re-wake `reason`
// still carries the authoritative findings and is unchanged.
func RewakeWithContextJSON(prompt, banner, context string) ([]byte, error) {
	return json.Marshal(rewake{
		Decision:      "block",
		SystemMessage: banner,
		Reason:        prompt,
		HookSpecificOutput: &stopHookSpecificOutput{
			HookEventName:     "Stop",
			AdditionalContext: context,
		},
	})
}

// ReviewContextMessage instructs the agent to tell the developer a security
// review fired, for surfaces that never render the systemMessage banner.
//
// It takes the FILE COUNT, not the banner string. An earlier version passed the
// whole banner "so the two channels can't drift" — but the banner carries the
// GitlessWarning suffix on a degraded run, which then surfaced inside the
// developer-facing notice as "⚠️ no git repo here" even when the repo IS a git
// repo (the baseline was missing for an unrelated reason). That reads as a false
// claim about the developer's project in the one line they actually see. The
// warning is DIAGNOSTIC — it belongs in the terminal banner and the plugin log,
// not in the headline notice; keep this message about what happened, not about
// how well it ran.
//
// The wording follows update.ContextMessage, which was tuned against a live agent:
// lead with the instruction, ask for ONE quoted+labelled line so the notice reads
// as plugin chrome rather than the agent's own remark, then continue the turn. It
// deliberately does NOT restate the findings — the re-wake `reason` already
// carries those and the agent reports what it fixed in its reply; duplicating
// them here would double the noise on every block.
// forceFixed is how many of the findings the re-wake actually force-fixes (see
// BuildFindingsPrompt's introduced/suggest-only/pre-existing split). It decides
// which of the two outcomes the notice states.
func ReviewContextMessage(fileCount int, findings []wire.Finding, forceFixed int) string {
	noun := "files"
	if fileCount == 1 {
		noun = "file"
	}
	head := "> Reviewed " + strconv.Itoa(fileCount) + " changed " + noun

	// The re-wake fires on THREE outcomes and only one of them is "addressed":
	// introduced findings are force-fixed in-turn, while suggest-only and
	// pre-existing ones are SURFACED and the agent is told not to touch them. An
	// unconditional "addressed below" therefore promised a fix that never came —
	// and with a degraded review (no baseline ⇒ nothing anchorable ⇒ everything
	// classified pre-existing) the surfaced-only case is the COMMON one, not an
	// edge case. Say which happened.
	var tail string
	switch {
	case len(findings) == 0:
		// Shouldn't reach here (an empty prompt doesn't block), but never claim a
		// finding we can't count.
		tail = ". See the review notes below."
	case forceFixed == 0:
		tail = " and raised " + count(len(findings), "finding") +
			" for you to review. They are not auto-fixed, so they need your decision."
	case forceFixed == len(findings):
		tail = " and fixed " + count(forceFixed, "finding") + " below."
	default:
		tail = ", fixed " + count(forceFixed, "finding") + " and surfaced " +
			strconv.Itoa(len(findings)-forceFixed) + " more for you to review."
	}

	return "Begin your reply with exactly this markdown, before anything else:\n\n" +
		"> 🔒 **LeoPrevent** · automated security review, not part of your request\n" +
		"> \n" +
		head + tail + "\n\n---\n\n" +
		"Then continue with the developer's request as normal, reporting what you " +
		"changed in response to the review."
}

// count renders "1 finding" / "3 findings".
func count(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return strconv.Itoa(n) + " " + noun + "s"
}

// ForceFixedCount reports how many findings the re-wake will actually apply
// without asking — the INTRODUCED ones whose rule permits auto-fix. It mirrors
// BuildFindingsPrompt's grouping exactly (suggest-only is checked FIRST, so an
// introduced finding on a suggest-only rule is surfaced, not force-fixed); keep
// the two in step if that split ever changes.
func ForceFixedCount(findings []wire.Finding) int {
	n := 0
	for _, f := range findings {
		if !f.SuggestOnly && !f.Preexisting {
			n++
		}
	}
	return n
}

// GitlessWarning is appended to the banner when the review ran WITHOUT a git
// baseline (transcript-fallback path): leoprevent then sees only the lines the
// agent wrote via edit tools — not Bash writes, and with no full-file context —
// so the review is weaker. Customer-facing and deliberately non-technical.
const GitlessWarning = "⚠️ no git repo here, so LeoPrevent sees less of your code (run git init for full coverage)"

// Banner is the short, neutral console notice. Selection is not detection: it
// names how many files are under review, never claims a violation was found —
// that verdict only comes from the review subagent.
func Banner(fileCount int) string {
	noun := "files"
	if fileCount == 1 {
		noun = "file"
	}
	return fmt.Sprintf("🔒 LeoPrevent: security review (%d %s)", fileCount, noun)
}

// firstSentence returns the first sentence of a block of text (up to the first
// ". " or the first newline, whichever comes first), trimmed.
func firstSentence(text string) string {
	text = strings.TrimSpace(text)
	for _, sep := range []string{". ", ".\n", "\n"} {
		if i := strings.Index(text, sep); i > 0 {
			return strings.TrimSpace(text[:i+1])
		}
	}
	if r := []rune(text); len(r) > 120 {
		return string(r[:120]) + "…" // rune-safe: never split a multi-byte char
	}
	return text
}
