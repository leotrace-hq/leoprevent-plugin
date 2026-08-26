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
// preexistingText is the paragraph that introduces the PRE-EXISTING findings, passed
// straight through from wire.ReviewResponse.PreexistingDirective and rendered VERBATIM.
// Empty means the server sent none, and preexistingInstruction's own default is used.
//
// ⚠️ THIS MODULE MUST NOT KNOW WHY THAT TEXT DIFFERS, AND MUST NEVER BRANCH ON IT. What
// the agent is told to do about code it did not write is a SERVER-SIDE policy decision.
// The client renders one group with one paragraph and cannot tell which policy produced
// it. Anything that inspected the string, or took a boolean alongside it, would put a
// second copy of that policy in the shipped binary — and then every developer's install
// would have to move in step with the server for the two to agree, which is the whole
// thing this shape avoids.
func BuildFindingsPrompt(findings []wire.Finding, preexistingText string) string {
	// Split into three groups by how each finding may be remediated:
	//   - introduced: a vuln the agent added THIS turn whose rule permits auto-fix →
	//     fixed in-turn ("apply directly, don't ask").
	//   - suggestOnly: the rule is marked auto_fix:false (high-regression-risk fix,
	//     e.g. proxy/server config) → reported to the developer, never fixed in-turn,
	//     EVEN IF introduced this turn. Checked FIRST so it wins over the provenance
	//     split (an introduced finding on a suggest-only rule must NOT be fixed).
	//   - preexisting: in code that already existed. WHAT THE AGENT IS TOLD TO DO WITH
	//     THESE IS NOT DECIDED HERE — it is the paragraph the server sent, rendered
	//     verbatim (see preexistingInstruction). This module deliberately does not know
	//     what the alternatives are, so there is exactly one code path either way.
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
		// The agent introduced nothing, but there are items below. Keep the marker prefix,
		// and stay NEUTRAL about what happens to them: each group's own paragraph says
		// that, and for pre-existing findings that paragraph comes from the server. The
		// old wording ("nothing to auto-fix") did two things wrong at once — it implied
		// LeoPrevent applies fixes, and it was a client-side claim about a server-side
		// decision, so it would flatly contradict a server paragraph asking for a fix.
		b.WriteString("🔒 LeoPrevent: security review: nothing to fix in the code you changed. See the items below.\n\n")
	default:
		// Genuinely clean; keep the Codex re-wake marker prefix either way.
		b.WriteString("🔒 LeoPrevent: security review: your change itself is clean.\n\n")
	}
	if len(suggestOnly) > 0 {
		// ⚠️ IT MUST NOT SAY "LeoPrevent does NOT auto-apply it", WHICH IS WHAT IT SAID
		// BEFORE. LeoPrevent never applies anything: every edit, in every group, is the
		// agent's. There are exactly two things it can say about a finding — fix it now, or
		// tell the developer about it — so wording that implies a third actor teaches the
		// agent the wrong model of who acts, and misleads the developer reading the same
		// line on their screen. The BEHAVIOUR here is unchanged: this group is still the
		// developer's call and still not fixed in-turn.
		b.WriteString("These are for the developer to decide on, not for you to fix now: the fix carries high regression risk (e.g. reverse-proxy / web-server config). Tell the developer what is wrong and what the fix would be, and do not change shared config without their go-ahead:\n\n")
		writeFindingGroups(&b, suggestOnly)
	}
	if len(preexisting) > 0 {
		b.WriteString(preexistingInstruction(preexistingText))
		b.WriteString("\n\n")
		writeFindingGroups(&b, preexisting)
	}
	// The prompt deliberately ends with the findings. It used to append AssumptionsAsk
	// here; that is removed (LEO-113) and must not come back without a decision, because
	// the session is the only channel a Stop hook has in either direction, so the ask and
	// the agent's answer both render on the developer's screen. See AssumptionsAsk for
	// what that cost, and for the parser that is still ready if it is re-enabled.
	return b.String()
}

// preexistingInstruction returns the paragraph that introduces the PRE-EXISTING findings:
// the SERVER's, when it sent one, and this module's own otherwise.
//
// ⚠️ THE DEFAULT IS THE ONLY WORDING THIS BINARY HOLDS, AND IT IS THE ONE THIS BINARY HAS
// ALWAYS HELD. That is the point. What the agent is told to do about code it did not write
// is a policy decision, it is made server-side, and it changes without a plugin release. So
// the client ships exactly one paragraph — the conservative one, unchanged — and renders the
// server's instead whenever one arrives. It never learns that another policy exists, never
// branches on which it got, and so can neither fall out of step with the server nor report
// the difference to the developer.
//
// This default is reached in the ORDINARY case: the server sent nothing because the policy
// is off, or because it predates the field. Falling back to SILENCE would be worse — an
// agent handed a list of flaws with no instruction invents one.
//
// Same posture as the local tier's meta-policy, which is also rendered verbatim from the
// server rather than kept here.
func preexistingInstruction(fromServer string) string {
	if t := strings.TrimSpace(fromServer); t != "" {
		return t
	}
	return "Pre-existing issues NOT introduced by your change this turn. Do NOT edit these " +
		"pre-existing lines. If code YOU added this turn routes through one of them, make your " +
		"added code safe without touching the old lines (e.g. wire it to a safe sibling helper), " +
		"but only when that stays compatible with existing data and flows; when unsure, leave it. " +
		"Once you're done, tell the developer these exist and ask whether they want them fixed:"
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
			loc := findingLocation(f)
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

// findingLocation renders a finding's location for the developer and the agent,
// widening it to `path:42-58` when the finding marks a SPAN (wire.Finding.EndLine).
//
// One definition, shared by the blocking re-wake and the non-blocking notice, because
// they name the same finding on the same screen: two spellings of one location reads as
// two findings. The SEPARATOR is a plain hyphen, not an en dash — this text goes to a
// terminal and to an agent that may echo it back, and a range spelled with a dash a
// developer cannot type is one they cannot grep for.
//
// A span is DISPLAY only. Location itself is untouched, so the string a later /outcome
// echoes back, and the identity every dashboard de-dupes on, stay `path:line`.
func findingLocation(f wire.Finding) string {
	loc := stripTicks(strings.TrimSpace(f.Location))
	if f.EndLine <= 0 || loc == "" {
		return loc
	}
	// The end is appended only when the location really ends in the START line: the
	// server guarantees EndLine > that line, but a location with no trailing :N (the
	// judge cited a symbol when no numbered context was available) has no start to
	// count from, and `handler:58` would then read as a line number that is not one.
	i := strings.LastIndexByte(loc, ':')
	if i < 0 {
		return loc
	}
	if n, err := strconv.Atoi(strings.TrimSpace(loc[i+1:])); err != nil || n <= 0 || f.EndLine <= n {
		return loc
	}
	return fmt.Sprintf("%s-%d", loc, f.EndLine)
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
	//
	// EVERY branch describes what the REVIEW did, never what LeoPrevent fixed.
	// The force-fix branch used to read "and fixed 1 finding below", which is
	// wrong twice over: it sits under the "🔒 LeoPrevent" byline, so it credits
	// the reviewer with an edit LeoPrevent never makes (the re-wake asks the
	// AGENT to fix), and it is emitted BEFORE the fix — this text is the first
	// thing in the reply, so an agent that then declines, defers or botches the
	// fix has already reported it as done, with nothing later contradicting it.
	// "flagged N to fix" is true when written and stays true either way; the
	// agent reports the actual edits in its own prose below, as the closing
	// instruction asks. Keep the verbs on the reviewer's side of the line.
	var tail string
	switch {
	case len(findings) == 0:
		// Shouldn't reach here (an empty prompt doesn't block), but never claim a
		// finding we can't count.
		tail = ". See the review notes below."
	case forceFixed == 0:
		tail = " and raised " + count(len(findings), "finding") + " for you to review."
	case forceFixed == len(findings):
		tail = " and flagged " + count(forceFixed, "finding") + " to fix below."
	default:
		tail = ", flagged " + count(forceFixed, "finding") + " to fix and surfaced " +
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

// ForceFixedCount reports how many findings the re-wake tells the agent to fix without
// asking: the INTRODUCED ones whose rule permits auto-fix. It mirrors BuildFindingsPrompt's
// grouping (suggest-only is checked FIRST, so a finding on a suggest-only rule is reported
// whatever its class); keep the two in step if that split ever changes.
//
// ⚠️ IT DELIBERATELY DOES NOT COUNT PRE-EXISTING FINDINGS, EVEN WHEN THE SERVER'S
// PARAGRAPH ASKS FOR THEM TO BE FIXED. An earlier version did, on the reasoning that the
// developer-facing notice would otherwise say "raised N for you to review" above a prompt
// asking the agent to fix them. That reasoning was sound about the notice and wrong about
// the boundary: this function is reached from the agent adapters, where the server's
// response is long gone, so counting them would need the POLICY compiled into the client —
// which would make the setting visible in the developer's own notice and put a second copy
// of a server-side decision in every install, to be updated in step.
//
// So the notice stays identical whichever policy is in force. It under-claims in that case
// (it says findings were raised, not that they will be fixed) but it says nothing false,
// and the agent reports its actual edits in its own prose below, which is what the closing
// instruction asks for.
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

// HeadAnchoredWarning is appended to the banner when a repository had no turn-start
// baseline and was reviewed against HEAD instead (vcs.BaselineInfo.HeadAnchored).
//
// ⚠️ IT STATES A LIMIT ON THE EVIDENCE, WHICH IS WHY IT IS NOT OPTIONAL. Such a diff is
// a superset of the turn: it carries this turn's work AND anything already uncommitted,
// with no way to tell them apart. So the findings may describe code the developer wrote
// earlier, they are surfaced for them to fix now or later rather than applied in-turn,
// and a count from this review must not be read as "introduced this turn". Saying that
// out loud is the difference between a weaker review and a misleading one.
// HeadAnchoredNotice is the NON-BLOCKING message for a review that ran only against
// HEAD. It replaces the block entirely: see the warning in engine on why such a review
// must never re-wake the agent.
func HeadAnchoredNotice(repos []string, findings int) string {
	if len(repos) == 0 {
		return ""
	}
	noun := "finding"
	if findings != 1 {
		noun = "findings"
	}
	return "⚠️ LeoPrevent: " + itoa(findings) + " " + noun + " in " + strings.Join(repos, ", ") +
		", which had no turn-start snapshot — so this compares against the last commit and " +
		"may be describing work you had already left uncommitted. Nothing was changed. Open " +
		"the repo itself for a review scoped to just this turn."
}

// HeadDeclinedNotice is the NON-BLOCKING message for a turn where several repositories
// held work and none could be attributed, so none was reviewed. Naming them is the whole
// point: reviewing nothing silently is the failure this replaced.
func HeadDeclinedNotice(repos []string) string {
	if len(repos) == 0 {
		return ""
	}
	return "⚠️ LeoPrevent: nothing was reviewed this turn. " + strings.Join(repos, ", ") +
		" all have uncommitted changes and nothing identified which one you were working " +
		"in, so guessing would have reviewed the others' work in progress. Open the repo " +
		"you are working in for a full review."
}

func itoa(n int) string { return strconv.Itoa(n) }

func HeadAnchoredWarning(repos []string) string {
	if len(repos) == 0 {
		return ""
	}
	return "⚠️ no turn-start snapshot for " + strings.Join(repos, ", ") +
		", so this compares against the last commit: it may include work you had " +
		"already left uncommitted, and those findings are for you to fix now or later " +
		"(open the repo itself for a review scoped to just this turn)"
}

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
