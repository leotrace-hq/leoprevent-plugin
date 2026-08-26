package review

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
	"github.com/leotrace-hq/leoprevent-plugin/rulespec"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

var ssrfChanges = []transcript.Change{{
	FilePath: "/p/app.py",
	AddedText: `@app.route("/refresh")
def refresh():
    url = request.args["url"]
    resp = requests.get(url)
    return resp.text
`,
}}

var ssrfRule = rulespec.Rule{
	ID:               "ssrf",
	Name:             "Server-Side Request Forgery",
	Severity:         "high",
	LookFor:          "HTTP client calls where the destination is influenced by untrusted input. This is the first sentence.",
	DoesNotApplyWhen: "the URL is a hardcoded constant",
	Suggestion:       "Resolve the hostname to an IP and reject private, loopback and link-local ranges before connecting.",
}

const metaPolicy = "Before reusing a helper, audit its implementation against the rules below."

// TestBuildPrompt (local tier): changed code + candidate rule + fix verbatim +
// the does_not_apply_when carve-out (the precision lever) + subagent instruction
// + CLEAN contract; selection framed as candidates, no "detected" claim.
func TestBuildPrompt(t *testing.T) {
	prompt := BuildPrompt(ssrfChanges, []rulespec.Rule{ssrfRule}, metaPolicy)

	for _, want := range []string{
		ssrfRule.Name,             // the human rule name ("Server-Side Request Forgery"), not the ID
		ssrfRule.Suggestion,       // fix recipe verbatim
		"does NOT apply when",     // the precision lever is rendered
		ssrfRule.DoesNotApplyWhen, // its text, verbatim
		"Task tool",               // fresh-subagent instruction
		`request.args["url"]`,     // changed code
		metaPolicy,                // meta-policy rendered VERBATIM from the server /rules response
		"CLEAN",                   // output contract
		"Candidate rules",         // selection ≠ detection framing
	} {
		if !strings.Contains(prompt, want) {
			t.Errorf("prompt missing %q", want)
		}
	}
	if strings.Contains(prompt, "detected") {
		t.Error("prompt must not claim detection — the verdict comes from the reviewer")
	}
}

// TestBuildPromptOmitsEmptyCarveOut: a rule with no does_not_apply_when must not
// emit a dangling "does NOT apply when:" line.
func TestBuildPromptOmitsEmptyCarveOut(t *testing.T) {
	r := ssrfRule
	r.DoesNotApplyWhen = ""
	if strings.Contains(BuildPrompt(ssrfChanges, []rulespec.Rule{r}, metaPolicy), "does NOT apply when") {
		t.Error("must not render an empty does-not-apply-when line")
	}
}

// TestPromptPrefixMatchesCodexMarker pins the first line of BOTH review prompts to
// the prefix the Codex adapter keys on (transcript.reWakeMarker). If a prompt's
// opening changes without updating that marker, the Codex turn-start exclusion
// silently breaks — so this test fails the change instead.
func TestPromptPrefixMatchesCodexMarker(t *testing.T) {
	const codexReWakeMarker = "🔒 LeoPrevent: security review" // = transcript.reWakeMarker
	localPrompt := BuildPrompt(ssrfChanges, []rulespec.Rule{ssrfRule}, metaPolicy)
	cloudPrompt := promptNoDirective([]wire.Finding{{Rule: "ssrf", Location: "app.py:4"}})
	if !strings.HasPrefix(localPrompt, codexReWakeMarker) {
		t.Errorf("local prompt opening drifted from the Codex marker %q: %.40q", codexReWakeMarker, localPrompt)
	}
	if !strings.HasPrefix(cloudPrompt, codexReWakeMarker) {
		t.Errorf("cloud prompt opening drifted from the Codex marker %q: %.40q", codexReWakeMarker, cloudPrompt)
	}
}

// TestBuildFindingsPrompt (cloud tier): the server already judged, so the prompt
// instructs the agent to apply each finding's fix, with location and fix text.
func TestBuildFindingsPrompt(t *testing.T) {
	prompt := promptNoDirective([]wire.Finding{{
		Rule:     "ssrf",
		Name:     "Server-Side Request Forgery", // server fills the human name
		Location: "app.py:4",
		Issue:    "URL fetched without validating it resolves to a public IP (`request.args`)",
		Fix:      "resolve and reject private ranges",
	}})
	// Grouped under the human rule NAME, then location + issue + fix. The backtick
	// in the issue must be stripped (the no-backtick assertion below verifies it).
	for _, want := range []string{"Server-Side Request Forgery", "app.py:4", "URL fetched without validating", "resolve and reject private ranges"} {
		if !strings.Contains(prompt, want) {
			t.Errorf("findings prompt missing %q", want)
		}
	}
	// The kebab rule ID must NOT appear (we show the name, not the ID).
	if strings.Contains(prompt, "ssrf") {
		t.Errorf("findings prompt leaks the rule ID:\n%s", prompt)
	}
	// No markdown: Claude Code renders the Stop re-wake as plain text, so backticks
	// would show literally to the developer. Keep the findings tick-free.
	if strings.Contains(prompt, "`") {
		t.Errorf("findings prompt must not contain backticks (they render literally):\n%s", prompt)
	}
}

// A finding that marks a SPAN names the whole construct in the re-wake and in the
// developer's notice, and the two must SPELL IT THE SAME WAY: they render on the same
// screen about the same finding, so two spellings read as two findings. One helper,
// asserted through both entry points.
//
// The separator is a plain HYPHEN. This text reaches a terminal and an agent that may
// echo it back, and a range spelled with an en dash is one a developer cannot type and
// cannot grep for.
func TestFindingSpanRendersAsARangeInBothOutputs(t *testing.T) {
	f := wire.Finding{
		Rule: "ssrf", Name: "Server-Side Request Forgery",
		Location: "app.py:42", EndLine: 58, Issue: "unvalidated fetch", Fix: "resolve first",
	}
	prompt := promptNoDirective([]wire.Finding{f})
	if !strings.Contains(prompt, "app.py:42-58") {
		t.Errorf("re-wake must name the span:\n%s", prompt)
	}
	notice := FixStillVulnerableNotice([]wire.Finding{f})
	if !strings.Contains(notice, "app.py:42-58") {
		t.Errorf("notice must name the same span:\n%s", notice)
	}
	for _, s := range []string{prompt, notice} {
		if strings.Contains(s, "\u2013") || strings.Contains(s, "\u2014") {
			t.Errorf("a span must be a plain hyphen, never a dash a developer cannot type:\n%s", s)
		}
	}
	// No span ⇒ byte-identical to what a single-line finding always produced.
	plain := f
	plain.EndLine = 0
	if got := promptNoDirective([]wire.Finding{plain}); !strings.Contains(got, "app.py:42") || strings.Contains(got, "42-") {
		t.Errorf("a single-line finding must render unchanged:\n%s", got)
	}
}

// ⚠️ A LOCATION WITH NO TRAILING LINE NUMBER GETS NO RANGE, even when the server sent a
// span. The judge cites a symbol name when it was shown no numbered context, and
// "handler-58" would read as a line number that is not one — there is no start for the
// end to be relative to.
func TestFindingSpanIsNotAppendedToALocationWithoutALine(t *testing.T) {
	got := promptNoDirective([]wire.Finding{
		{Rule: "ssrf", Name: "SSRF", Location: "app.py:fetch_url", EndLine: 58, Issue: "i", Fix: "f"},
	})
	if strings.Contains(got, "58") {
		t.Errorf("an unnumbered location must not gain a range:\n%s", got)
	}
}

// TestBuildFindingsPrompt_SplitsPreexisting: introduced findings are force-fixed
// ("don't ask"); pre-existing ones are surfaced with an explicit "ask the developer,
// don't fix now" instruction. The two are clearly separated.
func TestBuildFindingsPrompt_SplitsPreexisting(t *testing.T) {
	prompt := promptNoDirective([]wire.Finding{
		{Rule: "ssrf", Name: "Server-Side Request Forgery", Location: "app.py:12", Issue: "new vuln", Fix: "resolve to IP"},
		{Rule: "open-redirect", Name: "Open Redirect", Location: "app.py:3", Issue: "old vuln", Fix: "allowlist", Preexisting: true},
	})
	fixIdx := strings.Index(prompt, "fix before finishing this turn")
	preIdx := strings.Index(prompt, "Pre-existing issues NOT introduced")
	if fixIdx < 0 || preIdx < 0 || fixIdx > preIdx {
		t.Fatalf("expected force-fix section before the pre-existing section:\n%s", prompt)
	}
	if !strings.Contains(prompt, "ask whether they want them fixed") {
		t.Errorf("pre-existing must instruct asking the developer:\n%s", prompt)
	}
	for _, want := range []string{"Server-Side Request Forgery", "Open Redirect", "app.py:12", "app.py:3"} {
		if !strings.Contains(prompt, want) {
			t.Errorf("prompt missing %q", want)
		}
	}
}

// TestBuildFindingsPrompt_NewlyReachedLabel: a pre-existing finding flagged
// NewlyReached gets the per-finding heads-up that the agent's new code routes into it —
// while staying in the surfaced (ask, don't force-fix) section.
func TestBuildFindingsPrompt_NewlyReachedLabel(t *testing.T) {
	prompt := promptNoDirective([]wire.Finding{
		{Rule: "ssrf", Name: "Server-Side Request Forgery", Location: "helpers.py:9", Issue: "old sink", Fix: "resolve", Preexisting: true, NewlyReached: true},
	})
	if strings.Contains(prompt, "fix before finishing this turn") {
		t.Errorf("a newly-reached pre-existing finding must still be surfaced, not force-fixed:\n%s", prompt)
	}
	if !strings.Contains(prompt, "routes into this existing vulnerable helper") {
		t.Errorf("newly-reached pre-existing finding must carry the heads-up label:\n%s", prompt)
	}
}

// TestBuildFindingsPrompt_PreexistingOnly: a clean change that only surfaces a
// pre-existing issue must NOT tell the agent to "fix before finishing" — it asks.
func TestBuildFindingsPrompt_PreexistingOnly(t *testing.T) {
	prompt := promptNoDirective([]wire.Finding{
		{Rule: "open-redirect", Name: "Open Redirect", Location: "app.py:3", Issue: "old", Fix: "allowlist", Preexisting: true},
	})
	if strings.Contains(prompt, "fix before finishing this turn") {
		t.Errorf("pre-existing-only must not force a fix:\n%s", prompt)
	}
	if !strings.HasPrefix(prompt, "🔒 LeoPrevent: security review") {
		t.Errorf("must keep the Codex marker prefix:\n%.40q", prompt)
	}
	if !strings.Contains(prompt, "ask whether") {
		t.Errorf("must ask the developer:\n%s", prompt)
	}
}

func TestBanner(t *testing.T) {
	if one := Banner(1); !strings.Contains(one, "1 file)") {
		t.Errorf("Banner(1) = %q, want singular", one)
	}
	many := Banner(3)
	if !strings.Contains(many, "3 files)") {
		t.Errorf("Banner(3) = %q, want plural", many)
	}
	if strings.Contains(many, "detected") || strings.Contains(many, "violation") {
		t.Errorf("banner %q must not claim detection", many)
	}
}

func TestRewakeJSONCarriesBanner(t *testing.T) {
	banner := Banner(2)
	out, err := RewakeJSON("review this", banner)
	if err != nil {
		t.Fatalf("RewakeJSON: %v", err)
	}
	var decoded struct {
		Decision      string `json:"decision"`
		Reason        string `json:"reason"`
		SystemMessage string `json:"systemMessage"`
	}
	if err := json.Unmarshal(out, &decoded); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	if decoded.Decision != "block" {
		t.Errorf("unexpected decision: %+v", decoded)
	}
	if !strings.Contains(decoded.Reason, "review this") {
		t.Errorf("reason missing prompt: %q", decoded.Reason)
	}
	if decoded.SystemMessage != banner {
		t.Errorf("systemMessage = %q, want banner %q", decoded.SystemMessage, banner)
	}
}

// TestBuildFindingsPrompt_SuggestOnly: a suggest-only finding (auto_fix:false rule)
// is surfaced for manual review and NEVER force-fixed — even when introduced this
// turn (no Preexisting flag). It must not land in the "fix before finishing" block.
func TestBuildFindingsPrompt_SuggestOnly(t *testing.T) {
	prompt := promptNoDirective([]wire.Finding{
		{Rule: "proxy-path-handling", Name: "Proxy Path Handling", Location: "nginx.conf:10", Issue: "alias traversal", Fix: "add trailing slash", SuggestOnly: true},
	})
	if strings.Contains(prompt, "fix before finishing this turn") {
		t.Errorf("suggest-only must not be force-fixed:\n%s", prompt)
	}
	// The PROPERTY, not the prose: this group is the developer's call and the agent is not
	// to fix it now. The old assertion was on "does NOT auto-apply", which was wording that
	// implied LeoPrevent edits code — see TestNoCopyClaimsLeoPreventEditsCode.
	if !strings.Contains(prompt, "for the developer to decide on") {
		t.Errorf("suggest-only must say it is the developer's decision:\n%s", prompt)
	}
	if !strings.Contains(prompt, "not for you to fix now") {
		t.Errorf("suggest-only must tell the agent not to fix it in-turn:\n%s", prompt)
	}
	if !strings.HasPrefix(prompt, "🔒 LeoPrevent: security review") {
		t.Errorf("must keep the Codex marker prefix:\n%.40q", prompt)
	}
	for _, want := range []string{"Proxy Path Handling", "nginx.conf:10"} {
		if !strings.Contains(prompt, want) {
			t.Errorf("prompt missing %q", want)
		}
	}
}

// TestBuildFindingsPrompt_SuggestOnlyWinsOverIntroduced: an introduced finding on a
// suggest-only rule is surfaced, not force-fixed; an introduced finding on a normal
// rule in the same batch is still force-fixed.
func TestBuildFindingsPrompt_SuggestOnlyWinsOverIntroduced(t *testing.T) {
	prompt := promptNoDirective([]wire.Finding{
		{Rule: "ssrf", Name: "Server-Side Request Forgery", Location: "app.py:12", Issue: "new vuln", Fix: "resolve to IP"},
		{Rule: "proxy-path-handling", Name: "Proxy Path Handling", Location: "nginx.conf:10", Issue: "alias traversal", Fix: "trailing slash", SuggestOnly: true},
	})
	fixIdx := strings.Index(prompt, "fix before finishing this turn")
	sugIdx := strings.Index(prompt, "for the developer to decide on")
	if fixIdx < 0 || sugIdx < 0 || fixIdx > sugIdx {
		t.Fatalf("expected force-fix section before the suggest-only section:\n%s", prompt)
	}
}

// TestReviewContextMessageNeverClaimsLeoPreventFixedIt pins the wording of the
// developer-facing notice: it reports what the REVIEW did, never a completed fix.
//
// The line renders under the "🔒 LeoPrevent" byline and is the FIRST thing in the
// agent's reply, so "and fixed 1 finding below" credited LeoPrevent with an edit
// it never makes and announced it before the agent had made it. An agent that
// then declines, defers or botches the force-fix leaves that claim standing with
// nothing later contradicting it, which is the one failure this notice exists to
// prevent. Mutation check: revert either verb and this test fails.
func TestReviewContextMessageNeverClaimsLeoPreventFixedIt(t *testing.T) {
	forceFix := wire.Finding{Rule: "ssrf", Location: "app.py:12"}
	surfaced := wire.Finding{Rule: "idor-object-level-authz", Location: "old.py:4", Preexisting: true}

	cases := []struct {
		name    string
		f       []wire.Finding
		want    string
		wantNot []string
	}{{
		name: "all force-fixed",
		f:    []wire.Finding{forceFix},
		want: "flagged 1 finding to fix",
	}, {
		name: "mixed",
		f:    []wire.Finding{forceFix, forceFix, surfaced},
		want: "flagged 2 findings to fix and surfaced 1 more for you to review",
	}, {
		name: "surfaced only",
		f:    []wire.Finding{surfaced},
		want: "raised 1 finding for you to review",
	}}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			msg := ReviewContextMessage(9, c.f, ForceFixedCount(c.f))
			if !strings.Contains(msg, c.want) {
				t.Errorf("want %q in:\n%s", c.want, msg)
			}
			// No branch may state the fix as already done.
			for _, bad := range []string{"and fixed ", ", fixed "} {
				if strings.Contains(msg, bad) {
					t.Errorf("notice claims LeoPrevent fixed it (%q); it only flags, the agent fixes:\n%s", bad, msg)
				}
			}
			if !strings.Contains(msg, "9 changed files") {
				t.Errorf("notice should state the reviewed file count:\n%s", msg)
			}
		})
	}
}
