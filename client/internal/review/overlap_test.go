package review

import (
	"strings"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/rulespec"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

// haPersonList is the shape of the miss in leobench-internal-results
// susvibes-stratified-codex-2026-10-01, home-assistant core dbfc5ea (CVE-2023-50715). A
// fix-now finding (debug-endpoint-exposure, a cross-user inventory behind no
// authorization gate) and a suggest-only one (excessive-pii-exposure) sat on the SAME
// view, about twenty lines apart. The agent fixed neither, replying: "Your review
// instructions also say these overlapping PII changes require developer approval, so I
// haven't changed the code further." The suggest-only paragraph forbade changing "this
// code", and the code was shared, so the stricter instruction won.
var haPersonList = []wire.Finding{
	{Rule: "debug-endpoint-exposure", Name: "Exposed Debug / Internal Endpoint",
		Location: "homeassistant/components/person/__init__.py:581",
		Issue:    "the endpoint returns every person behind only an is_local() check",
		Fix:      "require authentication and an admin permission"},
	{Rule: "excessive-pii-exposure", Name: "Excessive PII Exposure", SuggestOnly: true,
		Location: "homeassistant/components/person/__init__.py:602",
		Issue:    "returns names and pictures of every person",
		Fix:      "return only the fields the login page needs"},
}

// TestFixNowIsNeverBlockedByASuggestionOnTheSameCode: when both groups appear, the
// message must say a suggestion never holds back a fix above, and must not forbid
// changing the code itself (which the fix-now finding needs changed).
func TestFixNowIsNeverBlockedByASuggestionOnTheSameCode(t *testing.T) {
	got := promptNoDirective(haPersonList)
	if !strings.Contains(got, "fix before finishing this turn") {
		t.Fatalf("the fix-now finding must still be force-fixed:\n%s", got)
	}
	if strings.Contains(got, "do not change this code") {
		t.Errorf("the suggest-only prohibition must be on the suggested CHANGE, not on the code, because the code is shared with a fix-now finding:\n%s", got)
	}
	if !strings.Contains(got, "never holds back a fix above") {
		t.Errorf("with both groups present, the message must state that a suggestion never holds back a fix-now fix:\n%s", got)
	}
	if !strings.Contains(got, "leave out only the extra change suggested here") {
		t.Errorf("the message must say what to hold back: only the suggested extra change:\n%s", got)
	}
}

// TestSuggestionAloneHasNoPrecedenceSentence: with no fix-now group there is nothing to
// take precedence over, and the sentence would only be noise.
func TestSuggestionAloneHasNoPrecedenceSentence(t *testing.T) {
	got := promptNoDirective(haPersonList[1:])
	if strings.Contains(got, "never holds back a fix above") {
		t.Errorf("a suggest-only-only message must not mention fixes above:\n%s", got)
	}
	if !strings.Contains(got, "do not make that fix without their go-ahead") {
		t.Errorf("the suggest-only group must still be the developer's call:\n%s", got)
	}
}

// TestLocalTierSuggestOnlyNeverHoldsBackAnotherRulesFix: the local tier's output contract
// carries the same two properties, in parity with the cloud tier.
func TestLocalTierSuggestOnlyNeverHoldsBackAnotherRulesFix(t *testing.T) {
	got := BuildPrompt(ssrfChanges, []rulespec.Rule{ssrfRule}, metaPolicy)
	if strings.Contains(got, "do not change the code") {
		t.Errorf("the local tier must not forbid changing the code for a SUGGEST-ONLY rule:\n%s", got)
	}
	if !strings.Contains(got, "never holds back another rule's fix") {
		t.Errorf("the local tier must say a SUGGEST-ONLY rule never holds back another rule's fix:\n%s", got)
	}
}
