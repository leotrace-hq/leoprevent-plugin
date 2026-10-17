package review

import (
	"strings"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

const relocationLine = "Removing the flaw is the fix; relocating it is not."

// LEO-409: an agent can satisfy a finding by MOVING the sink rather than removing it,
// and that is available on every taint-based rule, not a quirk of one. Measured on
// LEO-405: told about eval-injection, an agent deleted eval() and wrote the same
// request body to a temp file, then include'd it. Identically exploitable.
//
// The line belongs on the fix-now branch, where a fix is actually being asked for.
func TestRelocationLineIsOnTheFixNowBranchOnly(t *testing.T) {
	t.Run("present when a fix is demanded", func(t *testing.T) {
		got := promptNoDirective([]wire.Finding{
			{Rule: "eval-injection", Name: "Code / Eval Injection", Location: "a.php:2", Issue: "eval of request body", Fix: "reject the input"},
		})
		if !strings.Contains(got, relocationLine) {
			t.Fatalf("fix-now review must say relocating is not fixing:\n%s", got)
		}
		if strings.Index(got, relocationLine) < strings.Index(got, "fix before finishing this turn") {
			t.Error("the line must follow the fix-now header, not precede it")
		}
	})

	// Meaningless where no fix is being asked for, and this text is prepended to every
	// review, so it does not go anywhere it does not earn.
	t.Run("absent when nothing is to be fixed now", func(t *testing.T) {
		suggest := promptNoDirective([]wire.Finding{
			{Rule: "no-input-validation", Name: "Missing Input Validation", Location: "b.php:9", Issue: "unvalidated", Fix: "validate", SuggestOnly: true},
		})
		if strings.Contains(suggest, relocationLine) {
			t.Error("suggest-only review asks for no fix; the line does not belong")
		}
		pre := promptNoDirective([]wire.Finding{
			{Rule: "ssrf", Name: "Server-Side Request Forgery", Location: "c.py:3", Issue: "old", Fix: "allowlist", Preexisting: true},
		})
		if strings.Contains(pre, relocationLine) {
			t.Error("pre-existing findings are not force-fixed; the line does not belong")
		}
		if strings.Contains(promptNoDirective(nil), relocationLine) {
			t.Error("a clean review must carry no fix instructions")
		}
	})
}

// The adapters-in-parity rule applies to copy too: an agent on the local tier can
// relocate a sink just as cheaply, and would otherwise never be told it does not count.
func TestLocalTierCarriesTheSameInstruction(t *testing.T) {
	if got := BuildPrompt(nil, nil, ""); !strings.Contains(got, relocationLine) {
		t.Errorf("local tier output contract must match the cloud tier:\n%s", got)
	}
}
