package review

import (
	"strings"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

// Validation is scoped to fix-now findings. Appending it to every review would
// accidentally ask agents to remediate suggest-only or virtual code.
func TestFunctionalValidationIsScopedToIntroducedFixes(t *testing.T) {
	for _, tc := range []struct {
		name     string
		findings []wire.Finding
		want     bool
	}{
		{"introduced", []wire.Finding{introduced}, true},
		{"mixed", []wire.Finding{introduced, preexisting, suggestOnlyPre}, true},
		{"preexisting", []wire.Finding{preexisting}, false},
		{"suggest-only", []wire.Finding{suggestOnlyPre}, false},
		{"virtual", []wire.Finding{{Virtual: true, Location: "mcp:code"}}, false},
		{"clean", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := BuildFindingsPrompt(tc.findings, "SERVER DIRECTIVE")
			if strings.Contains(got, "temporarily revert your fix") != tc.want {
				t.Fatalf("functional validation scope is wrong: %s", got)
			}
			if tc.want {
				for _, requirement := range []string{
					"After fixing, run the existing tests",
					"only a test that passed before is a regression",
					"same untrusted input and exploit",
					"first try a narrower fix",
					"Do not leave a known functional regression",
					"Do not modify tests that existed before this turn",
					"a test you wrote this turn that asserts the vulnerable behaviour is part of the flaw",
					"exclude affected cases",
					"do not finish with them in place",
					"take out or rework the change that introduced the flaw",
					"do not claim functional validation",
				} {
					if !strings.Contains(got, requirement) {
						t.Errorf("missing validation boundary %q", requirement)
					}
				}
				// Introduced flaws are force-fixed: the pre-existing escape hatch (undo the
				// remediation, leave the flaw, report it unresolved) must never reach them.
				for _, banned := range []string{
					"undo only your remediation edits",
					"report the finding as unresolved",
					"Apply each directly",
				} {
					if strings.Contains(got, banned) {
						t.Errorf("introduced-finding prompt must not say %q", banned)
					}
				}
				// The developer reads this text too: the findings come first, the procedure after.
				if strings.Index(got, "After fixing, run") < strings.Index(got, introduced.Location) {
					t.Error("validation must follow the introduced findings")
				}
				// Tests run once, after the fix; a before-run only on a failure (LEO-693).
				for _, banned := range []string{"Before editing", "establish a baseline"} {
					if strings.Contains(got, banned) {
						t.Errorf("prompt must not ask for an up-front test run: found %q", banned)
					}
				}
			}
		})
	}
}
