package review

import "testing"

// ⚠️ THE GATE DECIDES WHETHER TO ASK, NEVER WHAT THE ANSWER IS, so it is deliberately
// over-broad: a false positive costs one short model call, a false negative loses a ticket
// nobody records. It also has to be a gate at all — `resolveLedger` runs on every ordinary
// turn while the ledger holds anything, so ungated this would re-classify the same carried
// findings on every turn of a long session.
func TestMentionsFollowUpOpensOnEitherSide(t *testing.T) {
	pass := [][2]string{
		// The developer's instruction is often the whole signal — the agent's reply on the
		// blocked turn predates the decision entirely.
		{"create an issue for that hardcoded secret", ""},
		{"raise a ticket for it", ""},
		{"", "Opened ENT-4585 for it. Leaving the code as it is."},
		{"", "Already ticketed, so no action."},
		{"", "Added it to the backlog."},
		{"", "This is tracked already."},
		// A proposal still opens the gate: the PROMPT is what the model judges.
		{"", "I'd lean toward a separate ticket for this."},
	}
	for _, c := range pass {
		if !MentionsFollowUp(c[0], c[1]) {
			t.Errorf("gate closed on prompt=%q reply=%q", c[0], c[1])
		}
	}

	skip := [][2]string{
		// ⚠️ The input guaranteed to be present on EVERY one of these turns: a security
		// finding's own prose. Without the technical-prefix denylist the gate opens on every
		// turn that carries a ledger, which is every turn this runs on.
		{"keep going", "The CWE-918 SSRF reaching RFC-1918 space is still open."},
		{"fix the tests", "Mitigates CVE-2021-44228 and the TLS-1 downgrade."},
		// Ordinary work, including work that names the tool.
		{"add a helper", "Fixed the LeoPrevent finding in forgotPassword."},
		{"keep going", "The hook flagged one pre-existing issue not introduced by this change."},
		{"", ""},
		{"   ", "   "},
	}
	for _, c := range skip {
		if MentionsFollowUp(c[0], c[1]) {
			t.Errorf("gate opened on prompt=%q reply=%q", c[0], c[1])
		}
	}
}
