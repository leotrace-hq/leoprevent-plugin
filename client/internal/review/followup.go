package review

import (
	"regexp"
	"strings"
)

// followUpWords and followUpKey gate the reasons-only resolution call: they decide whether
// a turn's words are worth asking the server to classify, when NO flagged file changed.
//
// ⚠️ THEY DECIDE WHETHER TO LOOK, NEVER WHAT THE ANSWER IS. The server's judge model is the
// only thing that says a ticket exists — these are deliberately over-broad, because the cost
// of a false positive is one short model call and the cost of a false negative is a ticket
// nobody ever records. A miss is the under-claiming direction, like every other residue here.
//
// ⚠️ AND A GATE IS REQUIRED, not an optimisation. `resolveLedger` runs on every ordinary turn
// while the ledger holds anything (6h TTL), so an ungated call would classify the same carried
// findings again on every turn of a long session.
var (
	followUpWords = regexp.MustCompile(`(?i)ticket|jira|backlog|kanban|\bsprint\b|track(ed|ing)\b|(open|file|creat|rais|log)\w*\s+(a\s+|an\s+)?(follow[- ]?up\s+)?(issue|card|ticket)`)
	// An issue KEY (ENT-4585, SEC-412). Case-SENSITIVE, letters then digits, which is what
	// keeps a branch name, a chapter range and a regex class out. RE2 has no look-around, so
	// the technical-prefix denylist below is applied in code.
	followUpKey = regexp.MustCompile(`\b[A-Z]{2,6}-\d{1,6}\b`)
)

// notAKey are prefixes that LOOK like an issue key and never are. Without them a security
// finding's own prose ("a CWE-918 SSRF in RFC-1918 space") opens the gate on every turn that
// carries a ledger — which is every turn this runs on.
var notAKey = map[string]bool{
	"CWE": true, "CVE": true, "RFC": true, "ISO": true, "UTF": true, "SHA": true,
	"AES": true, "RSA": true, "TLS": true, "SSL": true, "HTTP": true, "IPV": true,
}

// MentionsFollowUp reports whether the developer's instruction or the agent's reply suggests
// a follow-up was arranged this turn, and so whether the carried findings are worth
// classifying. See followUpWords.
func MentionsFollowUp(prompt, reply string) bool {
	for _, s := range []string{prompt, reply} {
		if strings.TrimSpace(s) == "" {
			continue
		}
		if followUpWords.MatchString(s) {
			return true
		}
		for _, m := range followUpKey.FindAllString(s, -1) {
			if p, _, ok := strings.Cut(m, "-"); ok && !notAKey[p] {
				return true
			}
		}
	}
	return false
}
