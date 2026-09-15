package review

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

func TestFixStillVulnerableNotice(t *testing.T) {
	msg := FixStillVulnerableNotice([]wire.Finding{
		{Rule: "ssrf", Name: "Server-Side Request Forgery", Location: "a.py:1", Issue: "blocklist still bypassable via DNS rebind", Fix: "resolve to IP and reject private ranges"},
		{Rule: "no-input-validation", Location: "b.py:2"}, // no Name -> falls back to rule ID
	})
	for _, want := range []string{"still vulnerable", "2 findings", "Server-Side Request Forgery", "a.py:1", "no-input-validation", "b.py:2"} {
		if !strings.Contains(msg, want) {
			t.Errorf("notice missing %q: %s", want, msg)
		}
	}
}

// The notice must NOT carry the judge's prose when there is more than one finding
// (LEO-120). Claude Code prefixes EVERY line of a systemMessage with "Stop says: ", so
// the old version's per-finding issue + fix rendered ~40 labelled lines and was unusable.
// This test fails against that code, on both the fix prose and the line count.
func TestFixStillVulnerableNoticeStaysShortWithSeveralFindings(t *testing.T) {
	msg := FixStillVulnerableNotice([]wire.Finding{
		{Rule: "nosql-injection", Name: "NoSQL Injection", Location: "docstore.js:28",
			Issue: "req.body.filter is passed directly as the MongoDB query filter",
			Fix:   "Validate that req.body.filter is a plain object whose values are all scalar types"},
		{Rule: "nosql-injection", Name: "NoSQL Injection", Location: "docstore.js:35",
			Issue: "req.body.email is passed directly to users.findOne()",
			Fix:   "assert that both req.body.email and req.body.password are strings"},
		{Rule: "xxe", Name: "XML External Entities", Location: "docstore.js:61",
			Issue: "parseXml is called with dtdload:true",
			Fix:   "Remove dtdload:true and replaceEntities:true from the options object"},
	})
	// The FIX prose never appears: the agent already had it verbatim in the re-wake, and
	// half a fix recipe is worse than none.
	for _, unwanted := range []string{"Validate that", "assert that", "Remove dtdload"} {
		if strings.Contains(msg, unwanted) {
			t.Errorf("notice must not carry the fix prose (%q): %s", unwanted, msg)
		}
	}
	// Nor the issue prose: with several findings there is no room to explain each.
	if strings.Contains(msg, "MongoDB query filter") {
		t.Errorf("notice must not carry per-finding issue prose with >1 finding: %s", msg)
	}
	// Two locations of ONE rule read as one line, so three findings are two rule lines
	// plus the headline and the non-blocking footer.
	if got, want := strings.Count(msg, "\n")+1, 4; got != want {
		t.Errorf("notice is %d lines, want %d (every line is prefixed with the hook label):\n%s", got, want, msg)
	}
	if !strings.Contains(msg, "NoSQL Injection: docstore.js:28, docstore.js:35") {
		t.Errorf("locations of one rule should be grouped onto its line: %s", msg)
	}
}

// A SINGLE finding is the one case with room to say why, so it says why: the ticket's
// "chevron to read more" in a surface that has no chevron. The issue only, never the fix.
func TestFixStillVulnerableNoticeExplainsASingleFinding(t *testing.T) {
	msg := FixStillVulnerableNotice([]wire.Finding{{
		Rule: "ssrf", Name: "Server-Side Request Forgery", Location: "fetch.py:12",
		Issue: "the `blocklist` is still bypassable via DNS rebinding. A resolved address is never re-checked",
		Fix:   "resolve the hostname to an IP and reject private ranges",
	}})
	if !strings.Contains(msg, "1 finding") || strings.Contains(msg, "1 findings") {
		t.Errorf("headline should read \"1 finding\": %s", msg)
	}
	if !strings.Contains(msg, "why: the blocklist is still bypassable via DNS rebinding.") {
		t.Errorf("single finding should carry the first sentence of the issue, backticks stripped: %s", msg)
	}
	// First sentence ONLY, and still no fix recipe.
	if strings.Contains(msg, "never re-checked") {
		t.Errorf("only the FIRST sentence of the issue belongs in the notice: %s", msg)
	}
	if strings.Contains(msg, "reject private ranges") {
		t.Errorf("the fix recipe must stay out of the notice: %s", msg)
	}

	// Prose with no sentence end falls back to a hard cut, which must land on a word
	// boundary: the judge writes JSON fragments and expressions, and a dangling
	// half-token on a one-line alert reads as a rendering bug. The cap falls inside
	// "unvalidated" here, so the old rune-cut would have emitted "unvalid…".
	issue := strings.Repeat("the handler forwards it on, ", 5) + "then queries with an unvalidated operator object"
	long := FixStillVulnerableNotice([]wire.Finding{{
		Rule: "nosql-injection", Name: "NoSQL Injection", Location: "d.js:28", Issue: issue,
	}})
	cut, ok := lineAfter(long, "  why: ")
	if !ok || !strings.HasSuffix(cut, "…") {
		t.Fatalf("expected a truncated why line, got %q", cut)
	}
	// What survives must be a prefix of the issue that stops where a word ends.
	kept := strings.TrimSuffix(cut, "…")
	rest, isPrefix := strings.CutPrefix(issue, kept)
	if !isPrefix {
		t.Fatalf("truncated why is not a prefix of the issue: %q", kept)
	}
	if rest != "" && !strings.HasPrefix(rest, " ") {
		t.Errorf("truncation split a token: %q ends mid-word (next: %q)", kept, rest[:min(12, len(rest))])
	}
}

// lineAfter returns the remainder of the line introduced by prefix.
func lineAfter(msg, prefix string) (string, bool) {
	for _, line := range strings.Split(msg, "\n") {
		if after, ok := strings.CutPrefix(line, prefix); ok {
			return after, true
		}
	}
	return "", false
}

// However many findings arrive, the notice stays a handful of lines: the rule groups are
// capped, each group's locations are capped, and BOTH remainders are stated as a COUNT.
// A bare ellipsis (what the old code emitted) tells the developer nothing about how much
// was hidden.
func TestFixStillVulnerableNoticeBoundsEverything(t *testing.T) {
	var many []wire.Finding
	for i := 0; i < 20; i++ {
		many = append(many, wire.Finding{Rule: "r" + strconv.Itoa(i), Name: "Rule " + strconv.Itoa(i), Location: "f.go:" + strconv.Itoa(i)})
	}
	msg := FixStillVulnerableNotice(many)
	if got := strings.Count(msg, "\n") + 1; got > 8 {
		t.Errorf("notice is %d lines for 20 findings, want a handful:\n%s", got, msg)
	}
	if !strings.Contains(msg, "16 more rules") {
		t.Errorf("the hidden remainder must be stated as a count, not an ellipsis: %s", msg)
	}

	// Many locations under ONE rule: the line names a few and counts the rest.
	same := make([]wire.Finding, 9)
	for i := range same {
		same[i] = wire.Finding{Rule: "xss", Name: "Cross-Site Scripting", Location: "t.js:" + strconv.Itoa(i)}
	}
	msg = FixStillVulnerableNotice(same)
	if !strings.Contains(msg, "(+6 more)") {
		t.Errorf("over-cap locations should be counted on the rule line: %s", msg)
	}
	if got, want := strings.Count(msg, "\n")+1, 3; got != want {
		t.Errorf("one rule over many locations is %d lines, want %d:\n%s", got, want, msg)
	}
}

// NoticeJSON must be NON-BLOCKING: a systemMessage with NO decision field, so the
// developer sees it but the stop proceeds (fail-open). A leaked "decision" here
// would trap the developer on the outage path — the exact opposite of the intent.
func TestNoticeJSONIsNonBlocking(t *testing.T) {
	out, err := NoticeJSON("⚠️ heads up")
	if err != nil {
		t.Fatalf("NoticeJSON: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := m["decision"]; ok {
		t.Errorf("notice must NOT carry a decision (would block); got %s", out)
	}
	if _, ok := m["reason"]; ok {
		t.Errorf("notice must NOT carry a reason; got %s", out)
	}
	if m["systemMessage"] != "⚠️ heads up" {
		t.Errorf("systemMessage = %v, want the message", m["systemMessage"])
	}
}

// Every classified reason must map to a distinct, non-empty notice that names the
// reason — a developer reading it should know whether to check the server or their
// license. SkipUnknown falls back to a generic line.
func TestSkipNoticePerReason(t *testing.T) {
	cases := map[SkipReason]string{
		SkipUnreachable:   "reach",
		SkipUnauthorized:  "license",
		SkipServerError:   "server",
		SkipMisconfigured: "misconfigured",
		SkipUnknown:       "unavailable",
	}
	seen := map[string]bool{}
	for reason, want := range cases {
		got := SkipNotice(reason)
		if got == "" {
			t.Errorf("%v: empty notice", reason)
		}
		if !strings.Contains(strings.ToLower(got), want) {
			t.Errorf("%v: notice %q does not mention %q", reason, got, want)
		}
		if !strings.Contains(got, "NOT") {
			t.Errorf("%v: notice should make clear the turn was NOT reviewed: %q", reason, got)
		}
		seen[got] = true
	}
	if len(seen) != len(cases) {
		t.Errorf("notices are not distinct across reasons: %d unique of %d", len(seen), len(cases))
	}
}

// SkipError unwraps to its cause so callers keep the full error for logging while
// classifying on Reason.
func TestSkipErrorUnwraps(t *testing.T) {
	cause := errors.New("apiclient: POST /review: status 401")
	se := &SkipError{Reason: SkipUnauthorized, Err: cause}
	if !errors.Is(se, cause) {
		t.Errorf("SkipError should unwrap to its cause")
	}
	if se.Error() != cause.Error() {
		t.Errorf("Error() = %q, want the cause %q", se.Error(), cause.Error())
	}
	// A reason-only SkipError still has a readable message.
	if (&SkipError{Reason: SkipUnreachable}).Error() == "" {
		t.Errorf("reason-only SkipError must have a message")
	}
}

// The update nag must reach BOTH surfaces: a verbatim systemMessage for the
// terminal, and injected turn context so the agent restates it on surfaces that
// never receive a systemMessage (desktop app / web UI). It must still not block.
func TestPromptNoticeJSONCarriesBothChannels(t *testing.T) {
	out, err := PromptNoticeJSON("⚠️  LeoPrevent 9.9.9 is available", "tell the developer")
	if err != nil {
		t.Fatalf("PromptNoticeJSON: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, k := range []string{"decision", "reason"} {
		if _, ok := m[k]; ok {
			t.Errorf("prompt notice must NOT carry %q (would block the prompt); got %s", k, out)
		}
	}
	if m["systemMessage"] != "⚠️  LeoPrevent 9.9.9 is available" {
		t.Errorf("systemMessage = %v, want the verbatim message", m["systemMessage"])
	}
	hso, ok := m["hookSpecificOutput"].(map[string]any)
	if !ok {
		t.Fatalf("missing hookSpecificOutput (the only channel the app/web UI receives); got %s", out)
	}
	if hso["hookEventName"] != "UserPromptSubmit" {
		t.Errorf("hookEventName = %v, want UserPromptSubmit", hso["hookEventName"])
	}
	if hso["additionalContext"] != "tell the developer" {
		t.Errorf("additionalContext = %v, want the injected context", hso["additionalContext"])
	}
}
