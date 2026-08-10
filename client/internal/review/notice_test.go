package review

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

func TestFixStillVulnerableNotice(t *testing.T) {
	msg := FixStillVulnerableNotice([]wire.Finding{
		{Rule: "ssrf", Name: "Server-Side Request Forgery", Location: "a.py:1", Issue: "blocklist still bypassable via DNS rebind", Fix: "resolve to IP and reject private ranges"},
		{Rule: "no-input-validation", Location: "b.py:2"}, // no Name → falls back to rule ID
	})
	for _, want := range []string{"still vulnerable", "Server-Side Request Forgery", "a.py:1", "no-input-validation", "b.py:2"} {
		if !strings.Contains(msg, want) {
			t.Errorf("notice missing %q: %s", want, msg)
		}
	}
	// The WHY (judge's issue) and the suggested fix must ride the notice — it's the
	// whole point: tell the agent why its fix is still vulnerable, not just where.
	for _, want := range []string{"blocklist still bypassable via DNS rebind", "resolve to IP and reject private ranges"} {
		if !strings.Contains(msg, want) {
			t.Errorf("notice missing the judge's reason/fix %q: %s", want, msg)
		}
	}
	// More than the cap → truncation marker, not a wall of findings.
	many := make([]wire.Finding, 5)
	for i := range many {
		many[i] = wire.Finding{Rule: "r", Location: "f"}
	}
	if !strings.Contains(FixStillVulnerableNotice(many), "…") {
		t.Error("over-cap notice should end with an ellipsis")
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
