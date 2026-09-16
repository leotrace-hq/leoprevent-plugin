package transcript

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// copilotTranscript is a trimmed but structurally faithful Copilot transcript, taken from a
// real VS Code session that blocked and remediated
// (workspaceStorage/<wsHash>/GitHub.copilot-chat/transcripts/9bee3c66-….jsonl, 56 records).
//
// The shape that matters: the session carries exactly ONE user.message — the developer's own
// prompt — and NO record of our injected re-wake. The only thing separating the pre-block
// commentary from the reply is the clock, which is why the parser is anchored on a timestamp.
// The 23-second gap between the last turn_end and the next turn_start is our review running.
const copilotTranscript = `{"type":"session.start","timestamp":"2026-08-21T10:45:30.280Z"}
{"type":"user.message","data":{"content":"Update this file to have a different planted vulnerability"},"timestamp":"2026-08-21T10:45:30.280Z"}
{"type":"assistant.message","data":{"messageId":"m1","content":"I'll inspect the current scratch test and the repo's workflow.","toolRequests":[{"name":"read_file","arguments":"{\"filePath\":\"/x/y.ts\"}"}]},"timestamp":"2026-08-21T10:45:34.261Z"}
{"type":"assistant.turn_end","timestamp":"2026-08-21T10:45:34.261Z"}
{"type":"tool.execution_start","data":{"name":"apply_patch"},"timestamp":"2026-08-21T10:47:14.400Z"}
{"type":"assistant.message","data":{"messageId":"m2","content":"Updated scratch-leoprevent-test.ts with a different planted vulnerability."},"timestamp":"2026-08-21T10:47:14.448Z"}
{"type":"assistant.turn_end","timestamp":"2026-08-21T10:47:14.448Z"}
{"type":"assistant.turn_start","timestamp":"2026-08-21T10:47:37.591Z"}
{"type":"assistant.message","data":{"messageId":"m3","content":"I'll apply the hook's requested remediation directly in the scratch file."},"timestamp":"2026-08-21T10:47:43.205Z"}
{"type":"assistant.message","data":{"messageId":"m4","content":"","toolRequests":[{"name":"apply_patch","arguments":"{\"patch\":\"@@ big body @@\"}"}]},"timestamp":"2026-08-21T10:47:45.205Z"}
{"type":"assistant.message","data":{"messageId":"m5","content":"Applied the remediation: strict validation, path containment, spawn with argument separation."},"timestamp":"2026-08-21T10:47:49.855Z"}
{"type":"assistant.turn_end","timestamp":"2026-08-21T10:47:49.855Z"}
`

// blockedAt is when the Stop hook delivered the block on that session: after m2 (the agent's
// own sign-off, which the first Stop followed) and before the re-wake's turn_start.
var blockedAt = time.Date(2026, 8, 21, 10, 47, 30, 0, time.UTC)

func writeCopilotTranscript(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "transcript.jsonl")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestParseCopilotAgentReplyTakesOnlyThePostBlockProse is the whole point of the anchor: the
// reply is what the agent said AFTER we spoke. It fails against a parser that returns the
// turn's prose without a boundary, which is the tempting shortcut given Copilot logs no
// re-wake message.
func TestParseCopilotAgentReplyTakesOnlyThePostBlockProse(t *testing.T) {
	got, err := ParseCopilotAgentReply(writeCopilotTranscript(t, copilotTranscript), blockedAt)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"requested remediation", "argument separation"} {
		if !strings.Contains(got, want) {
			t.Errorf("post-block prose %q missing from reply:\n%s", want, got)
		}
	}
	// The agent narrating its own work BEFORE it was shown a finding. Shipping this as
	// agent_response would put words in its mouth about a review it had not yet seen.
	for _, unwanted := range []string{"I'll inspect", "different planted vulnerability"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("pre-block commentary %q leaked into the reply:\n%s", unwanted, got)
		}
	}
	// Two messages, one blank line apart — assistantTextAfter's joining, so the two
	// parsers in this package read the same on a multi-message reply.
	if strings.Count(got, "\n\n") != 1 {
		t.Errorf("want the two post-block messages joined by one blank line, got:\n%q", got)
	}
}

// TestParseCopilotAgentReplyWithoutAnAnchorYieldsNothing pins the fail-open direction. A zero
// `since` means we do not know when we spoke, and a reply we cannot bound is a guess — the
// caller falls back to last_assistant_message instead.
func TestParseCopilotAgentReplyWithoutAnAnchorYieldsNothing(t *testing.T) {
	p := writeCopilotTranscript(t, copilotTranscript)
	got, err := ParseCopilotAgentReply(p, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if got != "" {
		t.Errorf("no anchor must yield no reply, got %q", got)
	}
	if got, err := ParseCopilotAgentReply("", blockedAt); err != nil || got != "" {
		t.Errorf("no transcript path must yield no reply, got %q / %v", got, err)
	}
}

// TestParseCopilotAgentReplyReadsProseOnly: a tool-call-only message contributes nothing, and
// neither do the non-message records. The tool arguments carry whole file bodies — already
// captured as the before/after code — so letting them through would swamp the prose and blow
// the reply cap on a large patch.
func TestParseCopilotAgentReplyReadsProseOnly(t *testing.T) {
	got, err := ParseCopilotAgentReply(writeCopilotTranscript(t, copilotTranscript), blockedAt)
	if err != nil {
		t.Fatal(err)
	}
	for _, unwanted := range []string{"apply_patch", "big body", "turn_start", "tool.execution"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("%q must not reach the reply:\n%s", unwanted, got)
		}
	}
}

// TestParseCopilotAgentReplySurvivesAMalformedFile: an undocumented internal format has to be
// read defensively. A garbled line, an unknown record type and a record with no usable
// timestamp are each skipped rather than aborting the parse — an untimestamped record cannot be
// placed on either side of the block, so it is dropped rather than guessed at.
func TestParseCopilotAgentReplySurvivesAMalformedFile(t *testing.T) {
	body := `not json at all
{"type":"assistant.message","data":{"messageId":"undated","content":"no timestamp here"}}
{"type":"assistant.message","data":{"messageId":"bad","content":"unparseable stamp"},"timestamp":"yesterday"}
{"type":"future.record.type","timestamp":"2026-08-21T10:47:44Z"}
{"type":"assistant.message","data":{"messageId":"good","content":"the real reply"},"timestamp":"2026-08-21T10:47:45Z"}
`
	got, err := ParseCopilotAgentReply(writeCopilotTranscript(t, body), blockedAt)
	if err != nil {
		t.Fatal(err)
	}
	if got != "the real reply" {
		t.Errorf("want just the well-formed post-block message, got %q", got)
	}
}

// TestParseCopilotAgentReplyDedupesLastWins: if a message id ever repeats, a partial is a
// PREFIX of the final, so first-wins would ship a half-written sentence and keeping both would
// ship the reply twice. Same resolution as assistantTextAfter. Copilot was not observed to
// repeat an id, so this pins the insurance rather than a fix.
func TestParseCopilotAgentReplyDedupesLastWins(t *testing.T) {
	body := `{"type":"assistant.message","data":{"messageId":"m","content":"This is a par"},"timestamp":"2026-08-21T10:47:45Z"}
{"type":"assistant.message","data":{"messageId":"m","content":"This is a partial, then the whole thing."},"timestamp":"2026-08-21T10:47:46Z"}
`
	got, err := ParseCopilotAgentReply(writeCopilotTranscript(t, body), blockedAt)
	if err != nil {
		t.Fatal(err)
	}
	if got != "This is a partial, then the whole thing." {
		t.Errorf("want the last copy only, got %q", got)
	}
}

// TestParseCopilotAgentReplyMissingFileErrors: the engine logs an unreadable transcript and
// falls back, so the error has to REACH it rather than being swallowed into an empty reply —
// the two are the same to the developer but not to whoever reads the plugin log.
func TestParseCopilotAgentReplyMissingFileErrors(t *testing.T) {
	got, err := ParseCopilotAgentReply(filepath.Join(t.TempDir(), "gone.jsonl"), blockedAt)
	if err == nil {
		t.Error("an unreadable transcript must report its error for the plugin log")
	}
	if got != "" {
		t.Errorf("want no reply on a read failure, got %q", got)
	}
}
