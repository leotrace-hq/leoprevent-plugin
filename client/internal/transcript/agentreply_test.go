package transcript

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/limits"
)

// The reply capture: the assistant prose AFTER the re-wake, not the turn's last
// assistant message.
//
// The bug these pin was invisible in the client and only showed up on a dashboard:
// `agent_response` carried a trailing sign-off ("PR #124 is unchanged and still
// green — say the word if you'd rather I…") while the reasoning that decided the
// outcome sat in an earlier assistant message of the same turn. Anything asserting
// a boundary here should read as "what does getting this wrong cost".

func writeReplyJSONL(t *testing.T, lines ...string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "transcript.jsonl")
	if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const (
	replyUserMsg   = `{"type":"user","message":{"role":"user","content":"add a fetch helper"}}`
	replyRewakeMsg = `{"type":"user","message":{"role":"user","content":"Stop hook feedback:\n🔒 LeoPrevent: security review — ssrf"}}`
)

func replyAsst(id, text string) string {
	return `{"type":"assistant","message":{"id":"` + id + `","role":"assistant","content":[{"type":"text","text":"` + text + `"}]}}`
}

func TestReplyIsEveryMessageAfterTheRewake(t *testing.T) {
	// THE REGRESSION. Three assistant messages follow the re-wake because the agent
	// reasoned, ran tools, then signed off. last_assistant_message is the third one
	// alone — which is the sentence that carries the least information about the
	// outcome being scored.
	p := writeReplyJSONL(t,
		replyUserMsg,
		replyAsst("m1", "Working on it."),
		replyRewakeMsg,
		replyAsst("m2", "This is a false positive: the URL is a hardcoded constant."),
		`{"type":"assistant","message":{"id":"m3","role":"assistant","content":[{"type":"tool_use","name":"Read","input":{"file_path":"a.py"}}]}}`,
		replyAsst("m4", "Left as-is. Say the word if you disagree."),
	)

	got, err := ParseAgentReply(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "false positive") {
		t.Errorf("the reasoning was dropped — this is the whole bug:\n%q", got)
	}
	if !strings.Contains(got, "Say the word") {
		t.Errorf("the sign-off should still be there, just not alone:\n%q", got)
	}
	// Text BEFORE the re-wake is the agent talking about its own work, not a response
	// to us. Including it would put an unrelated status line in the tuning signal.
	if strings.Contains(got, "Working on it") {
		t.Errorf("pre-re-wake text leaked into the reply:\n%q", got)
	}
}

func TestToolUseBlocksAreNotProse(t *testing.T) {
	// A tool_use block is the agent's ACTION — already captured as the before/after
	// code. Its input (a whole file body, a patch) would swamp the prose it is
	// supposed to sit beside.
	p := writeReplyJSONL(t, replyUserMsg, replyRewakeMsg,
		`{"type":"assistant","message":{"id":"m1","role":"assistant","content":[{"type":"tool_use","name":"Edit","input":{"file_path":"a.py","new_string":"SECRET_SAUCE"}}]}}`,
		replyAsst("m2", "Fixed."),
	)

	got, err := ParseAgentReply(p)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "SECRET_SAUCE") {
		t.Errorf("tool input leaked into the reply: %q", got)
	}
	if got != "Fixed." {
		t.Errorf("got %q, want just the prose", got)
	}
}

func TestDuplicateMessagesResolveToTheFinalCopy(t *testing.T) {
	// Claude logs one assistant message several times under a single id — streamed
	// partials, then the final. ParseTurnMeta keeps the FIRST (every copy carries the
	// same token counts); text needs the opposite, because a partial is a PREFIX.
	// First-wins would ship a half-written sentence; keeping every copy would ship the
	// reply three times over.
	p := writeReplyJSONL(t, replyUserMsg, replyRewakeMsg,
		replyAsst("m1", "This is a fal"),
		replyAsst("m1", "This is a false posi"),
		replyAsst("m1", "This is a false positive."),
	)

	got, err := ParseAgentReply(p)
	if err != nil {
		t.Fatal(err)
	}
	if got != "This is a false positive." {
		t.Errorf("got %q, want the final copy exactly once", got)
	}
}

func TestTheLastRewakeWins(t *testing.T) {
	// A turn can be blocked more than once. Only the most recent re-wake is the one
	// this outcome is scoring, so an earlier round's reply must not be folded in.
	p := writeReplyJSONL(t, replyUserMsg,
		replyRewakeMsg,
		replyAsst("m1", "First attempt at the fix."),
		replyRewakeMsg,
		replyAsst("m2", "Second attempt, now with a resolve-to-IP check."),
	)

	got, err := ParseAgentReply(p)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "First attempt") {
		t.Errorf("an earlier round's reply leaked in: %q", got)
	}
	if !strings.Contains(got, "Second attempt") {
		t.Errorf("the latest round's reply is missing: %q", got)
	}
}

func TestNoRewakeYieldsEmptySoTheCallerFallsBack(t *testing.T) {
	// "" is the miss signal the engine turns back into last_assistant_message. An
	// error would be wrong — a transcript with no block in it is a normal state.
	p := writeReplyJSONL(t, replyUserMsg, replyAsst("m1", "All done."))

	got, err := ParseAgentReply(p)
	if err != nil {
		t.Fatal(err)
	}
	if got != "" {
		t.Errorf("got %q, want empty so the engine falls back", got)
	}
}

func TestUnreadableTranscriptErrorsRatherThanLying(t *testing.T) {
	// The engine treats an error the same as a miss, but the error has to reach it —
	// silently returning "" would make a broken read indistinguishable from a turn
	// that was never blocked.
	if _, err := ParseAgentReply(filepath.Join(t.TempDir(), "nope.jsonl")); err == nil {
		t.Error("want an error for a missing transcript")
	}
}

func TestGarbledLinesDoNotAbortTheParse(t *testing.T) {
	// The transcript is a live file written by another process; one unparseable line
	// must not cost the whole reply.
	p := writeReplyJSONL(t, replyUserMsg, replyRewakeMsg, "{not json", replyAsst("m1", "Fixed it."))

	got, err := ParseAgentReply(p)
	if err != nil {
		t.Fatal(err)
	}
	if got != "Fixed it." {
		t.Errorf("got %q, want the reply despite the garbled line", got)
	}
}

func TestReplyIsCapped(t *testing.T) {
	// It is a body that egresses and is persisted, and since it became a whole segment
	// rather than one message its length is the agent's to choose.
	long := strings.Repeat("a", limits.MaxAgentReplyBytes+5000)
	p := writeReplyJSONL(t, replyUserMsg, replyRewakeMsg, replyAsst("m1", long))

	got, err := ParseAgentReply(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) > limits.MaxAgentReplyBytes+len("…[truncated]") {
		t.Errorf("got %d bytes, want <= the cap plus the marker", len(got))
	}
	if !strings.HasSuffix(got, "…[truncated]") {
		t.Error("truncation must be visible, not silent")
	}
}

func TestCapNeverSplitsARune(t *testing.T) {
	// A cut mid-rune yields invalid UTF-8, which JSON encoding then mangles into
	// replacement characters partway through a sentence.
	got := capReply(strings.Repeat("ä", limits.MaxAgentReplyBytes)) // 2 bytes per rune
	if !strings.HasSuffix(got, "…[truncated]") {
		t.Fatal("expected truncation")
	}
	body := strings.TrimSuffix(got, "…[truncated]")
	for _, r := range body {
		if r == '�' {
			t.Fatal("cut mid-rune")
		}
	}
}

func TestCodexReplyUsesItsOwnRewakeMarker(t *testing.T) {
	// Parity with Claude, different boundary: Codex surfaces a block as a plain user
	// message carrying our review text, with no "Stop hook feedback:" prefix. Reusing
	// Claude's marker here would find nothing and silently fall back forever.
	p := writeReplyJSONL(t,
		`{"type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"add a fetch helper"}]}}`,
		`{"type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"Working on it."}]}}`,
		`{"type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"`+reWakeMarker+` — ssrf"}]}}`,
		`{"type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"Resolved the host to an IP first."}]}}`,
	)

	got, err := ParseCodexAgentReply(p)
	if err != nil {
		t.Fatal(err)
	}
	if got != "Resolved the host to an IP first." {
		t.Errorf("got %q, want only the post-re-wake assistant text", got)
	}
}

func TestCodexNoRewakeYieldsEmpty(t *testing.T) {
	p := writeReplyJSONL(t,
		`{"type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"hello"}]}}`,
		`{"type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"hi"}]}}`,
	)

	got, err := ParseCodexAgentReply(p)
	if err != nil {
		t.Fatal(err)
	}
	if got != "" {
		t.Errorf("got %q, want empty so the engine falls back", got)
	}
}

// The marker each parser keys on is the SAME string its turn-start test already
// refuses, so the two can never disagree about what an injection looks like.
func TestMarkersMatchTheTurnStartLogic(t *testing.T) {
	var e entry
	if err := json.Unmarshal([]byte(replyRewakeMsg), &e); err != nil {
		t.Fatal(err)
	}
	if !isStopHookFeedback(e) {
		t.Error("a re-wake must be recognised as one")
	}
	if isGenuineUserMessage(e) {
		t.Error("a re-wake must not also be a turn start — the two are complements")
	}
}
