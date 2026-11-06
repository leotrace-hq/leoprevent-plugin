package transcript

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

// The shape Claude Code writes for an answered AskUserQuestion (taken from a real transcript).
const answeredOffer = `{"type":"user","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1","content":"Your questions have been answered: \"Fix the 3 dependencies that have a fix on the same major version?\"=\"Not now\"."}]},"toolUseResult":{"questions":[{"question":"Fix the 3 dependencies that have a fix on the same major version?","header":"LeoPrevent","options":[{"label":"Yes, fix them"},{"label":"Not now"}],"multiSelect":false}],"answers":{"Fix the 3 dependencies that have a fix on the same major version?":"Not now"}}}`

func TestOfferAnsweredReadsTheAnswerUnderItsHeader(t *testing.T) {
	if !OfferAnswered(writeTranscript(t, `{"type":"user","message":{"role":"user","content":"hi"}}`, answeredOffer), "LeoPrevent") {
		t.Error("answered offer not found")
	}
	if OfferAnswered(writeTranscript(t, answeredOffer), "Dep fixes") {
		t.Error("a question under another header counted")
	}
	unanswered := strings.Replace(answeredOffer, `"answers":{"Fix the 3 dependencies that have a fix on the same major version?":"Not now"}`, `"answers":{}`, 1)
	if OfferAnswered(writeTranscript(t, unanswered), "LeoPrevent") {
		t.Error("a question with no answer counted")
	}
	if OfferAnswered(filepath.Join(t.TempDir(), "missing.jsonl"), "LeoPrevent") {
		t.Error("a missing transcript counted")
	}
}

// Only a prompt carries the marker: the parent's start_session call that quotes it, which a fork
// inherits, doesn't.
func TestPromptHasOnlyMatchesAPrompt(t *testing.T) {
	marker := "[LeoPrevent: dependency fix session]"
	toolCall := `{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","id":"toolu_2","name":"start_session","input":{"prompt":"[LeoPrevent: dependency fix session]\nFix them."}}]}}`
	prompt := `{"type":"user","message":{"role":"user","content":"Update the 7 vulnerable dependencies.\nFix them.\n[LeoPrevent: dependency fix session]"}}`
	if PromptHas(writeTranscript(t, toolCall), marker) {
		t.Error("a quoted tool call counted as the prompt")
	}
	if !PromptHas(writeTranscript(t, toolCall, prompt), marker) {
		t.Error("the fix session's prompt not found")
	}
	if PromptHas(writeTranscript(t, prompt), "") {
		t.Error("an empty marker matched")
	}
}

// Only an absolute path to a regular .jsonl file is read: a relative path, another extension, a
// symlink or a folder reads as unanswered, never as whatever it points at.
func TestOpenTranscriptRefusesAnythingButATranscript(t *testing.T) {
	good := writeTranscript(t, answeredOffer)
	if !OfferAnswered(good, "LeoPrevent") {
		t.Fatal("a real transcript was refused")
	}
	dir := t.TempDir()
	other := filepath.Join(dir, "answers.txt")
	link := filepath.Join(dir, "linked.jsonl")
	folder := filepath.Join(dir, "folder.jsonl")
	if err := os.WriteFile(other, []byte(answeredOffer+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(folder, 0o700); err != nil {
		t.Fatal(err)
	}
	rel, err := filepath.Rel(mustGetwd(t), good)
	if err != nil {
		t.Fatal(err)
	}
	refused := map[string]string{"relative": rel, "not .jsonl": other, "folder": folder, "empty": ""}
	// Creating a symlink needs a privilege some Windows runners don't have; the case is
	// checked wherever one can be made.
	if err := os.Symlink(good, link); err == nil {
		refused["symlink"] = link
	}
	for name, p := range refused {
		if OfferAnswered(p, "LeoPrevent") || PromptHas(p, "Not now") {
			t.Errorf("%s path read: %s", name, p)
		}
	}
}

func mustGetwd(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return wd
}

// The agent's line counts only when the agent says it, on a line of its own: the offer quoting it
// in a hook message, or a reply that merely mentions it mid-sentence, doesn't.
func TestAgentSaidLineOnlyCountsTheAgentsOwnLine(t *testing.T) {
	line := "LeoPrevent: offer answered"
	hook := `{"type":"user","message":{"role":"user","content":"Stop hook feedback:\nAsk once... add the line \"LeoPrevent: offer answered\" on its own at the end."}}`
	mention := `{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"I'll add LeoPrevent: offer answered once you reply."}]}}`
	said := `{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"Understood, I'll leave the dependencies as they are.\n\n  LeoPrevent: offer answered  "}]}}`
	if AgentSaidLine(writeTranscript(t, hook, mention), line) {
		t.Error("a quote or a mention counted as the agent's line")
	}
	if !AgentSaidLine(writeTranscript(t, hook, said), line) {
		t.Error("the agent's own line wasn't found")
	}
	if AgentSaidLine(writeTranscript(t, said), "") {
		t.Error("an empty line matched")
	}
}

// The answered line is read from Codex's rollout and Copilot's transcript: only on a line of its
// own, and only in the agent's reply, never in the user message that quotes it.
func TestCodexAndCopilotTranscriptsSayTheAnsweredLine(t *testing.T) {
	line := wire.OfferAnsweredLine
	codexUser := `{"type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"` + line + `"}]}}`
	codexReply := func(text string) string {
		return `{"type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"` + text + `"}]}}`
	}
	if !CodexSaidOfferAnswered(writeTranscript(t, codexUser, codexReply(`Leaving them.\n\n`+line))) {
		t.Error("Codex: the answered line not found")
	}
	if CodexSaidOfferAnswered(writeTranscript(t, codexUser, codexReply(`I'll say `+line+` later.`))) {
		t.Error("Codex: a quote or a mention counted")
	}
	copilotUser := `{"type":"user.message","timestamp":"2026-11-04T10:00:00Z","data":{"content":"` + line + `"}}`
	copilotReply := func(text string) string {
		return `{"type":"assistant.message","timestamp":"2026-11-04T10:01:00Z","data":{"messageId":"m1","content":"` + text + `"}}`
	}
	if !CopilotSaidOfferAnswered(writeTranscript(t, copilotUser, copilotReply(`OK.\n\nLeoPrevent: offer answered`))) {
		t.Error("Copilot: the old answered line not found")
	}
	if CopilotSaidOfferAnswered(writeTranscript(t, copilotUser, copilotReply(`Want me to fix them?`))) {
		t.Error("Copilot: a user message or an unanswered reply counted")
	}
	if CodexSaidOfferAnswered(filepath.Join(t.TempDir(), "missing.jsonl")) || CopilotSaidOfferAnswered("") {
		t.Error("a missing transcript counted")
	}
}

// A skipped question isn't an answer (D60: no answer quietens nothing). The Claude desktop app
// records Skip as "[No preference]" (LEO-819, seen 6 Nov 2026).
func TestASkippedOfferIsNotAnswered(t *testing.T) {
	skipped := strings.ReplaceAll(answeredOffer, `"Not now"}}}`, `"[No preference]"}}}`)
	if OfferAnswered(writeTranscript(t, skipped), "LeoPrevent") {
		t.Error("a skipped question was read as an answer")
	}
	if !OfferAnswered(writeTranscript(t, skipped, answeredOffer), "LeoPrevent") {
		t.Error("an answer after a skip is still an answer")
	}
}
