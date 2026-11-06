package transcript

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

// The session scan's offer (LEO-673) is answered in the agent's own conversation, so the hook
// learns the answer from the agent's reply or its transcript (decided 23 Oct 2026; see
// internal/depquiet). OfferAnswered and PromptHas read Claude Code's format: the offer is only
// asked with AskUserQuestion, and the fix session only started, by the Claude adapter. The
// answered line (SaysOfferAnswered) is every agent's, read from each one's own transcript format
// where it has one (LEO-530).

// SaysOfferAnswered reports a reply with one of wire.OfferAnsweredLines on a line of its own
// (surrounding spaces aside): the line the scan's offer asks the agent to end its reply with once
// the developer answers, however they answered.
func SaysOfferAnswered(reply string) bool {
	for _, l := range strings.Split(reply, "\n") {
		if slices.Contains(wire.OfferAnsweredLines, strings.TrimSpace(l)) {
			return true
		}
	}
	return false
}

// CodexSaidOfferAnswered reports whether any assistant message in a Codex rollout says the
// answered line (SaysOfferAnswered). The rollout is written after the turn settles, so the Stop's
// own last_assistant_message covers the reply that just ended; this covers an earlier one. An
// unreadable rollout is unanswered.
func CodexSaidOfferAnswered(transcriptPath string) bool {
	f, err := openTranscript(transcriptPath)
	if err != nil {
		return false
	}
	defer f.Close()
	lines, err := readJSONLLines(f)
	if err != nil {
		return false
	}
	for _, raw := range lines {
		if !mentionsAnsweredLine(raw) {
			continue
		}
		var e codexEntry
		if json.Unmarshal(raw, &e) != nil || e.Type != "response_item" || e.Payload.Type != "message" || e.Payload.Role != "assistant" {
			continue
		}
		for _, c := range e.Payload.Content {
			if SaysOfferAnswered(c.Text) {
				return true
			}
		}
	}
	return false
}

// CopilotSaidOfferAnswered reports whether any assistant.message in a Copilot transcript says the
// answered line (SaysOfferAnswered). Copilot's Stop doesn't document last_assistant_message, so
// the transcript is how its answer is read. An unreadable transcript is unanswered.
func CopilotSaidOfferAnswered(transcriptPath string) bool {
	f, err := openTranscript(transcriptPath)
	if err != nil {
		return false
	}
	defer f.Close()
	lines, err := readJSONLLines(f)
	if err != nil {
		return false
	}
	for _, raw := range lines {
		if !mentionsAnsweredLine(raw) {
			continue
		}
		var r copilotRecord
		if json.Unmarshal(raw, &r) == nil && r.Type == "assistant.message" && SaysOfferAnswered(r.Data.Content) {
			return true
		}
	}
	return false
}

// mentionsAnsweredLine is the cheap pre-filter before a line is decoded. The answered lines have
// no character JSON escapes, so a line that says one holds it verbatim.
func mentionsAnsweredLine(raw []byte) bool {
	return slices.ContainsFunc(wire.OfferAnsweredLines, func(l string) bool { return strings.Contains(string(raw), l) })
}

// errNotATranscript is a path openTranscript refuses.
var errNotATranscript = errors.New("not a transcript file")

// openTranscript opens the agent's transcript for a reader whose answer changes what the
// developer is told (whether a scan's offer was answered). The path is the hook input's
// transcript_path, from the agent the plugin runs beside, and read as the developer, so nothing
// crosses a privilege boundary; the guard is free all the same, as in vcs (readAllFrom): only an
// absolute path to a regular .jsonl file, never a symlink, opened through a root on its own
// folder. Anything else is unanswered, which fails toward telling the developer again.
func openTranscript(path string) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Ext(path) != ".jsonl" {
		return nil, errNotATranscript
	}
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, errNotATranscript
	}
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return root.Open(filepath.Base(path))
}

// OfferAnswered reports whether the transcript has an AskUserQuestion with a question headed
// header that the developer answered, whatever they chose. Claude Code records the answer on the
// tool result's entry as toolUseResult: {"questions": [{"header": …}], "answers": {question: label}}.
// An unreadable transcript is unanswered, and so is a skipped question: the Claude desktop app
// records Skip as the answer "[No preference]" (seen 6 Nov 2026, LEO-819), and D60 has no answer
// quieten nothing.
func OfferAnswered(transcriptPath, header string) bool {
	f, err := openTranscript(transcriptPath)
	if err != nil {
		return false
	}
	defer f.Close()
	lines, err := readJSONLLines(f)
	if err != nil {
		return false
	}
	for _, line := range lines {
		if !strings.Contains(string(line), `"toolUseResult"`) {
			continue
		}
		var e struct {
			ToolUseResult struct {
				Questions []struct {
					Question string `json:"question"`
					Header   string `json:"header"`
				} `json:"questions"`
				Answers map[string]string `json:"answers"`
			} `json:"toolUseResult"`
		}
		if json.Unmarshal(line, &e) != nil {
			continue
		}
		for _, q := range e.ToolUseResult.Questions {
			if q.Header == header && answered(e.ToolUseResult.Answers[q.Question]) {
				return true
			}
		}
	}
	return false
}

// skippedAnswer is what Claude Code records as the answer to a question the developer skipped.
const skippedAnswer = "[No preference]"

// answered is an AskUserQuestion answer that chose something: not empty, not a skip.
func answered(a string) bool {
	a = strings.TrimSpace(a)
	return a != "" && !strings.EqualFold(a, skippedAnswer)
}

// AgentSaidLine reports whether any of the agent's replies in the transcript has line on a line of
// its own (surrounding spaces aside). The scan's offer asks the agent to end the reply after the
// developer answers with such a line (wire.OfferAnsweredLine), however they answered. The offer
// itself quotes the line, but it reaches the agent as a hook message, never as its own reply, so
// only the agent saying it counts.
func AgentSaidLine(transcriptPath, line string) bool {
	if strings.TrimSpace(line) == "" {
		return false
	}
	f, err := openTranscript(transcriptPath)
	if err != nil {
		return false
	}
	defer f.Close()
	lines, err := readJSONLLines(f)
	if err != nil {
		return false
	}
	for _, raw := range lines {
		if !strings.Contains(string(raw), line) {
			continue
		}
		var e entry
		if json.Unmarshal(raw, &e) != nil || e.Type != "assistant" {
			continue
		}
		var blocks []contentBlock
		if json.Unmarshal(e.Message.Content, &blocks) != nil {
			continue
		}
		for _, b := range blocks {
			if b.Type != "text" {
				continue
			}
			for _, l := range strings.Split(b.Text, "\n") {
				if strings.TrimSpace(l) == line {
					return true
				}
			}
		}
	}
	return false
}

// PromptHas reports whether any genuine user prompt in the transcript contains marker. A tool call
// that quotes it (the start_session that launched this session, carried into a fork's history) is
// not a prompt, so only the session that was started with it matches.
func PromptHas(transcriptPath, marker string) bool {
	if marker == "" {
		return false
	}
	f, err := openTranscript(transcriptPath)
	if err != nil {
		return false
	}
	defer f.Close()
	lines, err := readJSONLLines(f)
	if err != nil {
		return false
	}
	for _, line := range lines {
		if !strings.Contains(string(line), marker) {
			continue
		}
		var e entry
		if json.Unmarshal(line, &e) == nil && isGenuineUserMessage(e) && strings.Contains(userText(e), marker) {
			return true
		}
	}
	return false
}
