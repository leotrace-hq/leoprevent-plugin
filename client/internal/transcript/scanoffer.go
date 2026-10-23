package transcript

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// The session scan's offer (LEO-673) is answered in the agent's own conversation, so the hook
// learns the answer from the transcript (decided 23 Oct 2026; see internal/depquiet). Both readers
// are Claude Code's format: the offer is only asked with AskUserQuestion, and the fix session only
// started, by the Claude adapter.

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
// An unreadable transcript is unanswered.
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
			if q.Header == header && strings.TrimSpace(e.ToolUseResult.Answers[q.Question]) != "" {
				return true
			}
		}
	}
	return false
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
