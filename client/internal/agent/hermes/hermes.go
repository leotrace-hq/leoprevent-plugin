package hermes

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/agent"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/review"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

const (
	eventPreLLMCall  = "pre_llm_call"
	eventPreToolCall = "pre_tool_call"
	eventPreVerify   = "pre_verify"
)

type Adapter struct{}

func New() *Adapter           { return &Adapter{} }
func (*Adapter) Name() string { return "hermes" }

func (*Adapter) Environment(
	agent.Event,
) agent.Environment {
	return agent.Environment{Name: wire.EnvHermesCLI}
}

func (*Adapter) ParseEvent(
	stdin []byte,
) (agent.Event, error) {
	var p struct {
		Name      string         `json:"hook_event_name"`
		SessionID string         `json:"session_id"`
		Cwd       string         `json:"cwd"`
		Input     map[string]any `json:"tool_input"`
		Extra     struct {
			TurnID        string   `json:"turn_id"`
			Attempt       int      `json:"attempt"`
			FinalResponse string   `json:"final_response"`
			ChangedPaths  []string `json:"changed_paths"`
		} `json:"extra"`
	}
	if err := json.Unmarshal(stdin, &p); err != nil {
		return agent.Event{}, err
	}
	ev := agent.Event{SessionID: p.SessionID, Cwd: workspace(p.SessionID, p.Cwd)}
	switch p.Name {
	case eventPreLLMCall:
		ev.Name = agent.EventUserPromptSubmit
		ev.PromptID = p.Extra.TurnID
	case eventPreToolCall:
		ev.Name = agent.EventPreToolUse
		ev.EditPaths = agent.EditPathsFromToolInput(p.Input)
	case eventPreVerify:
		ev.Name = "Stop"
		ev.StopHookActive = p.Extra.Attempt > 0
		ev.LastAssistantMessage = p.Extra.FinalResponse
		if ev.Cwd == "" {
			ev.Cwd = changedDir(p.Extra.ChangedPaths)
		}
	default:
		return agent.Event{}, fmt.Errorf("unsupported Hermes event %q", p.Name)
	}
	return ev, nil
}

func (*Adapter) ChangedFiles(
	agent.Event,
) ([]transcript.Change, error) {
	return nil, nil
}

func (*Adapter) TurnMeta(
	agent.Event,
) (agent.TurnMeta, error) {
	return agent.TurnMeta{}, nil
}

func (*Adapter) AgentReply(
	agent.Event,
) (string, error) {
	return "", nil
}

func (*Adapter) DeliverReview(
	prompt, banner string,
	fileCount int,
	findings []wire.Finding,
	summary string,
) ([]byte, error) {
	notice := noticeParagraphs(review.ReviewContextMessageWith(summary, fileCount, findings, review.ForceFixedCount(findings)))
	// Hermes can put text before a repair tool call into private reasoning. Name
	// the final visible response explicitly; the notice itself stays server-controlled.
	return review.RewakeJSON(prompt+"\n\n"+notice+"\n\n"+
		"Hermes hides reasoning and intermediate messages from the developer. Include the LeoPrevent markdown notice above in your final, user-visible response after completing the requested repairs. Printing it only before a tool call or in reasoning does not show it to the developer. Render the notice as ordinary Markdown paragraphs, without blockquote markers or enclosing quotation marks.", banner)
}

func (*Adapter) DeliverNotice(
	message string,
) ([]byte, error) {
	return review.NoticeJSON(message)
}

func (*Adapter) WakeForDependencies(
	out []byte,
	prompt string,
) ([]byte, error) {
	merged, _, err := review.WithDependencyWake(out, prompt)
	return merged, err
}

func (*Adapter) RelayForDeveloper(
	out []byte,
	notice, markdown, before string,
) ([]byte, string, error) {
	merged, _, printed, err := review.WithDeveloperRelay(out, notice, markdown, before)
	if err != nil {
		return out, "", err
	}
	// The shared relay quotes its notice. Change only that exact generated block,
	// leaving repair instructions, nonce fences and other output fields intact.
	paragraphs := noticeParagraphs(printed)
	var hook map[string]json.RawMessage
	if err := json.Unmarshal(merged, &hook); err != nil {
		return out, "", err
	}
	var reason string
	if err := json.Unmarshal(hook["reason"], &reason); err != nil {
		return out, "", err
	}
	hook["reason"], _ = json.Marshal(strings.ReplaceAll(reason, "\n"+printed+"\n", "\n"+paragraphs+"\n"))
	merged, err = json.Marshal(hook)
	return merged, paragraphs, err
}

func (*Adapter) DeliverPromptNotice(
	message, context string,
) ([]byte, error) {
	text := strings.TrimSpace(context)
	if text == "" {
		text = strings.TrimSpace(message)
	}
	if text == "" {
		return nil, nil
	}
	return json.Marshal(map[string]string{"context": noticeParagraphs(text)})
}

// Hermes desktop's typography adds curly quotes and italics to Markdown
// blockquotes. Remove only the notice's quote layer, preserving its wording.
func noticeParagraphs(markdown string) string {
	lines := strings.Split(markdown, "\n")
	for i, line := range lines {
		if line == ">" {
			lines[i] = ""
		} else {
			lines[i] = strings.TrimPrefix(line, "> ")
		}
	}
	return strings.Join(lines, "\n")
}
