package devin

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/agent"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/review"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

type Adapter struct{}

func New() *Adapter           { return &Adapter{} }
func (*Adapter) Name() string { return "devin" }
func (*Adapter) Environment(
	agent.Event,
) agent.Environment {
	return agent.Environment{Name: wire.EnvDevinCLI}
}

func (*Adapter) ParseEvent(
	stdin []byte,
) (agent.Event, error) {
	var p struct {
		Name      string         `json:"hook_event_name"`
		SessionID string         `json:"session_id"`
		PromptID  string         `json:"prompt_id"`
		Cwd       string         `json:"cwd"`
		Active    bool           `json:"stop_hook_active"`
		Reply     string         `json:"last_assistant_message"`
		Input     map[string]any `json:"tool_input"`
	}
	if err := json.Unmarshal(stdin, &p); err != nil {
		return agent.Event{}, err
	}
	switch p.Name {
	case agent.EventUserPromptSubmit, agent.EventPreToolUse, "Stop":
	default:
		return agent.Event{}, fmt.Errorf("unsupported Devin event %q", p.Name)
	}
	if p.Cwd == "" {
		p.Cwd = os.Getenv("DEVIN_PROJECT_DIR")
	}
	return agent.Event{Name: p.Name, SessionID: p.SessionID, PromptID: p.PromptID, Cwd: p.Cwd, StopHookActive: p.Active, LastAssistantMessage: p.Reply, EditPaths: agent.EditPathsFromToolInput(p.Input)}, nil
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
	_ int,
	_ []wire.Finding,
	_ string,
) ([]byte, error) {
	return review.RewakeJSON(prompt, banner)
}
func (*Adapter) DeliverNotice(
	message string,
) ([]byte, error) {
	return review.NoticeJSON(message)
}

// WakeForDependencies wakes the agent with the dependency check's instructions (LEO-620), in the
// same shape as its review wake: after the review's prompt, which stays as it is, or on its own.
func (*Adapter) WakeForDependencies(out []byte, prompt string) ([]byte, error) {
	merged, _, err := review.WithDependencyWake(out, prompt)
	return merged, err
}

// RelayForDeveloper asks the agent to print a notice meant only for the developer (LEO-662). The
// Devin CLI's hooks document no Stop field shown to the user, so the notice is relayed through
// the same decision/reason wake as a review's: on its own, or added to a review's or the
// dependency check's wake, whose instructions stay as they are. The Stop after it carries
// stop_hook_active, so it never wakes again. The notice is in the systemMessage too.
func (*Adapter) RelayForDeveloper(out []byte, notice, markdown string) ([]byte, string, error) {
	merged, _, printed, err := review.WithDeveloperRelay(out, notice, markdown)
	if err != nil {
		return out, "", err
	}
	return merged, printed, nil
}
func (*Adapter) DeliverPromptNotice(
	message, context string,
) ([]byte, error) {
	return review.PromptNoticeJSON(message, context)
}
