package engine

import (
	"io"
	"log/slog"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/agent"
)

type replyAgent struct {
	agent.Agent
	reply string
}

func (r replyAgent) AgentReply(agent.Event) (string, error) { return r.reply, nil }

func TestAgentReplyKeepsTheFinalMessageTheTranscriptHadNotFlushed(t *testing.T) {
	// Arrange
	a := replyAgent{reply: "Checking how the router is mounted..."}
	ev := agent.Event{LastAssistantMessage: "Fixed: the route now checks the session first."}

	// Act
	got := agentReply(a, ev, slog.New(slog.NewTextHandler(io.Discard, nil)))

	// Assert
	want := "Checking how the router is mounted...\n\nFixed: the route now checks the session first."
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestAgentReplyDoesNotRepeatAFinalMessageItAlreadyHolds(t *testing.T) {
	// Arrange
	a := replyAgent{reply: "Looked at it.\n\nFixed: the route now checks the session first."}
	ev := agent.Event{LastAssistantMessage: "Fixed: the route now checks the session first."}

	// Act
	got := agentReply(a, ev, slog.New(slog.NewTextHandler(io.Discard, nil)))

	// Assert
	if got != a.reply {
		t.Fatalf("got %q, want the parsed reply unchanged", got)
	}
}
