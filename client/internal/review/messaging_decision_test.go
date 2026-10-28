package review

import (
	"strings"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

func TestDecisionAskHasNoClientDefault(t *testing.T) {
	// Arrange
	SetMessaging(nil)
	t.Cleanup(func() { SetMessaging(nil) })

	// Act
	got := DecisionAsk(2)

	// Assert
	if got != "" {
		t.Errorf("with no server template there must be no question; got %q", got)
	}
}

func TestDecisionAskFillsTheServerTemplate(t *testing.T) {
	// Arrange
	SetMessaging(&wire.Messaging{Mark: "🔒", DecisionAsk: "Ask about {count}; start with {mark} LeoPrevent:"})
	t.Cleanup(func() { SetMessaging(nil) })

	// Act
	got := DecisionAsk(3)
	none := DecisionAsk(0)

	// Assert
	if got != "Ask about 3; start with 🔒 LeoPrevent:" {
		t.Errorf("got %q", got)
	}
	if none != "" {
		t.Errorf("no findings to decide means no question; got %q", none)
	}
}

func TestDecisionAskRefusesABadTemplate(t *testing.T) {
	for name, tmpl := range map[string]string{
		"unknown placeholder": "Ask about {files}",
		"unclosed brace":      "Ask about {count",
		"too long":            strings.Repeat("a", maxDecisionRunes+1),
	} {
		// Arrange
		SetMessaging(&wire.Messaging{DecisionAsk: tmpl})

		// Act
		got := DecisionAsk(1)

		// Assert
		if got != "" {
			t.Errorf("%s: a template the client cannot trust must be dropped; got %q", name, got)
		}
	}
	SetMessaging(nil)
}
