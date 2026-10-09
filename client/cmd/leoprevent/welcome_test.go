package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/config"
)

func TestWelcomePrintsOnceAcrossSetLicenseRuns(t *testing.T) {
	// Arrange
	defer config.SetUserConfigDirForTest(t.TempDir())()

	// Act
	var first, second bytes.Buffer
	printWelcome(&first, "claude")
	printWelcome(&second, "claude")

	// Assert
	if !strings.Contains(first.String(), "LeoPrevent reviews your code") {
		t.Errorf("first run did not print the welcome: %q", first.String())
	}
	if second.Len() != 0 {
		t.Errorf("repeat run reprinted the welcome: %q", second.String())
	}
}

func TestWelcomeCopyDoesNotOverclaim(t *testing.T) {
	// Assert
	for _, bad := range []string{"LeoPrevent fixes it", "are running", "is running"} {
		if strings.Contains(welcomeMessage, bad) {
			t.Errorf("welcome copy contains %q", bad)
		}
	}
	if !strings.Contains(welcomeMessage, "flags it and your agent fixes it") {
		t.Error("welcome copy lost the flag/fix attribution")
	}
}

func TestWelcomeRelaysToTheAgentOnlyWhereOutputIsHidden(t *testing.T) {
	// Assert
	for name, tc := range map[string]struct {
		entrypoint, app string
		want            bool
	}{
		"plain shell":        {"", "", false},
		"claude terminal":    {"cli", "", false},
		"claude over ssh":    {"ssh-remote", "", false},
		"claude desktop":     {"claude-desktop", "", true},
		"claude vscode":      {"claude-vscode", "", true},
		"claude web":         {"remote", "", true},
		"unknown entrypoint": {"something-new", "", true},
		"codex cli":          {"", "com.apple.Terminal", false},
		"codex desktop":      {"", codexAppBundle, true},
		"copilot in vscode":  {"", vscodeAppBundle, true},
		"iterm":              {"", "com.googlecode.iterm2", false},
	} {
		if got := needsRelay(tc.entrypoint, func() string { return tc.app }); got != tc.want {
			t.Errorf("%s: needsRelay = %v, want %v", name, got, tc.want)
		}
	}
}

func TestWelcomeOutputCarriesTheRelayNoteOnlyInTheDesktopApp(t *testing.T) {
	for entrypoint, want := range map[string]bool{"cli": false, "claude-desktop": true} {
		// Arrange
		defer config.SetUserConfigDirForTest(t.TempDir())()
		t.Setenv("CLAUDE_CODE_ENTRYPOINT", entrypoint)

		// Act
		var out bytes.Buffer
		printWelcome(&out, "claude")

		// Assert
		if got := strings.Contains(out.String(), relayNote); got != want {
			t.Errorf("entrypoint %q: relay note present = %v, want %v", entrypoint, got, want)
		}
	}
}

func TestWelcomeContinuesTheLeoPreventQuoteBlock(t *testing.T) {
	// Assert
	for _, line := range strings.Split(strings.TrimSuffix(welcomeMessage, "\n"), "\n") {
		if !strings.HasPrefix(line, "> ") {
			t.Errorf("welcome line is outside the quote block, so it would not render with the byline: %q", line)
		}
	}
}

func TestWelcomeUsesTheCodexTestInstruction(
	t *testing.T,
) {
	defer config.SetUserConfigDirForTest(t.TempDir())()
	var out bytes.Buffer
	printWelcome(&out, "codex")
	if strings.Contains(out.String(), "/leoprevent:test") {
		t.Fatal("Codex welcome advertises an unavailable slash command")
	}
	if !strings.Contains(out.String(), "Ask Codex to run the LeoPrevent test using the installed plugin skill") {
		t.Fatal("Codex welcome omits the verified skill instruction")
	}
}
