package vcs

import (
	"errors"
	"os/exec"
	"strings"
	"testing"
)

func exitErr(t *testing.T,
	script string) error {
	t.Helper()
	_, err := exec.Command("sh", "-c", script).Output()
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("expected an exit error from %q, got %v", script, err)
	}
	return err
}

func TestStashResultTreatsSilentExitOneAsClean(t *testing.T) {
	// Arrange
	err := exitErr(t, "exit 1")

	// Act
	out, got := stashResult("", err)

	// Assert
	if got != nil || out != "" {
		t.Errorf("a silent exit 1 is git stash create finding nothing to save; want clean, got out=%q err=%v", out, got)
	}
}

func TestStashResultKeepsRealFailures(t *testing.T) {
	for _, tc := range []struct {
		name   string
		script string
		out    string
	}{
		{"stderr", "echo 'fatal: bad index' >&2; exit 1", ""},
		{"other code", "exit 128", ""},
		{"output", "exit 1", "abc123"},
	} {
		// Arrange
		err := exitErr(t, tc.script)

		// Act
		_, got := stashResult(tc.out, err)

		// Assert
		if got == nil {
			t.Errorf("%s: a real failure must stay a failure", tc.name)
		}
	}
}

func TestGitErrorsCarryStderr(t *testing.T) {
	// Arrange
	dir := t.TempDir()

	// Act
	_, err := gitIn(dir, nil, "rev-parse", "--verify", "no-such-ref-anywhere")

	// Assert
	if err == nil || !strings.Contains(err.Error(), "exit status") || len(err.Error()) <= len("exit status 128") {
		t.Errorf("a git failure should carry git's own message; got %v", err)
	}
}
