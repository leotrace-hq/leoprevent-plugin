package vcs

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func gitAt(t *testing.T, dir, when string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t",
		"GIT_AUTHOR_DATE="+when, "GIT_COMMITTER_DATE="+when,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

func lineOf(t *testing.T, body, text string) int {
	t.Helper()
	for i, ln := range strings.Split(body, "\n") {
		if strings.TrimSpace(ln) == text {
			return i + 1
		}
	}
	t.Fatalf("%q not in %q", text, body)
	return 0
}

func TestLinesAMidTurnMergeBroughtInAreNotTheAgents(t *testing.T) {
	// Arrange
	dir, session := initRepo(t)
	gitRun(t, dir, "checkout", "-q", "-b", "colleague")
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte("import os\nos.system(cmd)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, dir, "add", "-A")
	gitAt(t, dir, "2020-01-01T00:00:00Z", "commit", "-q", "-m", "colleague: shell call")
	gitRun(t, dir, "checkout", "-q", "master")
	if err := CaptureBaseline(dir, session); err != nil {
		t.Fatal(err)
	}
	gitRun(t, dir, "merge", "-q", "--ff-only", "colleague")
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte("import os\nos.system(cmd)\neval(user_input)\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Act
	changes, ok, _, err := ChangedFiles(dir, session)

	// Assert
	if err != nil || !ok {
		t.Fatalf("ChangedFiles: ok=%v err=%v", ok, err)
	}
	var lines []int
	var body string
	for _, c := range changes {
		if c.FilePath == "app.py" {
			lines, body = c.AddedLines, c.FullContent
		}
	}
	mine, theirs := lineOf(t, body, "eval(user_input)"), lineOf(t, body, "os.system(cmd)")
	has := func(n int) bool {
		for _, l := range lines {
			if l == n {
				return true
			}
		}
		return false
	}
	if !has(mine) {
		t.Errorf("the agent's own line %d is not counted as added: %v", mine, lines)
	}
	if has(theirs) {
		t.Errorf("the merged-in line %d is counted as the agent's: %v", theirs, lines)
	}
}

func TestTheAgentsOwnMidTurnCommitStillCountsAsAdded(t *testing.T) {
	// Arrange
	dir, session := initRepo(t)
	if err := CaptureBaseline(dir, session); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte("import os\neval(user_input)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-q", "-m", "agent: eval")

	// Act
	changes, ok, _, err := ChangedFiles(dir, session)

	// Assert
	if err != nil || !ok {
		t.Fatalf("ChangedFiles: ok=%v err=%v", ok, err)
	}
	for _, c := range changes {
		if c.FilePath == "app.py" {
			n := lineOf(t, c.FullContent, "eval(user_input)")
			for _, l := range c.AddedLines {
				if l == n {
					return
				}
			}
			t.Fatalf("the agent's committed line %d is not counted as added: %v", n, c.AddedLines)
		}
	}
	t.Fatal("app.py was not reviewed")
}
