package vcs

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const unpinnedAction = "uses: aws-actions/configure-aws-credentials@v4\n"

func withRemote(t *testing.T, dir string) string {
	t.Helper()
	t.Setenv("GIT_COMMITTER_NAME", "t")
	t.Setenv("GIT_COMMITTER_EMAIL", "t@t")
	bare := t.TempDir()
	gitRun(t, bare, "init", "-q", "--bare")
	gitRun(t, dir, "remote", "add", "origin", bare)
	gitRun(t, dir, "push", "-q", "origin", "master")
	gitRun(t, dir, "fetch", "-q", "origin")
	return bare
}

func commitFile(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, dir, "add", name)
	gitRun(t, dir, "commit", "-q", "-m", "change "+name)
}

func reviewed(t *testing.T, dir, session string) map[string]int {
	t.Helper()
	changes, ok, skip, err := ChangedFiles(dir, session)
	if err != nil || !ok {
		t.Fatalf("ChangedFiles: ok=%v skip=%q err=%v", ok, skip, err)
	}
	got := map[string]int{}
	for _, c := range changes {
		got[c.FilePath]++
	}
	return got
}

func TestCommitPushedOnABranchThenSwitchedAwayIsReviewed(t *testing.T) {
	// Arrange
	dir, session := initRepo(t)
	withRemote(t, dir)
	if err := CaptureBaseline(dir, session); err != nil {
		t.Fatal(err)
	}
	gitRun(t, dir, "checkout", "-q", "-b", "feature/pin")
	commitFile(t, dir, "deploy.yml", unpinnedAction)
	gitRun(t, dir, "push", "-q", "-u", "origin", "feature/pin")
	gitRun(t, dir, "checkout", "-q", "master")

	// Act
	changes, ok, _, err := ChangedFiles(dir, session)

	// Assert
	if err != nil || !ok || len(changes) != 1 {
		t.Fatalf("want deploy.yml reviewed, got ok=%v err=%v changes=%+v", ok, err, changes)
	}
	c := changes[0]
	if c.FilePath != "deploy.yml" || !strings.Contains(c.FullContent, "configure-aws-credentials@v4") {
		t.Errorf("wrong change: %+v", c)
	}
	if len(c.AddedLines) != 1 || c.AddedLines[0] != 1 {
		t.Errorf("the committed line is the agent's and must anchor as added, got %v", c.AddedLines)
	}
}

func TestCommitLeftCheckedOutIsReviewedOnce(t *testing.T) {
	// Arrange
	dir, session := initRepo(t)
	withRemote(t, dir)
	if err := CaptureBaseline(dir, session); err != nil {
		t.Fatal(err)
	}
	gitRun(t, dir, "checkout", "-q", "-b", "feature/pin")
	commitFile(t, dir, "deploy.yml", unpinnedAction)
	gitRun(t, dir, "push", "-q", "-u", "origin", "feature/pin")

	// Act
	got := reviewed(t, dir, session)

	// Assert
	if got["deploy.yml"] != 1 || len(got) != 1 {
		t.Errorf("want deploy.yml reviewed exactly once, got %v", got)
	}
}

func TestCommitsInAnotherWorktreeAreNotThisSessions(t *testing.T) {
	// Arrange
	dir, session := initRepo(t)
	withRemote(t, dir)
	if err := CaptureBaseline(dir, session); err != nil {
		t.Fatal(err)
	}
	wt := filepath.Join(t.TempDir(), "wt")
	gitRun(t, dir, "worktree", "add", "-q", "-b", "feature/other", wt)
	commitFile(t, wt, "other.yml", unpinnedAction)
	gitRun(t, wt, "push", "-q", "-u", "origin", "feature/other")

	// Act
	got := reviewed(t, dir, session)

	// Assert
	if len(got) != 0 {
		t.Errorf("a commit in a worktree this session never recorded may be another session's, got %v", got)
	}
}

func TestOnlyThisWorktreesCommitsAreReviewed(t *testing.T) {
	// Arrange
	dir, session := initRepo(t)
	withRemote(t, dir)
	wt := filepath.Join(t.TempDir(), "wt")
	gitRun(t, dir, "worktree", "add", "-q", "-b", "feature/other", wt)
	if err := CaptureBaseline(dir, session); err != nil {
		t.Fatal(err)
	}
	commitFile(t, wt, "other.yml", unpinnedAction)
	gitRun(t, dir, "checkout", "-q", "-b", "feature/pin")
	commitFile(t, dir, "deploy.yml", unpinnedAction)
	gitRun(t, dir, "checkout", "-q", "master")

	// Act
	got := reviewed(t, dir, session)

	// Assert
	if got["deploy.yml"] != 1 || got["other.yml"] != 0 {
		t.Errorf("want only this worktree's commit, got %v", got)
	}
}

func TestSiblingWorktreeRecordedAtPreToolUseIsReviewedOnce(t *testing.T) {
	// Arrange
	dir, session := initRepo(t)
	withRemote(t, dir)
	if err := CaptureBaseline(dir, session); err != nil {
		t.Fatal(err)
	}
	wt := filepath.Join(t.TempDir(), "wt")
	gitRun(t, dir, "worktree", "add", "-q", "-b", "feature/pin", wt)
	if err := RecordEditedRepo(filepath.Join(wt, "deploy.yml"), dir, session); err != nil {
		t.Fatal(err)
	}
	commitFile(t, wt, "deploy.yml", unpinnedAction)
	gitRun(t, wt, "push", "-q", "-u", "origin", "feature/pin")

	// Act
	got := reviewed(t, dir, session)

	// Assert
	total := 0
	for p, n := range got {
		if strings.HasSuffix(p, "deploy.yml") {
			total += n
		}
	}
	if total != 1 || len(got) != 1 {
		t.Errorf("want deploy.yml reviewed exactly once across both sections, got %v", got)
	}
}

func TestCommitPushedThenResetAwayIsReviewed(t *testing.T) {
	// Arrange
	dir, session := initRepo(t)
	withRemote(t, dir)
	if err := CaptureBaseline(dir, session); err != nil {
		t.Fatal(err)
	}
	commitFile(t, dir, "deploy.yml", unpinnedAction)
	gitRun(t, dir, "push", "-q", "origin", "HEAD:refs/heads/feature/pin")
	gitRun(t, dir, "reset", "-q", "--hard", "origin/master")

	// Act
	got := reviewed(t, dir, session)

	// Assert
	if got["deploy.yml"] != 1 || len(got) != 1 {
		t.Errorf("want deploy.yml reviewed exactly once, got %v", got)
	}
}

func TestOnlyTheTurnsCommitsOnABranchAreReviewed(t *testing.T) {
	// Arrange
	dir, session := initRepo(t)
	withRemote(t, dir)
	gitRun(t, dir, "checkout", "-q", "-b", "feature/pin")
	commitFile(t, dir, "old.yml", "earlier work\n")
	gitRun(t, dir, "checkout", "-q", "master")
	backdate(t, dir, "feature/pin")
	if err := CaptureBaseline(dir, session); err != nil {
		t.Fatal(err)
	}
	gitRun(t, dir, "checkout", "-q", "feature/pin")
	commitFile(t, dir, "deploy.yml", unpinnedAction)
	gitRun(t, dir, "checkout", "-q", "master")

	// Act
	got := reviewed(t, dir, session)

	// Assert
	if got["deploy.yml"] != 1 || got["old.yml"] != 0 {
		t.Errorf("want only this turn's commit reviewed, got %v", got)
	}
}

func TestAColleaguesCommitFetchedMidTurnIsNotReviewed(t *testing.T) {
	// Arrange
	dir, session := initRepo(t)
	bare := withRemote(t, dir)
	other := t.TempDir()
	gitRun(t, other, "clone", "-q", bare, ".")
	gitRun(t, other, "checkout", "-q", "-b", "colleague")
	if err := CaptureBaseline(dir, session); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, "theirs.yml"), []byte(unpinnedAction), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, other, "add", "theirs.yml")
	cmd := exec.Command("git", "-C", other, "commit", "-q", "-m", "theirs")
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=c", "GIT_AUTHOR_EMAIL=c@c", "GIT_COMMITTER_NAME=c", "GIT_COMMITTER_EMAIL=c@c")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("colleague commit: %v\n%s", err, out)
	}
	gitRun(t, other, "push", "-q", "origin", "colleague")
	gitRun(t, dir, "fetch", "-q", "origin")

	// Act
	got := reviewed(t, dir, session)

	// Assert
	if len(got) != 0 {
		t.Errorf("another committer's work is not the agent's, got %v", got)
	}
}

func TestNoCommitsThisTurnStaysNoChange(t *testing.T) {
	// Arrange
	dir, session := initRepo(t)
	withRemote(t, dir)
	if err := CaptureBaseline(dir, session); err != nil {
		t.Fatal(err)
	}

	// Act
	got := reviewed(t, dir, session)

	// Assert
	if len(got) != 0 {
		t.Errorf("a quiet turn must stay quiet, got %v", got)
	}
}

func backdate(t *testing.T, dir, branch string) {
	t.Helper()
	cmd := exec.Command("git", "-C", dir, "commit-tree", branch+"^{tree}", "-p", branch+"^", "-m", "earlier work")
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t",
		"GIT_COMMITTER_DATE=2001-01-01T00:00:00Z", "GIT_AUTHOR_DATE=2001-01-01T00:00:00Z")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("commit-tree: %v", err)
	}
	gitRun(t, dir, "update-ref", "refs/heads/"+branch, strings.TrimSpace(string(out)))
}
