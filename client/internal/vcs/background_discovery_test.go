package vcs

import (
	"path/filepath"
	"strings"
	"testing"
)

func backgroundStop(
	t *testing.T,
	cwd, sessionID string,
) []changeAlias {
	t.Helper()
	if err := StageBaseline(cwd, sessionID); err != nil {
		t.Fatalf("StageBaseline: %v", err)
	}
	changes, ok, skip, err := ChangedFiles(cwd, sessionID)
	if err != nil || !ok {
		t.Fatalf("expected the git path, got ok=%v skip=%q err=%v", ok, skip, err)
	}
	if err := PromoteStagedBaseline(cwd, sessionID); err != nil {
		t.Fatalf("PromoteStagedBaseline: %v", err)
	}
	return aliased(changes)
}

func TestBackgroundStopMovesADiscoveredRepoBaselineForward(t *testing.T) {
	// Arrange
	needGit(t)
	base := t.TempDir()
	cwd := seedRepoAt(t, filepath.Join(base, "platform"), "app.py", "x = 1\n")
	other := seedRepoAt(t, filepath.Join(base, "worker"), "job.py", "y = 1\n")
	s := session(t, "vcs-bg-discovered")
	if err := CaptureBaseline(cwd, s); err != nil {
		t.Fatal(err)
	}
	edits(t, other, "job.py", s, cwd)
	appendTo(t, filepath.Join(other, "job.py"), "first = 1\n")
	backgroundStop(t, cwd, s)
	edits(t, other, "job.py", s, cwd)
	appendTo(t, filepath.Join(other, "job.py"), "second = 1\n")

	// Act
	got := backgroundStop(t, cwd, s)

	// Assert
	c, found := findChange(got, "worker/job.py")
	if !found || len(got) != 1 {
		t.Fatalf("want only worker/job.py, got %+v", got)
	}
	if strings.Contains(c.AddedText, "first") || !strings.Contains(c.AddedText, "second") {
		t.Errorf("second stop must review only what changed since the first, got %q", c.AddedText)
	}
}

func TestBackgroundStopStillReviewsAWriteMadeDuringTheReview(t *testing.T) {
	// Arrange
	needGit(t)
	base := t.TempDir()
	cwd := seedRepoAt(t, filepath.Join(base, "platform"), "app.py", "x = 1\n")
	other := seedRepoAt(t, filepath.Join(base, "worker"), "job.py", "y = 1\n")
	s := session(t, "vcs-bg-during")
	if err := CaptureBaseline(cwd, s); err != nil {
		t.Fatal(err)
	}
	edits(t, other, "job.py", s, cwd)
	appendTo(t, filepath.Join(other, "job.py"), "first = 1\n")
	if err := StageBaseline(cwd, s); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := ChangedFiles(cwd, s); err != nil {
		t.Fatal(err)
	}
	appendTo(t, filepath.Join(other, "job.py"), "during = 1\n")
	if err := PromoteStagedBaseline(cwd, s); err != nil {
		t.Fatal(err)
	}

	// Act
	got := backgroundStop(t, cwd, s)

	// Assert
	c, found := findChange(got, "worker/job.py")
	if !found || !strings.Contains(c.AddedText, "during") {
		t.Errorf("a write made while the previous stop was reviewed must be reviewed now, got %+v", got)
	}
}

func TestBackgroundStopDoesNotReviewTheSessionRepoTwice(t *testing.T) {
	// Arrange
	needGit(t)
	repo := seedRepoAt(t, filepath.Join(t.TempDir(), "libreville-v1"), "app.py", "x = 1\n")
	s := session(t, "vcs-bg-self")
	edits(t, repo, "app.py", s, repo)
	appendTo(t, filepath.Join(repo, "app.py"), "first = 1\n")
	backgroundStop(t, repo, s)
	edits(t, repo, "app.py", s, repo)
	appendTo(t, filepath.Join(repo, "app.py"), "second = 1\n")

	// Act
	got := backgroundStop(t, repo, s)

	// Assert
	if len(got) != 1 || got[0].FilePath != "app.py" {
		t.Fatalf("want the session repo once, unlabelled, got %+v", got)
	}
	if strings.Contains(got[0].AddedText, "first") || !strings.Contains(got[0].AddedText, "second") {
		t.Errorf("second stop must review only what changed since the first, got %q", got[0].AddedText)
	}
}
