package vcs

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func committedBlob(t *testing.T,
	dir string,
	rel string) string {
	t.Helper()
	gitRun(t, dir, "add", rel)
	gitRun(t, dir, "commit", "-q", "-m", "commit "+rel)
	out, err := exec.Command("git", "-C", dir, "rev-parse", "HEAD:"+rel).Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}

func changeBlob(t *testing.T,
	dir string,
	session string,
	rel string) string {
	t.Helper()
	changes, ok, skip, err := ChangedFiles(dir, session)
	if err != nil || !ok {
		t.Fatalf("ChangedFiles: ok=%v skip=%q err=%v", ok, skip, err)
	}
	for _, c := range changes {
		if c.FilePath == rel {
			return c.BlobSHA
		}
	}
	t.Fatalf("%s not among the changes %+v", rel, changes)
	return ""
}

func TestReviewedFileBlobMatchesTheCommitThatLandsIt(t *testing.T) {
	// Arrange
	dir, session := initRepo(t)
	if err := CaptureBaseline(dir, session); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte("import os\nos.system(input())\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Act
	got := changeBlob(t, dir, session, "app.py")

	// Assert
	if want := committedBlob(t, dir, "app.py"); got == "" || got != want {
		t.Errorf("reviewed blob %q, committed blob %q", got, want)
	}
}

func TestReviewedBlobAppliesCleanFiltersLikeACommit(t *testing.T) {
	// Arrange
	dir, session := initRepo(t)
	gitRun(t, dir, "config", "core.autocrlf", "true")
	if err := CaptureBaseline(dir, session); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "win.py"), []byte("a = 1\r\nb = 2\r\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Act
	got := changeBlob(t, dir, session, "win.py")

	// Assert
	want := committedBlob(t, dir, "win.py")
	raw, err := exec.Command("git", "-C", dir, "hash-object", "--no-filters", "win.py").Output()
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(raw)) == want {
		t.Fatal("fixture does not exercise a clean filter")
	}
	if got != want {
		t.Errorf("reviewed blob %q, committed blob %q", got, want)
	}
}

func TestTurnCommitCarriesItsCommittedBlob(t *testing.T) {
	// Arrange
	dir, session := initRepo(t)
	withRemote(t, dir)
	if err := CaptureBaseline(dir, session); err != nil {
		t.Fatal(err)
	}
	gitRun(t, dir, "checkout", "-q", "-b", "feature/pin")
	commitFile(t, dir, "deploy.yml", unpinnedAction)
	want, err := exec.Command("git", "-C", dir, "rev-parse", "HEAD:deploy.yml").Output()
	if err != nil {
		t.Fatal(err)
	}
	gitRun(t, dir, "push", "-q", "-u", "origin", "feature/pin")
	gitRun(t, dir, "checkout", "-q", "master")

	// Act
	got := changeBlob(t, dir, session, "deploy.yml")

	// Assert
	if got != strings.TrimSpace(string(want)) {
		t.Errorf("turn-commit blob %q, committed blob %q", got, strings.TrimSpace(string(want)))
	}
}

func TestPullRequestLaneNeverClaimsABlob(t *testing.T) {
	// Arrange
	dir := prRepo(t)
	write(t, dir, "seed.py", "seed = 1\n")
	commit(t, dir, "seed")
	gitDo(t, dir, "checkout", "-q", "-b", "feature")
	write(t, dir, "app.py", "import os\nos.system(input())\n")
	commit(t, dir, "feature")

	// Act
	changes, skip, err := DiffRange(dir, "main")

	// Assert
	if err != nil || skip != "" || len(changes) == 0 {
		t.Fatalf("DiffRange: skip=%q err=%v changes=%+v", skip, err, changes)
	}
	for _, c := range changes {
		if c.BlobSHA != "" {
			t.Errorf("%s carries blob %q; a lane review would attest its own pull request", c.FilePath, c.BlobSHA)
		}
	}
}

func TestBlobIDRejectsWhatGitDidNotHash(t *testing.T) {
	// Arrange
	cases := map[string]string{
		"empty":     "",
		"short":     "abc123",
		"not hex":   strings.Repeat("z", 40),
		"too long":  strings.Repeat("a", 41),
		"uppercase": strings.Repeat("A", 40),
	}

	for name, in := range cases {
		// Act
		got := validBlobID(in)

		// Assert
		want := ""
		if name == "uppercase" {
			want = strings.Repeat("a", 40)
		}
		if got != want {
			t.Errorf("%s: validBlobID(%q) = %q, want %q", name, in, got, want)
		}
	}
}
