package engine

import (
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/outcome"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
)

func gitRepoWith(t *testing.T,
	files map[string]string) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	for _, args := range [][]string{{"init", "-q"}, {"config", "user.email", "t@t"}, {"config", "user.name", "t"}} {
		if out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	for name, body := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func blobOf(t *testing.T,
	dir string,
	rel string) string {
	t.Helper()
	out, err := exec.Command("git", "-C", dir, "hash-object", "--", rel).Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}

func TestFallbackFileCarriesTheBlobItWouldCommitAs(t *testing.T) {
	// Arrange
	dir := gitRepoWith(t, map[string]string{"pkg/app.py": "import os\nos.system(input())\n"})
	cwd := filepath.Join(dir, "pkg")
	changes := []transcript.Change{{FilePath: "app.py", AddedText: "os.system(input())"}}

	// Act
	got := withFileContent(changes, cwd, slog.Default())

	// Assert
	if want := blobOf(t, dir, "pkg/app.py"); got[0].BlobSHA != want {
		t.Errorf("BlobSHA = %q, want %q", got[0].BlobSHA, want)
	}
}

func TestFallbackOutsideARepoClaimsNoBlob(t *testing.T) {
	// Arrange
	project := t.TempDir()
	if err := os.WriteFile(filepath.Join(project, "app.py"), []byte("x = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	changes := []transcript.Change{{FilePath: "app.py", AddedText: "x = 1"}}

	// Act
	got := withFileContent(changes, project, slog.Default())

	// Assert
	if got[0].FullContent == "" || got[0].BlobSHA != "" {
		t.Errorf("want content and no blob outside git, got %+v", got[0])
	}
}

func TestFlaggedFileReadBackCarriesItsBlob(t *testing.T) {
	// Arrange
	dir := gitRepoWith(t, map[string]string{"app.py": "import shlex\n"})
	p := outcome.Pending{Sources: []outcome.Source{{Path: "app.py", Root: dir, Relative: "app.py"}}}

	// Act
	got := withFlaggedFiles(nil, p, slog.Default())

	// Assert
	if len(got) != 1 || got[0].BlobSHA != blobOf(t, dir, "app.py") {
		t.Errorf("want the flagged file with its blob, got %+v", got)
	}
}
