package vcs

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The turn-start copy is the working tree as it was when the prompt arrived (uncommitted
// work included), not HEAD; a file created this turn is fs.ErrNotExist; a symlink is never
// read as the file it names.
func TestTurnStartReadsTheStartOfTheTurn(t *testing.T) {
	dir, session := initRepo(t)
	write := func(rel, body string) {
		t.Helper()
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("web/package-lock.json", `{"committed": true}`)
	write("elsewhere.txt", "not a lockfile")
	if err := os.Symlink("../elsewhere.txt", filepath.Join(dir, "web", "go.sum")); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-q", "-m", "lockfile")
	write("web/package-lock.json", `{"uncommitted before the turn": true}`) // the start of the turn
	write("tools/go.mod", "module tools\n")                                 // untracked, small
	if err := CaptureBaseline(dir, session); err != nil {
		t.Fatal(err)
	}
	write("web/package-lock.json", `{"changed this turn": true}`)
	write("api/go.mod", "module api\n")

	ts, ok := LoadTurnStart(dir, session)
	if !ok {
		t.Fatal("no turn-start state")
	}
	root, err := git(dir, "rev-parse", "--show-toplevel")
	if err != nil {
		t.Fatal(err)
	}
	root = strings.TrimSpace(root)
	open := ts.Opener(root)
	at := func(rel string) string { return filepath.Join(root, filepath.FromSlash(rel)) }

	if b, err := open(at("web/package-lock.json")); err != nil || string(b) != `{"uncommitted before the turn": true}` {
		t.Errorf("tracked file: %q, %v (want the uncommitted start-of-turn copy, not HEAD or now)", b, err)
	}
	if b, err := open(at("tools/go.mod")); err != nil || string(b) != "module tools\n" {
		t.Errorf("untracked at turn start: %q, %v", b, err)
	}
	if _, err := open(at("api/go.mod")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("created this turn: %v, want fs.ErrNotExist", err)
	}
	if _, err := open(at("web/go.sum")); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("a symlink: %v", err)
	}
	if _, err := open(filepath.Join(filepath.Dir(root), "outside", "go.mod")); err == nil || !strings.Contains(err.Error(), "outside") {
		t.Errorf("a path outside the repository: %v", err)
	}
	if _, err := ts.Opener(filepath.Join(root, "not-a-repo"))(at("go.mod")); !errors.Is(err, ErrNoTurnStartCopy) {
		t.Errorf("a root with no capture: %v", err)
	}
}

// An untracked file whose content the snapshot didn't keep (too large) existed at the start:
// it must read as "no copy", never as new this turn.
func TestTurnStartUntrackedWithoutACopy(t *testing.T) {
	dir, session := initRepo(t)
	prev, prevDep := maxUntrackedBlobTotal, maxUntrackedDependencyTotal
	maxUntrackedBlobTotal, maxUntrackedDependencyTotal = 1, 1
	t.Cleanup(func() { maxUntrackedBlobTotal, maxUntrackedDependencyTotal = prev, prevDep })
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(`{"big": true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := CaptureBaseline(dir, session); err != nil {
		t.Fatal(err)
	}
	ts, _ := LoadTurnStart(dir, session)
	root, _ := git(dir, "rev-parse", "--show-toplevel")
	root = strings.TrimSpace(root)
	if _, err := ts.Opener(root)(filepath.Join(root, "package-lock.json")); !errors.Is(err, ErrNoTurnStartCopy) {
		t.Errorf("untracked, not kept: %v, want ErrNoTurnStartCopy", err)
	}
}

// A repository before its first commit holds its lockfile untracked, and a lockfile is usually
// over the 112 KB that bounds what the review sends. Its start-of-turn copy is kept all the same
// (it never leaves the machine), so the dependency check can tell what the turn changed in it;
// an ordinary untracked file that size still isn't kept. Each copy is matched by its own path.
func TestALargeUntrackedLockfileKeepsItsCopy(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	gitRun(t, dir, "init", "-q", "-b", "master") // no commits
	session := sanitize(t.Name())
	t.Cleanup(func() { _ = os.Remove(scratchPath(scopedSession(dir, session))) })
	big := strings.Repeat("x", 139*1024)
	for rel, body := range map[string]string{
		"package-lock.json":     `{"lockfileVersion": 3, "pad": "` + big + `"}`,
		"web/package-lock.json": `{"lockfileVersion": 3, "web": "` + big + `"}`,
		"notes.txt":             big,
	} {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := CaptureBaseline(dir, session); err != nil {
		t.Fatal(err)
	}
	// The turn changes both lockfiles; the copies are what they were at the start.
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(`{"changed": true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "web", "package-lock.json"), []byte(`{"changed": "web"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	ts, ok := LoadTurnStart(dir, session)
	if !ok {
		t.Fatal("no turn-start copy in a repository with no commits")
	}
	root, _ := git(dir, "rev-parse", "--show-toplevel")
	root = strings.TrimSpace(root)
	open := ts.Opener(root)
	for rel, want := range map[string]string{"package-lock.json": `"pad"`, "web/package-lock.json": `"web"`} {
		got, err := open(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil || !strings.Contains(string(got), want) || len(got) < 139*1024 {
			t.Errorf("%s: the copy from the start of the turn, by its own path: %d bytes, %v", rel, len(got), err)
		}
	}
	if _, err := open(filepath.Join(root, "notes.txt")); !errors.Is(err, ErrNoTurnStartCopy) {
		t.Errorf("an ordinary untracked file that size still isn't kept: %v", err)
	}
}
