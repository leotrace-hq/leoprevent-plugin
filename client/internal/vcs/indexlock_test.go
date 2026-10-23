package vcs

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// bigDirtyRepo builds a repository large enough that `git stash create` spends real
// time refreshing the index, then bumps every file's mtime so the refresh must re-stat
// and rehash them all. That window, with .git/index.lock held, is the one a timeout
// used to SIGKILL git inside.
func bigDirtyRepo(t *testing.T, files int) string {
	t.Helper()
	dir, _ := initRepo(t)
	for i := 0; i < files; i++ {
		sub := filepath.Join(dir, fmt.Sprintf("d%03d", i/200))
		if i%200 == 0 {
			if err := os.MkdirAll(sub, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(sub, fmt.Sprintf("f%d.txt", i)), []byte(fmt.Sprintf("%d\n", i)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-q", "-m", "big")
	return dir
}

func touchAll(t *testing.T, dir string, at time.Time) {
	t.Helper()
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && d.Name() == ".git" {
			return filepath.SkipDir
		}
		if !d.IsDir() {
			return os.Chtimes(p, at, at)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// A turn-start snapshot that runs out of time must never leave .git/index.lock behind.
// Observed in a benchmark run on tensorflow and salt: the lock's mtime was exactly the
// git timeout before "git baseline captured", and the developer's next `git add` failed
// with "index.lock exists". Mutation-checked: with stash create run against the real
// index and SIGKILLed on timeout (the old behaviour) this fails at the first timeout that
// lands inside the refresh, which is why it sweeps a range rather than trusting one.
func TestTimedOutSnapshotNeverLeavesIndexLock(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a large repository")
	}
	isolateSessionScratch(t)
	dir := bigDirtyRepo(t, 20000)
	prev := stashSnapshotTimeout
	t.Cleanup(func() { stashSnapshotTimeout = prev })

	lock := filepath.Join(dir, ".git", "index.lock")
	timedOut := 0
	at := time.Now().Add(time.Hour)
	for _, d := range []time.Duration{10, 20, 35, 50, 75, 100, 150, 200, 300, 400} {
		at = at.Add(time.Minute) // a new mtime every round, so every refresh rehashes
		touchAll(t, dir, at)
		stashSnapshotTimeout = d * time.Millisecond
		if _, err := captureRepo(dir); errors.Is(err, errGitTimedOut) {
			timedOut++
		}
		if _, err := os.Stat(lock); err == nil {
			t.Fatalf("timeout %v left %s behind; the developer's next git add would fail", stashSnapshotTimeout, lock)
		}
	}
	if timedOut == 0 {
		t.Skip("every snapshot finished inside the shortest timeout; this machine is too fast to exercise the kill")
	}
	// The real index must still be usable by the developer.
	gitRun(t, dir, "add", "-A")
}

// The snapshot must not need the developer's index lock at all. A lock that exists
// because the developer is mid-commit (or a stale one we did not create) used to fail
// the capture; it must now neither fail it nor be touched.
func TestSnapshotIgnoresAndPreservesAForeignIndexLock(t *testing.T) {
	isolateSessionScratch(t)
	dir, session := initRepo(t)
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte("import os\nimport sys\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	lock := filepath.Join(dir, ".git", "index.lock")
	if err := os.WriteFile(lock, []byte("someone else's"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(lock) })

	if err := CaptureBaseline(dir, session); err != nil {
		t.Fatalf("capture must not need the index lock: %v", err)
	}
	got, err := os.ReadFile(lock)
	if err != nil || string(got) != "someone else's" {
		t.Fatalf("a lock the plugin did not create was touched (err=%v, content=%q)", err, got)
	}
	// The pre-existing uncommitted edit is in the baseline, so nothing is this turn's.
	changes, ok, skip, err := ChangedFiles(dir, session)
	if !ok || err != nil || len(changes) != 0 {
		t.Fatalf("want an empty authoritative change set, got ok=%v skip=%q err=%v changes=%d", ok, skip, err, len(changes))
	}
}

// A failed snapshot is a failure: no scratch, the previous turn's baseline gone, and the
// Stop names the cause. It used to be swallowed into a HEAD baseline and logged as
// "git baseline captured".
func TestFailedSnapshotIsReportedAsAFailure(t *testing.T) {
	isolateSessionScratch(t)
	dir, session := initRepo(t)
	if err := CaptureBaseline(dir, session); err != nil {
		t.Fatal(err)
	}
	scoped := scopedSession(dir, session)
	if _, err := os.Stat(scratchPath(scoped)); err != nil {
		t.Fatalf("first capture wrote no scratch: %v", err)
	}

	prev := stashSnapshotTimeout
	stashSnapshotTimeout = time.Nanosecond
	err := CaptureBaseline(dir, session)
	stashSnapshotTimeout = prev
	if !errors.Is(err, errGitTimedOut) {
		t.Fatalf("want a timeout error, got %v", err)
	}
	if _, err := os.Stat(scratchPath(scoped)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the previous turn's scratch survived a failed capture (err=%v)", err)
	}
	if _, ok, skip, _ := ChangedFiles(dir, session); ok || skip != SkipCaptureFailed {
		t.Fatalf("want ok=false skip=%q, got ok=%v skip=%q", SkipCaptureFailed, ok, skip)
	}

	// The next good capture clears the failure.
	if err := CaptureBaseline(dir, session); err != nil {
		t.Fatal(err)
	}
	if _, ok, skip, _ := ChangedFiles(dir, session); !ok {
		t.Fatalf("a good capture after a failed one must review again, got skip=%q", skip)
	}
}

// A repository with no commits still captures (the empty-tree baseline): stash create
// refuses an unborn branch, and that refusal must not now read as a failure.
func TestUnbornRepoStillCaptures(t *testing.T) {
	isolateSessionScratch(t)
	dir := t.TempDir()
	gitRun(t, dir, "init", "-q")
	out, err := captureRepo(dir)
	if err != nil || out[:len(emptyTree)] != emptyTree {
		t.Fatalf("want the empty-tree baseline, got %q err=%v", out, err)
	}
}

// A repository discovered at PreToolUse reports its snapshot failure rather than
// recording nothing and saying nothing.
func TestRecordEditedRepoReturnsASnapshotFailure(t *testing.T) {
	isolateSessionScratch(t)
	other, _ := initRepo(t)
	workspace := t.TempDir()
	prev := stashSnapshotTimeout
	stashSnapshotTimeout = time.Nanosecond
	defer func() { stashSnapshotTimeout = prev }()
	if err := RecordEditedRepo(filepath.Join(other, "app.py"), workspace, "sess"); !errors.Is(err, errGitTimedOut) {
		t.Fatalf("want the timeout surfaced, got %v", err)
	}
}

// A linked worktree keeps its index in its own per-worktree git dir. The snapshot must
// copy THAT index, or a change staged in the worktree before the turn would read as
// this turn's work.
func TestSnapshotUsesALinkedWorktreesOwnIndex(t *testing.T) {
	isolateSessionScratch(t)
	main, session := initRepo(t)
	wt := filepath.Join(t.TempDir(), "wt")
	gitRun(t, main, "worktree", "add", "-q", "-b", "side", wt)
	if err := os.WriteFile(filepath.Join(wt, "app.py"), []byte("import os\nimport sys\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, wt, "add", "app.py") // staged before the turn starts
	t.Cleanup(func() { _ = os.Remove(scratchPath(scopedSession(wt, session))) })

	if err := CaptureBaseline(wt, session); err != nil {
		t.Fatal(err)
	}
	changes, ok, skip, err := ChangedFiles(wt, session)
	if !ok || err != nil || len(changes) != 0 {
		t.Fatalf("pre-turn staged work leaked into the turn: ok=%v skip=%q err=%v changes=%d", ok, skip, err, len(changes))
	}
}
