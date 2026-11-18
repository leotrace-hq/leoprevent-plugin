package vcs

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func gitOut(t *testing.T, dir string, args ...string) string {
	t.Helper()
	out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).Output()
	if err != nil {
		t.Fatalf("git %s: %v", strings.Join(args, " "), err)
	}
	return strings.TrimSpace(string(out))
}

// prune is the harshest collection a developer's tooling can run: expire every reflog,
// then gc with no grace period, so anything unreachable from a ref is deleted.
func prune(t *testing.T, dir string) {
	t.Helper()
	gitRun(t, dir, "reflog", "expire", "--expire=now", "--all")
	gitRun(t, dir, "gc", "-q", "--prune=now")
}

// dirtyTurn starts a turn on a repository with uncommitted work, so the baseline is a
// real stash commit rather than HEAD, then has the "agent" add a line.
func dirtyTurn(t *testing.T) (dir, session, stash string) {
	t.Helper()
	dir, session = initRepo(t)
	t.Cleanup(func() { ClearBaseline(dir, session) })
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte("import os\nprint('wip')\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := CaptureBaseline(dir, session); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(scratchPath(scopedSession(dir, session)))
	if err != nil {
		t.Fatal(err)
	}
	stash = strings.TrimSpace(strings.SplitN(string(data), "\n", 2)[0])
	if stash == gitOut(t, dir, "rev-parse", "HEAD") {
		t.Fatal("baseline is HEAD; the test needs a stash commit")
	}
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte("import os\nprint('wip')\nos.system(input())\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir, session, stash
}

// TestBaselineSurvivesGarbageCollection is LEO-394: a gc between the turn-start capture
// and the Stop deleted the dangling stash commit, and the Stop fell back to the
// transcript with SkipBaselineGone. The pin keeps it reachable.
func TestBaselineSurvivesGarbageCollection(t *testing.T) {
	dir, session, _ := dirtyTurn(t)
	prune(t, dir)

	changes, ok, skip, err := ChangedFiles(dir, session)
	if err != nil || !ok {
		t.Fatalf("ChangedFiles after gc: ok=%v skip=%q err=%v, want the git path", ok, skip, err)
	}
	if len(changes) != 1 || changes[0].FilePath != "app.py" {
		t.Fatalf("changes = %+v, want app.py", changes)
	}
	// Turn-scoped: the pre-existing uncommitted line is NOT this turn's.
	if got := changes[0].AddedText; !strings.Contains(got, "os.system") || strings.Contains(got, "wip") {
		t.Errorf("AddedText = %q, want only the line added this turn", got)
	}
}

// TestBaselinePinIsInvisibleToEverydayGit: the pin must not appear as a branch, a tag or
// a stash entry, and must not touch the working tree or index.
func TestBaselinePinIsInvisibleToEverydayGit(t *testing.T) {
	dir, session, stash := dirtyTurn(t)
	if got, want := gitOut(t, dir, "for-each-ref", "--format=%(refname)", baselineRefPrefix), sessionPinPrefix(session)+stash; got != want {
		t.Fatalf("pins = %q, want exactly %s", got, want)
	}
	if got := gitOut(t, dir, "branch", "--list"); got != "* master" {
		t.Errorf("git branch = %q", got)
	}
	if got := gitOut(t, dir, "tag", "--list"); got != "" {
		t.Errorf("git tag = %q", got)
	}
	if got := gitOut(t, dir, "stash", "list"); got != "" {
		t.Errorf("git stash list = %q", got)
	}
}

// TestBaselineGoneIsReportedOnlyWhenTheCommitIsGone keeps the two diff failures apart:
// a really missing baseline is SkipBaselineGone, as before.
func TestBaselineGoneIsReportedOnlyWhenTheCommitIsGone(t *testing.T) {
	dir, session, stash := dirtyTurn(t)
	gitRun(t, dir, "update-ref", "-d", sessionPinPrefix(session)+stash)
	prune(t, dir)
	if _, ok, skip, _ := ChangedFiles(dir, session); ok || skip != SkipBaselineGone {
		t.Fatalf("ok=%v skip=%q, want SkipBaselineGone", ok, skip)
	}
}

func TestBaselineDiffFailureWithTheCommitPresentIsNotBlamedOnGC(t *testing.T) {
	dir, session, _ := dirtyTurn(t)
	// A ref that exists but is a blob: the object is present, the diff cannot use it.
	blob := gitOut(t, dir, "hash-object", "-w", "app.py")
	path := scratchPath(scopedSession(dir, session))
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.SplitN(string(data), "\n", 2)
	if err := os.WriteFile(path, []byte(blob+"\n"+lines[1]), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok, skip, _ := ChangedFiles(dir, session); ok || skip != SkipBaselineDiffFailed {
		t.Fatalf("ok=%v skip=%q, want SkipBaselineDiffFailed", ok, skip)
	}
}

// TestExpiredBaselinePinsArePruned: pins are pruned by age at every capture, so a
// repository never accumulates them; a fresh one stays.
func TestExpiredBaselinePinsArePruned(t *testing.T) {
	dir, _, stash := dirtyTurn(t)
	pruneBaselineRefs(dir, time.Now())
	if gitOut(t, dir, "for-each-ref", baselineRefPrefix) == "" {
		t.Fatal("a fresh pin was pruned")
	}
	pruneBaselineRefs(dir, time.Now().Add(baselineRefTTL+time.Hour))
	if got := gitOut(t, dir, "for-each-ref", baselineRefPrefix); got != "" {
		t.Fatalf("expired pin survived: %q (stash %s)", got, stash)
	}
}

// TestClearBaselineRemovesTheSessionsPin: the end of a headless run leaves no ref behind.
func TestClearBaselineRemovesTheSessionsPin(t *testing.T) {
	dir, session, _ := dirtyTurn(t)
	ClearBaseline(dir, session)
	if got := gitOut(t, dir, "for-each-ref", baselineRefPrefix); got != "" {
		t.Fatalf("pin survived ClearBaseline: %q", got)
	}
}

func TestIsObjectID(t *testing.T) {
	for s, want := range map[string]bool{
		strings.Repeat("a", 40):       true,
		strings.Repeat("0", 64):       true,
		strings.Repeat("A", 40):       false,
		"../../heads/main":            false,
		strings.Repeat("a", 39) + "/": false,
		"":                            false,
	} {
		if got := isObjectID(s); got != want {
			t.Errorf("isObjectID(%q) = %v, want %v", s, got, want)
		}
	}
}

// TestConcurrentSessionsKeepTheirOwnPins: two sessions that snapshot the identical
// working tree get the identical stash commit. When one ends (ClearBaseline) the other's
// baseline must stay pinned, or the next gc deletes it from under a live session.
func TestConcurrentSessionsKeepTheirOwnPins(t *testing.T) {
	dir, a := initRepo(t)
	b := a + "-other"
	t.Cleanup(func() { ClearBaseline(dir, a); ClearBaseline(dir, b) })
	// A fixed, recent commit date makes both `git stash create` calls produce one SHA
	// regardless of a second boundary between them.
	date := strconv.FormatInt(time.Now().Unix(), 10) + " +0000"
	t.Setenv("GIT_COMMITTER_DATE", date)
	t.Setenv("GIT_AUTHOR_DATE", date)
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte("import os\nprint('wip')\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	stashOf := func(session string) string {
		if err := CaptureBaseline(dir, session); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(scratchPath(scopedSession(dir, session)))
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(strings.SplitN(string(data), "\n", 2)[0])
	}
	if sa, sb := stashOf(a), stashOf(b); sa != sb || sa == gitOut(t, dir, "rev-parse", "HEAD") {
		t.Fatalf("stash a=%s b=%s; the test needs one shared stash commit", sa, sb)
	}
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte("import os\nprint('wip')\nos.system(input())\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	ClearBaseline(dir, a)
	prune(t, dir)

	changes, ok, skip, err := ChangedFiles(dir, b)
	if err != nil || !ok {
		t.Fatalf("session b after a cleared and gc ran: ok=%v skip=%q err=%v, want its baseline intact", ok, skip, err)
	}
	if len(changes) != 1 || !strings.Contains(changes[0].AddedText, "os.system") {
		t.Fatalf("changes = %+v, want app.py's os.system line", changes)
	}
}
