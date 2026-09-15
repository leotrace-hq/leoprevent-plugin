package vcs

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
)

func prRepo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	for _, args := range [][]string{
		{"init", "-q", "-b", "main"},
		{"config", "user.email", "t@t"},
		{"config", "user.name", "t"},
	} {
		if out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	return dir
}

func gitDo(t *testing.T, dir string, args ...string) {
	t.Helper()
	if out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func write(t *testing.T, dir, rel, body string) {
	t.Helper()
	p := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func commit(t *testing.T, dir, msg string) {
	t.Helper()
	gitDo(t, dir, "add", "-A")
	gitDo(t, dir, "commit", "-qm", msg)
}

// TestDiffRangeIsTheBranchsOwnWork is the merge-base regression, and it fails
// against a two-dot `git diff <base> HEAD`: with the base branch having moved on
// since the fork, that diff reports the base's own later commits as though the pull
// request were reverting them.
func TestDiffRangeIsTheBranchsOwnWork(t *testing.T) {
	dir := prRepo(t)
	write(t, dir, "seed.py", "seed = 1\n")
	commit(t, dir, "seed")

	// The branch forks here and adds ONE file.
	gitDo(t, dir, "checkout", "-q", "-b", "feature")
	write(t, dir, "mine.py", "import requests\nrequests.get(url)\n")
	commit(t, dir, "mine")

	// Meanwhile main moves on, twice — the ordinary state of a busy repository.
	gitDo(t, dir, "checkout", "-q", "main")
	write(t, dir, "someone-else.py", "other = 1\n")
	commit(t, dir, "theirs")
	write(t, dir, "seed.py", "seed = 2\n")
	commit(t, dir, "their edit")
	gitDo(t, dir, "checkout", "-q", "feature")

	changes, skip, err := DiffRange(dir, "main")
	if err != nil || skip != "" {
		t.Fatalf("DiffRange: skip=%q err=%v", skip, err)
	}
	got := map[string]bool{}
	for _, c := range changes {
		got[c.FilePath] = true
	}
	if !got["mine.py"] {
		t.Error("the branch's own file must be reviewed")
	}
	if got["someone-else.py"] || got["seed.py"] {
		t.Errorf("a pull request must not carry the BASE branch's later commits; got %v", keys(got))
	}
}

// TestDiffRangeCarriesRealAddedLineNumbers: the lane needs them twice over — the
// judge cites a line, and an inline review comment cannot be anchored without one.
// What must not happen is those numbers being read as authorship, and that is the
// SERVER's job (api.surfaceAll), not this function's.
func TestDiffRangeCarriesRealAddedLineNumbers(t *testing.T) {
	dir := prRepo(t)
	write(t, dir, "app.py", "one\ntwo\nthree\n")
	commit(t, dir, "seed")
	gitDo(t, dir, "checkout", "-q", "-b", "feature")
	write(t, dir, "app.py", "one\ntwo\nthree\nfour\n")
	commit(t, dir, "add a line")

	changes, skip, err := DiffRange(dir, "main")
	if err != nil || skip != "" {
		t.Fatalf("DiffRange: skip=%q err=%v", skip, err)
	}
	if len(changes) != 1 {
		t.Fatalf("changes = %v, want just app.py", pathsOfT(changes))
	}
	if len(changes[0].AddedLines) != 1 || changes[0].AddedLines[0] != 4 {
		t.Errorf("AddedLines = %v, want [4] — the real position in the head commit", changes[0].AddedLines)
	}
	if changes[0].FullContent == "" {
		t.Error("FullContent must travel: the judge reasons over the whole file, not the hunk")
	}
}

// TestDiffRangeIgnoresUntrackedFiles: a pull request is committed code. A build step
// that runs before the review would otherwise have its output reviewed as though
// somebody had proposed it — a false positive nobody on the pull request can act on.
func TestDiffRangeIgnoresUntrackedFiles(t *testing.T) {
	dir := prRepo(t)
	write(t, dir, "seed.py", "seed = 1\n")
	commit(t, dir, "seed")
	gitDo(t, dir, "checkout", "-q", "-b", "feature")
	write(t, dir, "proposed.py", "proposed = 1\n")
	commit(t, dir, "proposed")

	// A CI step's leftover: present, not ignored, not committed.
	write(t, dir, "build-output.py", "import os\nos.system(cmd)\n")

	changes, skip, err := DiffRange(dir, "main")
	if err != nil || skip != "" {
		t.Fatalf("DiffRange: skip=%q err=%v", skip, err)
	}
	for _, c := range changes {
		if c.FilePath == "build-output.py" {
			t.Error("an untracked file is the CI job's own doing, not part of the pull request")
		}
	}
	if len(changes) != 1 || changes[0].FilePath != "proposed.py" {
		t.Errorf("changes = %v, want just proposed.py", pathsOfT(changes))
	}
}

// TestDiffRangeRefusesRatherThanReturningNothing: on this lane an empty change set
// is indistinguishable from a pull request that proposes nothing reviewable, so a
// failure that returned one would read as a clean bill of health.
func TestDiffRangeRefusesRatherThanReturningNothing(t *testing.T) {
	dir := prRepo(t)
	write(t, dir, "seed.py", "seed = 1\n")
	commit(t, dir, "seed")

	if _, skip, _ := DiffRange(dir, "no-such-branch"); skip == "" {
		t.Error("an unresolvable base must yield a SkipReason, not an empty diff")
	}
	if _, skip, _ := DiffRange(dir, ""); skip == "" {
		t.Error("an empty base must yield a SkipReason")
	}
	if _, skip, _ := DiffRange(t.TempDir(), "main"); skip != SkipNotGitRepo {
		t.Errorf("a non-repository must report %q, got %q", SkipNotGitRepo, skip)
	}
}

// TestRevResolvesTellsABranchFromARef underpins the zero-config base: a
// pull_request checkout holds the base branch as a remote-tracking ref only.
func TestRevResolvesTellsABranchFromARef(t *testing.T) {
	dir := prRepo(t)
	write(t, dir, "seed.py", "seed = 1\n")
	commit(t, dir, "seed")

	if !RevResolves(dir, "main") {
		t.Error("main should resolve in a repository that has it")
	}
	if RevResolves(dir, "origin/main") {
		t.Error("origin/main must NOT resolve here: there is no remote")
	}
	if RevResolves(dir, "") {
		t.Error("an empty revision must never resolve")
	}
}

// pathsOfT names the collected paths for a failure message.
func pathsOfT(cs []transcript.Change) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.FilePath)
	}
	return out
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
