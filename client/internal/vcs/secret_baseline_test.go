package vcs

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/pathgate"
)

// noGitIdentity makes git behave as on a machine (or CI runner) with no user.name or
// user.email: no global or system config, and no guessing from the host name. stash
// create has a fallback identity there; commit-tree does not.
func noGitIdentity(t *testing.T) {
	t.Helper()
	cfg := filepath.Join(t.TempDir(), "gitconfig")
	if err := os.WriteFile(cfg, []byte("[user]\n\tuseConfigOnly = true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_CONFIG_GLOBAL", cfg)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
}

// dirtyRepoWithSecrets is a repository whose committed .env was modified in the working
// tree, with a never-committed key staged and an ordinary code change.
func dirtyRepoWithSecrets(t *testing.T) string {
	t.Helper()
	dir, _ := initRepo(t)
	writeFile(t, filepath.Join(dir, ".env"), "TOKEN=committed\n")
	writeFile(t, filepath.Join(dir, "sub/handler.py"), "def h(): pass\n")
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-q", "-m", "env")
	writeFile(t, filepath.Join(dir, ".env"), "TOKEN=modified-not-committed\n")
	writeFile(t, filepath.Join(dir, "deploy.pem"), "-----BEGIN KEY-----\n")
	gitRun(t, dir, "add", "deploy.pem")
	writeFile(t, filepath.Join(dir, "app.py"), "import sys\n")
	return dir
}

// LEO-1040: the turn-start baseline is pinned under refs/leoprevent/baselines/ for 24h.
// A key the developer staged, or a secret file's uncommitted content, must not be in
// that commit, because it would outlive its deletion and ship on `git push --mirror`.
// Captured from a subdirectory, as the agent's cwd often is: ls-files and pathspecs are
// relative to it, and an earlier version missed both secrets from there.
func TestBaselineSnapshotKeepsSecretContentOutOfThePinnedCommit(t *testing.T) {
	noGitIdentity(t)
	dir := dirtyRepoWithSecrets(t)

	block, err := captureRepo(filepath.Join(dir, "sub"), "test")
	if err != nil {
		t.Fatalf("captureRepo: %v", err)
	}
	ref := strings.SplitN(block, "\n", 2)[0]
	if ref == gitOut(t, dir, "rev-parse", "HEAD") || ref == emptyTree {
		t.Fatalf("expected a baseline commit for a dirty tree, got %q", ref)
	}

	if files := gitOut(t, dir, "ls-tree", "-r", "--name-only", ref); strings.Contains(files, "deploy.pem") {
		t.Errorf("baseline holds the staged key deploy.pem:\n%s", files)
	}
	if got, want := gitOut(t, dir, "rev-parse", ref+":.env"), gitOut(t, dir, "rev-parse", "HEAD:.env"); got != want {
		t.Errorf("baseline .env is %s, want HEAD's %s (the uncommitted content must not be pinned)", got, want)
	}
	if got := gitOut(t, dir, "show", ref+":app.py"); got != "import sys" {
		t.Errorf("baseline app.py = %q, want the working tree's change", got)
	}
	// Outside secret paths the baseline is the tree stash create would write, so nothing
	// else the developer had changed reads as this turn's work. (Secret paths do differ,
	// and ChangedFiles drops them.)
	for _, p := range strings.Split(gitOut(t, dir, "diff", "--name-only", ref), "\n") {
		if p != "" && !pathgate.IsSecretPath(p) {
			t.Errorf("working tree differs from the baseline in non-secret path %q", p)
		}
	}

	if staged := gitOut(t, dir, "diff", "--cached", "--name-only"); !strings.Contains(staged, "deploy.pem") {
		t.Errorf("the developer's real index lost the staged key; staged=%q", staged)
	}
	assertNotInObjectStore(t, dir, ".env")
}

// assertNotInObjectStore fails when the working copy of path was written into the
// repository's objects. The baseline's index copy shares them, so refreshing a secret
// path there would leave its uncommitted bytes in .git/objects (and in any copy of
// .git) even when the pinned commit leaves them out.
func assertNotInObjectStore(t *testing.T, dir, path string) {
	t.Helper()
	blob := gitOut(t, dir, "hash-object", "--no-filters", path)
	if err := exec.Command("git", "-C", dir, "cat-file", "-e", blob).Run(); err == nil {
		t.Errorf("the uncommitted content of %s was written to the object store as %s", path, blob)
	}
}

// Codex on #2225: a developer staged the removal of their tracked .env (`git rm
// --cached`) and kept an edited copy. The index no longer lists it, but stash create
// would still write the working copy into the stash, because the path differs from HEAD.
func TestStagedRemovalOfASecretKeepsItsWorkingCopyOutOfTheBaseline(t *testing.T) {
	noGitIdentity(t)
	dir, _ := initRepo(t)
	writeFile(t, filepath.Join(dir, ".env"), "TOKEN=committed\n")
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-q", "-m", "env")
	gitRun(t, dir, "rm", "-q", "--cached", ".env")
	writeFile(t, filepath.Join(dir, ".env"), "TOKEN=local-only\n")
	writeFile(t, filepath.Join(dir, "app.py"), "import sys\n")

	block, err := captureRepo(dir, "test")
	if err != nil {
		t.Fatalf("captureRepo: %v", err)
	}
	ref := strings.SplitN(block, "\n", 2)[0]
	if got, want := gitOut(t, dir, "rev-parse", ref+":.env"), gitOut(t, dir, "rev-parse", "HEAD:.env"); got != want {
		t.Errorf("baseline .env is %s, want HEAD's %s", got, want)
	}
	if got := gitOut(t, dir, "show", ref+":app.py"); got != "import sys" {
		t.Errorf("baseline app.py = %q, want the working tree's change", got)
	}
	assertNotInObjectStore(t, dir, ".env")
}

// A committed secret file (a .env.example is common) on a clean tree must keep HEAD as
// the baseline, as stash create does. Dropping the path instead made every turn in such
// a repository build and pin a commit that differs from HEAD only by that file.
func TestCleanTreeWithACommittedSecretKeepsHEADAsBaseline(t *testing.T) {
	dir, _ := initRepo(t)
	writeFile(t, filepath.Join(dir, ".env.example"), "TOKEN=\n")
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-q", "-m", "example")

	block, err := captureRepo(dir, "test")
	if err != nil {
		t.Fatalf("captureRepo: %v", err)
	}
	if ref, head := strings.SplitN(block, "\n", 2)[0], gitOut(t, dir, "rev-parse", "HEAD"); ref != head {
		t.Errorf("baseline = %s, want HEAD %s", ref, head)
	}
	if refs := gitOut(t, dir, "for-each-ref", "refs/leoprevent/"); refs != "" {
		t.Errorf("a clean tree pinned a baseline: %s", refs)
	}
}
