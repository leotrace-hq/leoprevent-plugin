package delivery

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
)

func gitRepo(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range files {
		fp := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(fp), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(fp, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	run := func(args ...string) {
		c := exec.Command("git", append([]string{"-C", dir}, args...)...)
		c.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-q")
	run("add", "-A")
	run("commit", "-q", "-m", "init")
}

// ⚠️ THE EGRESS GUARD. Two projects in one workspace, each with a helpers.py. A change
// in project-a that imports `helpers` must resolve to project-a's file and NEVER to
// project-b's — resolving against the workspace folder instead of the repository root
// would send another project's source to the server as "context".
func TestImportsNeverResolveIntoASiblingProject(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	ws := t.TempDir()
	gitRepo(t, filepath.Join(ws, "project-a"), map[string]string{
		"helpers.py": "def fetch(url):\n    return MINE_PROJECT_A\n",
		"app.py":     "from helpers import fetch\n",
	})
	gitRepo(t, filepath.Join(ws, "project-b"), map[string]string{
		"helpers.py": "def fetch(url):\n    return SECRET_OF_PROJECT_B\n",
	})

	changes := []transcript.Change{{
		FilePath:  "project-a/app.py",
		RepoDir:   "project-a",
		RepoRoot:  filepath.Join(ws, "project-a"),
		AddedText: "from helpers import fetch\nfetch(url)\n",
	}}
	got := resolveContext(ws, changes)

	for _, cf := range got {
		if strings.Contains(cf.Content, "SECRET_OF_PROJECT_B") {
			t.Fatalf("EGRESS BUG: a sibling project's source was resolved as context (%s)", cf.Path)
		}
		if !strings.HasPrefix(cf.Path, "project-a/") {
			t.Errorf("context paths must be qualified by their repo, got %q", cf.Path)
		}
	}
	// And it must actually have found project-a's own helper, or the test proves nothing.
	var found bool
	for _, cf := range got {
		if strings.Contains(cf.Content, "MINE_PROJECT_A") {
			found = true
		}
	}
	if !found {
		t.Error("expected project-a's own helper to be resolved; the guard above is vacuous without it")
	}
}

// A single-repo turn is unchanged: no RepoDir, no prefix on the context paths.
func TestSingleRepoContextIsUnprefixed(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	repo := filepath.Join(t.TempDir(), "solo")
	gitRepo(t, repo, map[string]string{
		"helpers.py": "def fetch(url):\n    return 1\n",
		"app.py":     "from helpers import fetch\n",
	})
	changes := []transcript.Change{{
		FilePath:  "app.py",
		AddedText: "from helpers import fetch\nfetch(url)\n",
	}}
	for _, cf := range resolveContext(repo, changes) {
		if strings.Contains(cf.Path, "/") && strings.HasPrefix(cf.Path, "solo/") {
			t.Errorf("a single-repo turn must not gain a repo prefix, got %q", cf.Path)
		}
	}
}

// A workspace folder with no repository under the changed file contributes nothing
// rather than falling back to some other root.
func TestUnresolvableRepoContributesNoContext(t *testing.T) {
	changes := []transcript.Change{{
		FilePath: "nowhere/app.py",
		RepoDir:  "nowhere",
		RepoRoot: filepath.Join(t.TempDir(), "nowhere"),
	}}
	if got := resolveContext(t.TempDir(), changes); len(got) != 0 {
		t.Errorf("expected no context, got %+v", got)
	}
}

// ⚠️ THE DECISIVE VERSION OF THE GUARD ABOVE. Here the helper exists ONLY in the
// sibling project, so the correct answer is NO context at all. A resolver anchored on
// the workspace folder would find project-b's file and egress it; one anchored on the
// repository root cannot see it. Deterministic, unlike the two-helpers case, where
// either file could legitimately match.
func TestAnImportMatchingOnlyASiblingResolvesToNothing(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	ws := t.TempDir()
	gitRepo(t, filepath.Join(ws, "project-a"), map[string]string{
		"app.py": "from shared_helpers import fetch\n",
	})
	gitRepo(t, filepath.Join(ws, "project-b"), map[string]string{
		"shared_helpers.py": "def fetch(url):\n    return SECRET_OF_PROJECT_B\n",
	})

	changes := []transcript.Change{{
		FilePath:  "project-a/app.py",
		RepoDir:   "project-a",
		RepoRoot:  filepath.Join(ws, "project-a"),
		AddedText: "from shared_helpers import fetch\nfetch(url)\n",
	}}
	for _, cf := range resolveContext(ws, changes) {
		if strings.Contains(cf.Content, "SECRET_OF_PROJECT_B") {
			t.Fatalf("EGRESS BUG: resolved a sibling project's file as context (%s)", cf.Path)
		}
	}
}

// The same question for an INDEX-based language. Go's resolver builds an index over
// the root it is given, so a workspace-wide root is where a cross-project match is
// most plausible. project-a imports a package that exists ONLY in project-b.
func TestGoImportMatchingOnlyASiblingResolvesToNothing(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	ws := t.TempDir()
	gitRepo(t, filepath.Join(ws, "project-a"), map[string]string{
		"go.mod":  "module example.com/a\n\ngo 1.22\n",
		"main.go": "package main\n\nimport \"example.com/b/helpers\"\n\nfunc main() { helpers.Fetch(\"x\") }\n",
	})
	gitRepo(t, filepath.Join(ws, "project-b"), map[string]string{
		"go.mod":             "module example.com/b\n\ngo 1.22\n",
		"helpers/helpers.go": "package helpers\n\nfunc Fetch(u string) string { return SECRET_OF_PROJECT_B }\n",
	})

	changes := []transcript.Change{{
		FilePath:  "project-a/main.go",
		RepoDir:   "project-a",
		RepoRoot:  filepath.Join(ws, "project-a"),
		AddedText: "import \"example.com/b/helpers\"\nhelpers.Fetch(\"x\")\n",
	}}
	for _, cf := range resolveContext(ws, changes) {
		if strings.Contains(cf.Content, "SECRET_OF_PROJECT_B") {
			t.Fatalf("EGRESS: resolved a sibling project's Go package as context (%s)", cf.Path)
		}
	}
}

// ⚠️ THE REGRESSION FOR THE LABEL-IS-A-BASENAME CHANGE. A repository discovered at
// PreToolUse can live ANYWHERE, so its label is only its basename — and here cwd holds
// a DIFFERENT project of the same name. Rebuilding the root as cwd/label finds that one
// and egresses its source as context for a change that was made somewhere else
// entirely. Fails against the cwd-join resolver.
func TestASameNamedProjectInCwdIsNotResolvedForARepoElsewhere(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	ws := t.TempDir()
	// The decoy: same basename, sitting inside the folder the editor has open.
	gitRepo(t, filepath.Join(ws, "alpha"), map[string]string{
		"helpers.py": "def fetch(url):\n    return SECRET_OF_THE_DECOY\n",
	})
	// The real one, nowhere near cwd.
	elsewhere := filepath.Join(t.TempDir(), "somewhere-else", "alpha")
	gitRepo(t, elsewhere, map[string]string{
		"helpers.py": "def fetch(url):\n    return MINE_REAL_ALPHA\n",
		"app.py":     "from helpers import fetch\n",
	})

	changes := []transcript.Change{{
		FilePath:  "alpha/app.py",
		RepoDir:   "alpha",
		RepoRoot:  elsewhere,
		AddedText: "from helpers import fetch\nfetch(url)\n",
	}}
	got := resolveContext(ws, changes)
	for _, cf := range got {
		if strings.Contains(cf.Content, "SECRET_OF_THE_DECOY") {
			t.Fatalf("EGRESS BUG: resolved a same-named project inside cwd (%s)", cf.Path)
		}
	}
	var found bool
	for _, cf := range got {
		if strings.Contains(cf.Content, "MINE_REAL_ALPHA") {
			found = true
		}
	}
	if !found {
		t.Error("expected the real repository's helper to be resolved; the guard is vacuous without it")
	}
}

// A labelled change carrying no root resolves NOTHING rather than falling back to cwd,
// which is the same wrong-project answer one step removed.
func TestALabelledChangeWithNoRootResolvesNothing(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	ws := t.TempDir()
	gitRepo(t, filepath.Join(ws, "alpha"), map[string]string{
		"helpers.py": "def fetch(url):\n    return SECRET_OF_THE_DECOY\n",
	})
	changes := []transcript.Change{{
		FilePath:  "alpha/app.py",
		RepoDir:   "alpha",
		AddedText: "from helpers import fetch\nfetch(url)\n",
	}}
	if got := resolveContext(ws, changes); len(got) != 0 {
		t.Errorf("expected no context without a recorded root, got %+v", got)
	}
}
