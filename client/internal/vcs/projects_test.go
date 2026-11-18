package vcs

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// The session scan looks in the repository the session is in, or the few beneath a workspace
// folder, and never in a folder that isn't a project.
func TestProjectReposDecidesWhatTheSessionIsWorkingOn(t *testing.T) {
	needGit(t)
	t.Setenv("HOME", t.TempDir()) // so the developer's real home folder never decides a case

	ws := t.TempDir()
	one := seedRepoAt(t, filepath.Join(ws, "one"), "app.py", "x = 1\n")
	if err := os.MkdirAll(filepath.Join(one, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := ProjectRepos(one); got.Skip != "" || len(got.Roots) != 1 || !sameDir(got.Roots[0], one) {
		t.Errorf("a repository: %+v", got)
	}
	if got := ProjectRepos(filepath.Join(one, "src")); len(got.Roots) != 1 || !sameDir(got.Roots[0], one) {
		t.Errorf("a folder inside a repository is that repository: %+v", got)
	}

	two := seedRepoAt(t, filepath.Join(ws, "group", "two"), "app.py", "x = 1\n")
	got := ProjectRepos(ws)
	var roots []string
	for _, r := range got.Roots {
		roots = append(roots, resolveDir(r))
	}
	if got.Skip != "" || !slices.Contains(roots, resolveDir(one)) || !slices.Contains(roots, resolveDir(two)) || len(roots) != 2 {
		t.Errorf("a workspace of two projects: %+v", got)
	}
	seedRepoAt(t, filepath.Join(ws, "three"), "app.py", "x = 1\n")
	if got := ProjectRepos(ws); got.Skip != SkipSeveralProjects || got.Roots != nil {
		t.Errorf("more projects than the review's fallback takes: %+v", got)
	}
	if got := ProjectRepos(t.TempDir()); got.Skip != SkipNoRepository {
		t.Errorf("a folder with no repository: %+v", got)
	}
	if got := ProjectRepos(""); got.Skip != SkipNoRepository {
		t.Errorf("no folder: %+v", got)
	}
}

// Never the home folder or the filesystem root, even when one is a repository.
func TestProjectReposNeverScansHomeOrRoot(t *testing.T) {
	needGit(t)
	home := seedRepoAt(t, filepath.Join(t.TempDir(), "home"), ".bashrc", "export X=1\n") // dotfiles in git
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home) // os.UserHomeDir reads this, not HOME, on Windows
	if got := ProjectRepos(home); got.Skip != SkipHomeFolder {
		t.Errorf("the home folder: %+v", got)
	}
	if err := os.MkdirAll(filepath.Join(home, ".config"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := ProjectRepos(filepath.Join(home, ".config")); got.Skip != SkipHomeFolder {
		t.Errorf("a folder whose repository is the home folder: %+v", got)
	}
	project := seedRepoAt(t, filepath.Join(home, "code", "app"), "app.py", "x = 1\n")
	if got := ProjectRepos(project); got.Skip != "" || len(got.Roots) != 1 {
		t.Errorf("a project of its own inside the home folder is fine: %+v", got)
	}
	if got := ProjectRepos(string(filepath.Separator)); got.Skip != SkipFilesystemRoot {
		t.Errorf("the filesystem root: %+v", got)
	}
}

// Tracked files and untracked ones git doesn't ignore; ignored files never.
func TestTrackedFilesFollowsGit(t *testing.T) {
	needGit(t)
	root := seedRepoAt(t, filepath.Join(t.TempDir(), "r"), "package-lock.json", "{}\n")
	for rel, body := range map[string]string{".gitignore": "build/\n", "web/package-lock.json": "{}\n", "build/package-lock.json": "{}\n"} {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	files, err := TrackedFiles(root)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(files, "package-lock.json") || !slices.Contains(files, "web/package-lock.json") || slices.Contains(files, "build/package-lock.json") {
		t.Errorf("files = %v", files)
	}
}
