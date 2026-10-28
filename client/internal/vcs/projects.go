package vcs

import (
	"os"
	"path/filepath"
	"strings"
)

// Why a folder isn't scanned for dependency files (Projects.Skip).
const (
	SkipHomeFolder      = "home folder"
	SkipFilesystemRoot  = "filesystem root"
	SkipNoRepository    = "no repository"
	SkipSeveralProjects = "several projects"
)

// Projects are the repositories the session-start scan of dependency files looks in (LEO-549),
// or why it looks in none.
type Projects struct {
	Roots []string
	// Skip is set when the folder isn't a project: the home folder or the filesystem root, no
	// repository in reach, or more than the review's fallback finds.
	Skip string
}

// ProjectRepos decides what a session in cwd is working on: the repository cwd is in, or, when
// cwd isn't one, the repositories beneath it found by the same bounded search the review's
// HEAD fallback uses (two levels, at most two repositories). It never answers with the home
// folder or the filesystem root, even when one is a repository (dotfiles kept in git): a scan
// there would report on every project the machine holds.
func ProjectRepos(cwd string) Projects {
	if cwd == "" {
		return Projects{Skip: SkipNoRepository}
	}
	if skip := notAProject(cwd); skip != "" {
		return Projects{Skip: skip}
	}
	if root := RepoRoot(cwd); root != "" {
		if skip := notAProject(root); skip != "" {
			return Projects{Skip: skip}
		}
		return Projects{Roots: []string{root}}
	}
	roots := reposBeneath(cwd, map[string]bool{})
	switch {
	case len(roots) == 0:
		return Projects{Skip: SkipNoRepository}
	case len(roots) > maxFallbackRepos:
		return Projects{Skip: SkipSeveralProjects}
	}
	return Projects{Roots: roots}
}

// notAProject names the folders that are never a project of their own.
func notAProject(dir string) string {
	d := resolveDir(filepath.Clean(dir))
	if d == filepath.Dir(d) {
		return SkipFilesystemRoot
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" && sameDir(d, resolveDir(home)) {
		return SkipHomeFolder
	}
	return ""
}

// TrackedFiles lists a repository's files as git sees them: tracked, plus untracked ones git
// doesn't ignore, as paths relative to root with forward slashes. Git-ignored paths never
// appear, so the scan never reads what the project itself keeps out (an installed
// node_modules, build output). It walks nothing itself.
func TrackedFiles(root string) ([]string, error) {
	out, err := git(root, "ls-files", "-z", "--cached", "--others", "--exclude-standard")
	if err != nil {
		return nil, err
	}
	var files []string
	seen := map[string]bool{}
	for _, f := range strings.Split(out, "\x00") {
		if f != "" && !seen[f] {
			seen[f] = true
			files = append(files, f)
		}
	}
	return files, nil
}
