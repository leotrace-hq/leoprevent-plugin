package vcs

import "strings"

// OnDefaultBranch says whether the repository at root has its default branch checked out: true
// or false, nil when it can't tell (not a repository, a detached HEAD, no default branch known,
// any git error). The default branch is the one origin's HEAD names; without that ref, main if
// the repository has a local main, else master if it has one. It reads local refs only: no
// network, and never `git remote set-head`, which would change the developer's repository.
//
// A flag for /dependencies (LEO-513), so a fix on a feature branch isn't read as fixed for
// everyone. The branch's name never leaves this function.
func OnDefaultBranch(root string) *bool {
	out, err := git(root, "symbolic-ref", "--quiet", "--short", "HEAD")
	current := strings.TrimSpace(out)
	if err != nil || current == "" {
		return nil // detached, or not a repository
	}
	def := defaultBranch(root)
	if def == "" {
		return nil
	}
	on := current == def
	return &on
}

// defaultBranch is the repository's default branch's name, or "" when none is known.
func defaultBranch(root string) string {
	if out, err := git(root, "symbolic-ref", "--quiet", "--short", "refs/remotes/origin/HEAD"); err == nil {
		if name, ok := strings.CutPrefix(strings.TrimSpace(out), "origin/"); ok && name != "" {
			return name
		}
		return ""
	}
	for _, name := range []string{"main", "master"} {
		if _, err := git(root, "show-ref", "--verify", "--quiet", "refs/heads/"+name); err == nil {
			return name
		}
	}
	return ""
}
