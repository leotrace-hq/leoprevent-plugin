package engine

import (
	"log/slog"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/depcheck"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/policycheck"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/vcs"
	"github.com/leotrace-hq/leoprevent-plugin/pathgate"
)

type pathExclusions map[string][]string

func policyExclusions(r Reviewer,
	cwd string,
	changes []transcript.Change,
	now time.Time) pathExclusions {
	pc, ok := r.(policycheck.Checker)
	if !ok {
		return nil
	}
	return policycheck.Check(pc, licenseKey(), turnRepos(cwd, changes), now).ExcludedPaths
}

func (x pathExclusions) split(cwd string,
	usedGit bool,
	changes []transcript.Change) ([]transcript.Change, []transcript.Change) {
	if len(x) == 0 {
		return changes, nil
	}
	origins := map[string]string{}
	originOf := func(c transcript.Change) string {
		if o, ok := origins[c.RepoDir]; ok {
			return o
		}
		dir := cwd
		if c.RepoDir != "" {
			dir = changeRoot(cwd, c)
		}
		o := vcs.RepoOrigin(dir)
		origins[c.RepoDir] = o
		return o
	}
	offset := ""
	if !usedGit {
		offset = cwdOffset(cwd)
	}
	kept := make([]transcript.Change, 0, len(changes))
	var dropped []transcript.Change
	for _, c := range changes {
		if c.Virtual {
			kept = append(kept, c)
			continue
		}
		patterns := x[originOf(c)]
		if _, ok := pathgate.ExcludedPath(patterns, repoRelative(c, offset)); ok {
			dropped = append(dropped, c)
			continue
		}
		c.ExcludedPaths = patterns
		kept = append(kept, c)
	}
	return kept, dropped
}

func (x pathExclusions) drop(cwd string,
	usedGit bool,
	changes []transcript.Change,
	log *slog.Logger,
	what string) []transcript.Change {
	kept, dropped := x.split(cwd, usedGit, changes)
	logExcluded(log, what, dropped)
	return kept
}

func logExcluded(log *slog.Logger,
	what string,
	dropped []transcript.Change) {
	if len(dropped) == 0 {
		return
	}
	paths := make([]string, len(dropped))
	for i, c := range dropped {
		paths[i] = c.FilePath
	}
	log.Info("changed files not sent: organisation excluded paths", "for", what, "excluded", len(dropped), "paths", strings.Join(paths, ", "))
}

func repoRelative(c transcript.Change,
	offset string) string {
	if c.RepoDir != "" {
		return strings.TrimPrefix(c.FilePath, c.RepoDir+"/")
	}
	p := filepath.ToSlash(c.FilePath)
	if offset == "" || filepath.IsAbs(c.FilePath) {
		return p
	}
	return path.Join(offset, p)
}

func cwdOffset(cwd string) string {
	root := vcs.RepoRoot(cwd)
	if cwd == "" || root == "" {
		return ""
	}
	rel, err := filepath.Rel(resolvedPath(root), resolvedPath(cwd))
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return ""
	}
	return filepath.ToSlash(rel)
}

func (x pathExclusions) lister() depcheck.Lister {
	if len(x) == 0 {
		return projectLister
	}
	return depcheck.Lister{
		Projects: projectLister.Projects,
		Files: func(root string) ([]string, error) {
			files, err := projectLister.Files(root)
			patterns := x[vcs.RepoOrigin(root)]
			if err != nil || len(patterns) == 0 {
				return files, err
			}
			kept := make([]string, 0, len(files))
			for _, f := range files {
				if _, ok := pathgate.ExcludedPath(patterns, f); !ok {
					kept = append(kept, f)
				}
			}
			return kept, nil
		},
	}
}
