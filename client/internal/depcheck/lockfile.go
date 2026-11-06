package depcheck

import (
	"log/slog"
	"path/filepath"
	"strings"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/deps"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
)

// The mid-session check (LEO-819, decided 6 Nov 2026): when a turn changes code, the dependency
// file covering that code is scanned whole and its findings shown, so the developer hears about
// the dependency issues of the code they're working on, when they're working on it. The scan's
// notice at the session's start is off (engine.showSessionScan); this is how a developer hears
// about what was already there.
//
// The covering file is the nearest one of the code's own ecosystem in its folder or above, up to
// its repository's root: go.mod for a .go file; package-lock.json, npm-shrinkwrap.json or
// pnpm-lock.yaml for JavaScript and TypeScript. In an npm workspace that is the root's lockfile,
// so a change in one member reports the whole workspace's findings (decided 6 Nov 2026: scoping
// to the member's package.json is a follow-up). Code in any other language has no covering file.
// A folder with no repository has none either: its scan is gitlessCheck's.

// coveringNames are the dependency files that cover a source file, by its extension.
var coveringNames = map[string][]string{
	".go":     {"go.mod"},
	".js":     npmLocks,
	".jsx":    npmLocks,
	".mjs":    npmLocks,
	".cjs":    npmLocks,
	".ts":     npmLocks,
	".tsx":    npmLocks,
	".mts":    npmLocks,
	".cts":    npmLocks,
	".vue":    npmLocks,
	".svelte": npmLocks,
	".astro":  npmLocks,
}

// npmLocks are npm's and pnpm's lockfiles, in the order one is preferred when a folder has two.
var npmLocks = []string{"package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml"}

// Covering is the dependency files covering the code the turn changed: one per file, labelled as
// the scan labels it (its path in the repository, under the repository's folder when the turn
// spans several). A dependency file the turn changed itself is left out: the turn's own check has
// it (dependencyCheck), and the two never both report one file in a turn. So is a deleted or
// virtual change, code under node_modules/ or vendor/, and anything outside its repository.
func Covering(changes []transcript.Change, cwd string, log *slog.Logger) []ScanFile {
	changed := map[string]bool{}
	for _, p := range ChangedDependencyFiles(changes, cwd) {
		changed[p] = true
	}
	seen := map[string]bool{}
	var out []ScanFile
	for _, ch := range changes {
		names := coveringNames[strings.ToLower(filepath.Ext(ch.FilePath))]
		if ch.Virtual || ch.Deleted || ch.RepoRoot == "" || len(names) == 0 {
			continue
		}
		src, ok := onDisk(ch, cwd)
		if !ok {
			continue
		}
		rel, err := filepath.Rel(ch.RepoRoot, src)
		if err != nil || vendored(filepath.ToSlash(rel)) {
			continue
		}
		f, ok := nearest(ch.RepoRoot, filepath.Dir(src), names)
		if !ok {
			continue
		}
		key := resolved(f.Path)
		if changed[key] || seen[key] {
			continue
		}
		seen[key] = true
		if ch.RepoDir != "" {
			f.Label = ch.RepoDir + "/" + f.Label
		}
		out = append(out, f)
	}
	if len(out) > 0 {
		log.Debug("dependency check: files covering this turn's code", "files", len(out))
	}
	return out
}

// nearest walks up from dir to root and returns the first dependency file named in names that a
// scan would read: a regular file (never a symlink), inside root.
func nearest(root, dir string, names []string) (ScanFile, bool) {
	for {
		for _, n := range names {
			p := filepath.Join(dir, n)
			if regular(p) && within(root, p) {
				rel, err := filepath.Rel(root, p)
				if err != nil {
					return ScanFile{}, false
				}
				label := filepath.ToSlash(rel)
				return ScanFile{Label: label, Path: p, Root: root, depth: strings.Count(label, "/")}, true
			}
		}
		if filepath.Clean(dir) == filepath.Clean(root) {
			return ScanFile{}, false
		}
		parent := filepath.Dir(dir)
		if parent == dir || !within(root, parent) {
			return ScanFile{}, false
		}
		dir = parent
	}
}

// ChangedDependencyFiles is the dependency files among changes, by their resolved path on disk.
func ChangedDependencyFiles(changes []transcript.Change, cwd string) []string {
	var out []string
	for _, ch := range changes {
		if ch.Virtual {
			continue
		}
		if _, ok := deps.All.For(ch.FilePath); !ok {
			continue
		}
		if p, ok := onDisk(ch, cwd); ok {
			out = append(out, resolved(p))
		}
	}
	return out
}

// Key is how a dependency file is told apart across a session: its resolved path on disk.
func (f ScanFile) Key() string { return resolved(f.Path) }

// Without is w less the files whose Key is in drop.
func (w Workspace) Without(drop map[string]bool) Workspace {
	if len(drop) == 0 {
		return w
	}
	files := make([]ScanFile, 0, len(w.Files))
	for _, f := range w.Files {
		if !drop[f.Key()] {
			files = append(files, f)
		}
	}
	w.Files = files
	return w
}

// ScanLockfiles checks files whole for the mid-session check and returns the notice, with no
// summary line above it (LEO-819 cut 1: each file's own heading says it once), what the server
// put to the agent and its offer, and the Keys of the files the server answered. A file not
// answered (a timeout, a 5xx) isn't in checked, so a later turn tries it again. Like Scan, it
// says nothing when the server has no dependency check.
func ScanLockfiles(files []ScanFile, turnStart TurnStart, c Checker, log *slog.Logger) (text, markdown, agent, offer string, checked []string) {
	var items []item
	byLabel := map[string]string{}
	for _, f := range files {
		items = append(items, item{label: f.Label, path: f.Path, root: f.Root, rel: relativeOnly(f.Label), whole: true})
		byLabel[f.Label] = f.Key()
	}
	r := check(items, turnStart, c, log)
	if r.unavailable {
		return "", "", "", "", nil
	}
	for label := range r.t.checked {
		if k, ok := byLabel[label]; ok && !r.t.missed[label] {
			checked = append(checked, k)
		}
	}
	if len(r.notices) > 0 {
		text, markdown = r.compose("")
	}
	return text, markdown, r.agentText(), r.offerText(), checked
}
