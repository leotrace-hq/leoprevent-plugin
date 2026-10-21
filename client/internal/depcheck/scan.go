package depcheck

import (
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/deps"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
)

// The session scan (LEO-549, decision D51): at the end of a session's first turn, every
// dependency file in the project is checked whole, for the developer's information only.
//
// ⚠️ PLACEHOLDER WORDING, WRITTEN HERE, like the multi-file summary line: the scan's summary and
// skip lines become server-overridable templates with the rest of the Stop's wording (LEO-620).

// maxScanFiles bounds the dependency files one scan checks. The rest are counted, never shown
// as clean.
const maxScanFiles = 50

// A folder that isn't a repository is walked instead (LEO-658), bounded because there's no
// .gitignore to say what the project keeps out: at most maxWalkDepth folders down, and at most
// maxWalkEntries entries looked at, nearest first.
const (
	maxWalkDepth   = 4
	maxWalkEntries = 5000
)

// noRepository is vcs.SkipNoRepository: no repository at or beneath the session's folder.
const noRepository = "no repository"

// gitlessWarning ends the scan's summary when it walked a folder, like the review's own no-git
// warning (review.GitlessWarning), which shows only when there's code to review.
const gitlessWarning = "⚠️ no git repo here, so the dependency scan reaches less of your project (run git init for full coverage)"

// ScanFile is one dependency file found in the project.
type ScanFile struct {
	// Label names it in the notice: its path in the repository, under the repository's name
	// when the scan covers more than one.
	Label string
	Path  string // absolute
	Root  string // its repository, for the start-of-turn copy
}

// Workspace is what the scan looks at: the dependency files found, or why there are none.
type Workspace struct {
	Files []ScanFile
	// Over counts the dependency files past maxScanFiles, which weren't checked.
	Over int
	// Walked is set when the folder isn't a repository, so its files came from walking it, not
	// from git. Cut is set when the walk stopped at maxWalkEntries.
	Walked, Cut bool
	// Skip is set when the folder isn't a project (a vcs.Skip* reason): nothing is scanned,
	// and the developer is told so in one line.
	Skip string
}

// Lister is how the scan learns about the project, so this package needs no git of its own.
type Lister struct {
	// Projects returns the repositories to scan, or why none (vcs.ProjectRepos).
	Projects func(cwd string) (roots []string, skip string)
	// Files lists a repository's files, relative to its root (vcs.TrackedFiles).
	Files func(root string) ([]string, error)
}

// Find lists the dependency files in the project at cwd: the files git lists in each repository
// that a reader reads (deps.All), never under node_modules/ or vendor/, never a symlink, at most
// maxScanFiles. A folder with no repository at or beneath it is walked instead (walkFolder).
func Find(cwd string, l Lister, log *slog.Logger) Workspace {
	roots, skip := l.Projects(cwd)
	if skip == noRepository && cwd != "" {
		files, cut := walkFolder(cwd)
		w := Workspace{Walked: true, Cut: cut}
		for _, f := range files {
			// No Root: without git there's no start-of-turn copy, so nothing is marked as changed.
			w.add(cwd, f, f, "")
		}
		log.Info("dependency scan: no repository, folder walked", "files", len(w.Files), "over_cap", w.Over, "walk_cut", cut)
		return w
	}
	if skip != "" {
		log.Info("dependency scan: skipped", "reason", skip)
		return Workspace{Skip: skip}
	}
	var w Workspace
	for _, root := range roots {
		files, err := l.Files(root)
		if err != nil {
			log.Warn("dependency scan: repository NOT listed", "repo", filepath.Base(root), "err", err.Error())
			continue
		}
		for _, f := range files {
			label := f
			if len(roots) > 1 {
				label = filepath.Base(root) + "/" + f
			}
			w.add(root, f, label, root)
		}
	}
	log.Info("dependency scan: found", "repos", len(roots), "files", len(w.Files), "over_cap", w.Over)
	return w
}

// add takes f, a path relative to dir, when a reader reads it and it's a regular file inside dir
// and outside node_modules/ and vendor/, up to maxScanFiles; past that it's counted in Over. root
// is its repository, for the start-of-turn copy, or "" when there is none.
func (w *Workspace) add(dir, f, label, root string) {
	if _, ok := deps.All.For(f); !ok || vendored(f) {
		return
	}
	abs := filepath.Join(dir, filepath.FromSlash(f))
	if !regular(abs) || !within(dir, abs) {
		return
	}
	if len(w.Files) == maxScanFiles {
		w.Over++
		return
	}
	w.Files = append(w.Files, ScanFile{Label: label, Path: abs, Root: root})
}

// walkFolder lists the files under dir, relative to it with forward slashes, nearest first. It
// never enters node_modules/, vendor/, a hidden folder (.git, .venv, .next) or a symlink, goes at
// most maxWalkDepth folders down, and stops after maxWalkEntries entries, reporting cut. Test
// folders are walked: their dependencies are installed and can run (decided 21 Oct 2026).
func walkFolder(dir string) (files []string, cut bool) {
	type folder struct {
		rel   string
		depth int
	}
	queue := []folder{{"", 0}}
	seen := 0
	for len(queue) > 0 {
		f := queue[0]
		queue = queue[1:]
		entries, err := os.ReadDir(filepath.Join(dir, filepath.FromSlash(f.rel)))
		if err != nil {
			continue
		}
		for _, e := range entries {
			if seen++; seen > maxWalkEntries {
				return files, true
			}
			rel := path.Join(f.rel, e.Name())
			switch {
			case e.Type()&fs.ModeSymlink != 0:
			case e.IsDir():
				name := e.Name()
				if f.depth < maxWalkDepth && !strings.HasPrefix(name, ".") && name != "node_modules" && name != "vendor" {
					queue = append(queue, folder{rel, f.depth + 1})
				}
			case e.Type().IsRegular():
				files = append(files, rel)
			}
		}
	}
	return files, false
}

// vendored is a path inside an installed or vendored tree, which is someone else's project.
func vendored(rel string) bool {
	for _, seg := range strings.Split(path.Dir(rel), "/") {
		if seg == "node_modules" || seg == "vendor" {
			return true
		}
	}
	return false
}

var lstat = os.Lstat

// regular is a file that exists and isn't a symlink.
func regular(p string) bool {
	fi, err := lstat(p)
	return err == nil && fi.Mode().IsRegular()
}

// Scan checks every file in w whole (with this turn's changes still marked), and the turn's own
// changed dependency files that w doesn't cover as at any other Stop, and returns the notice, what
// the server put to the agent (only ever the turn's own changes, or any change in a folder with no
// repository), and its offer to fix what was already there (LEO-673; "" when there's none). It
// says nothing when everything was checked and nothing is serious. A skipped scan returns its one
// line, plus any notice for the turn's own files.
func Scan(w Workspace, changes []transcript.Change, cwd string, turnStart TurnStart, c Checker, log *slog.Logger) (text, markdown, agent, offer string) {
	var items []item
	covered := map[string]bool{}
	for _, f := range w.Files {
		items = append(items, item{label: f.Label, path: f.Path, root: f.Root, rel: relativeOnly(f.Label), whole: true})
		covered[resolved(f.Path)] = true
	}
	items = append(items, turnItems(changes, cwd, covered, log)...)
	r := check(items, turnStart, c, log)
	if r.unavailable {
		return "", "", "", ""
	}

	var lead string
	switch {
	case w.Skip != "":
		lead = skipLine(w.Skip)
	case len(r.notices) > 0 || len(r.t.missed) > 0 || w.Over > 0 || w.Cut || (w.Walked && len(w.Files) > 0):
		// A walked folder always says so, once, with what it found: the review's own warning
		// shows only when there's code to review. A folder with no dependency files says nothing.
		lead = scanSummary(r.t, len(r.notices), len(items), w.Over, w.Cut)
		if w.Walked {
			lead += " " + gitlessWarning
		}
	}
	if lead == "" && len(r.notices) == 0 {
		return "", "", r.agentText(), r.offerText()
	}
	text, markdown = r.compose(lead)
	return text, markdown, r.agentText(), r.offerText()
}

// scanSummary heads the scan's notice: what's open across the project's dependency files, and
// what couldn't be checked. noticed is how many files have a notice, of files scanned; cut is a
// folder walk that stopped at maxWalkEntries.
func scanSummary(t tally, noticed, files, over int, cut bool) string {
	line := "🛡️ LeoPrevent · dependency scan of this project, for your information: "
	in := fmt.Sprintf("in %d of %d dependency files", noticed, files)
	if noticed == files {
		in = fmt.Sprintf("in %d dependency %s", files, plural(files, "file", "files"))
	}
	switch {
	case noticed == 0:
		line += fmt.Sprintf("nothing high or critical in the %d dependency %s checked", len(t.checked), plural(len(t.checked), "file", "files"))
	case t.issues == 0: // a server older than the issue counts
		line += "something to look at " + in
	case t.malicious == 0:
		line += fmt.Sprintf("%d high or critical %s %s", t.issues, plural(t.issues, "issue", "issues"), in)
	default:
		line += fmt.Sprintf("%d %s to fix %s, %d of them malicious", t.issues, plural(t.issues, "issue", "issues"), in, t.malicious)
	}
	var notChecked []string
	if n := len(t.missed); n > 0 {
		notChecked = append(notChecked, fmt.Sprintf("%d %s couldn't be checked", n, plural(n, "file", "files")))
	}
	if over > 0 {
		notChecked = append(notChecked, fmt.Sprintf("%d more %s over the limit of %d", over, plural(over, "file", "files"), maxScanFiles))
	}
	if cut {
		notChecked = append(notChecked, "the folder was too large to look through in full")
	}
	if len(notChecked) > 0 {
		line += " (" + strings.Join(notChecked, "; ") + ")"
	}
	return line
}

// skipLine tells the developer the scan didn't happen, so silence never reads as "nothing found".
func skipLine(reason string) string {
	const lead = "🛡️ LeoPrevent · dependency scan skipped: "
	switch reason {
	case "home folder":
		return lead + "this is your home folder. Open a project folder to scan it."
	case "filesystem root":
		return lead + "this is the root of the file system. Open a project folder to scan it."
	case "several projects":
		return lead + "this folder holds several projects. Open one of them to scan it."
	default:
		return lead + "there's no git repository in this folder."
	}
}
