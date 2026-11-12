package depcheck

import (
	"fmt"
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
// maxScanFiles.
func Find(cwd string, l Lister, log *slog.Logger) Workspace {
	roots, skip := l.Projects(cwd)
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
			if _, ok := deps.All.For(f); !ok || vendored(f) {
				continue
			}
			abs := filepath.Join(root, filepath.FromSlash(f))
			if !regular(abs) || !within(root, abs) {
				continue
			}
			if len(w.Files) == maxScanFiles {
				w.Over++
				continue
			}
			label := f
			if len(roots) > 1 {
				label = filepath.Base(root) + "/" + f
			}
			w.Files = append(w.Files, ScanFile{Label: label, Path: abs, Root: root})
		}
	}
	log.Info("dependency scan: found", "repos", len(roots), "files", len(w.Files), "over_cap", w.Over)
	return w
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
// changed dependency files that w doesn't cover as at any other Stop, and returns the notice.
// It says nothing when everything was checked and nothing is serious. A skipped scan returns
// its one line, plus any notice for the turn's own files.
func Scan(w Workspace, changes []transcript.Change, cwd string, turnStart TurnStart, c Checker, log *slog.Logger) (text, markdown string) {
	var items []item
	covered := map[string]bool{}
	for _, f := range w.Files {
		items = append(items, item{label: f.Label, path: f.Path, root: f.Root, whole: true})
		covered[resolved(f.Path)] = true
	}
	items = append(items, turnItems(changes, cwd, covered, log)...)
	r := check(items, turnStart, c, log)

	var lead string
	switch {
	case w.Skip != "":
		lead = skipLine(w.Skip)
	case len(r.notices) > 0 || len(r.t.missed) > 0 || w.Over > 0:
		lead = scanSummary(r.t, len(r.notices), len(items), w.Over)
	}
	if lead == "" && len(r.notices) == 0 {
		return "", ""
	}
	return r.compose(lead)
}

// scanSummary heads the scan's notice: what's open across the project's dependency files, and
// what couldn't be checked. noticed is how many files have a notice, of files scanned.
func scanSummary(t tally, noticed, files, over int) string {
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
