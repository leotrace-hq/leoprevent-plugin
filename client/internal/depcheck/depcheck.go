// Package depcheck is the end-of-turn dependency check (LEO-511, decision D58): for the
// dependency files a turn changed, it reads them now and as they were at the start of the turn,
// sends what changed to POST /dependencies, and returns the server's developer notice.
//
// ⚠️ A PLACEHOLDER FOR TESTING, OFF BY DEFAULT. It runs only with LEOPREVENT_SEND_DEPENDENCIES=on.
// How the notice reaches the developer is still tentative (LEO-511, "Delivering the dependency
// notice"); until that's agreed the caller shows it as a plain notice, which the Claude desktop
// app and claude.ai don't display. It sends only the turn's changes, never the whole file on a
// session's first change (that rule isn't built), and nothing it does changes the review.
//
// Which files it looks at comes only from the readers (deps.All): nothing here names a file.
package depcheck

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/deps"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

// switchEnv turns the check on. It's the plugin's switch, separate from the server's
// LEOPREVENT_DEPENDENCY_CHECK.
const switchEnv = "LEOPREVENT_SEND_DEPENDENCIES"

// Enabled reports whether the check is switched on for this process.
func Enabled() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv(switchEnv)), "on")
}

// maxPerRequest is the server's MaxDependencyPackages (config.go in the server module, which the
// plugin can't import). A larger list is sent as several requests.
var maxPerRequest = 10000

// budget bounds the whole check on the Stop path: no request starts after it, and each request
// has its own client timeout too. Past it the rest is skipped and logged, never reported clean.
const budget = 8 * time.Second

// Checker posts one request to /dependencies. The cloud reviewer implements it.
type Checker interface {
	CheckDependencies(wire.DependenciesRequest) (wire.DependenciesResponse, error)
}

// TurnStart returns the reader of the repository at root as it was at the start of the turn,
// or nil when there's no turn-start copy (then every dependency is sent with no change known).
type TurnStart func(root string) deps.Opener

// Run checks the dependency files among changes and returns the developer notice, as plain text
// and as markdown (with each advisory linked), both "" when there's nothing to say. It fails
// open: any error is logged and that file is skipped. It logs counts and the file path (on the
// developer's own machine), never package names.
func Run(changes []transcript.Change, cwd string, turnStart TurnStart, c Checker, log *slog.Logger) (text, markdown string) {
	r := check(turnItems(changes, cwd, nil, log), turnStart, c, log)
	if len(r.notices) == 0 {
		return "", ""
	}
	// One file needs no summary, just its name; several get a summary line, then each named.
	return r.compose(r.t.summary())
}

// item is one dependency file to check: label is how it's named (in the notice and the log),
// root its repository (for the start-of-turn copy), whole whether every dependency is sent or
// only the turn's changes.
type item struct {
	label, path, root string
	whole             bool
}

type fileNotice struct{ path, notice, markdown string }

// results are a check's notices, one per file that has one, and its tally.
type results struct {
	notices []fileNotice
	t       tally
}

// compose puts a summary line (if any) above each file's notice, named by its file.
func (r results) compose(summary string) (text, markdown string) {
	var texts, mds []string
	if summary != "" {
		texts, mds = append(texts, summary), append(mds, summary)
	}
	for _, n := range r.notices {
		texts = append(texts, labelled(n.path, n.notice))
		mds = append(mds, labelled(escapeMarkdown(n.path), n.markdown))
	}
	return strings.Join(texts, "\n\n"), strings.Join(mds, "\n\n")
}

// turnItems are the dependency files among changes, each sending only the turn's changes. A
// file already in skip (by its path on disk) is left out.
func turnItems(changes []transcript.Change, cwd string, skip map[string]bool, log *slog.Logger) []item {
	var items []item
	for _, ch := range changes {
		if ch.Deleted || ch.Virtual {
			continue // a deleted file has nothing to check; its removals are for the fix check
		}
		if _, ok := deps.All.For(ch.FilePath); !ok {
			continue
		}
		path, inside := onDisk(ch, cwd)
		if !inside {
			log.Warn("dependency check: file outside the project, NOT read", "file", ch.FilePath)
			continue
		}
		if skip[resolved(path)] {
			continue
		}
		items = append(items, item{label: ch.FilePath, path: path, root: ch.RepoRoot})
	}
	return items
}

// check reads and sends each item within the budget, and gathers the answers.
func check(items []item, turnStart TurnStart, c Checker, log *slog.Logger) results {
	start := time.Now()
	r := results{t: tally{checked: map[string]bool{}, missed: map[string]bool{}}}
	t := &r.t
	for _, it := range items {
		if time.Since(start) > budget {
			log.Warn("dependency check: out of time, file NOT checked", "file", it.label)
			t.missed[it.label] = true
			continue
		}
		marked, ecosystem, ok := read(it, turnStart, log)
		if !ok {
			t.missed[it.label] = true
			continue
		}
		var pkgs []wire.DependencyVersion
		private := 0
		for _, m := range deps.Collapse(marked) {
			if m.Private {
				private++ // never sent: it may be the customer's own package
				continue
			}
			pkgs = append(pkgs, wire.DependencyVersion{Name: m.Name, Version: m.Version, Line: m.Line,
				DependencyContext: wire.DependencyContext{Indirect: m.Indirect, Dev: m.Dev, Change: m.Change, Previous: m.Previous}})
		}
		log.Info("dependency check: read", "file", it.label, "ecosystem", ecosystem, "whole", it.whole,
			"marked", len(marked), "to_send", len(pkgs), "private_withheld", private)
		for i := 0; i < len(pkgs); i += maxPerRequest {
			if time.Since(start) > budget {
				log.Warn("dependency check: out of time, the rest was NOT checked", "file", it.label, "unsent", len(pkgs)-i)
				t.missed[it.label] = true
				break
			}
			batch := pkgs[i:min(i+maxPerRequest, len(pkgs))]
			resp, err := c.CheckDependencies(wire.DependenciesRequest{Ecosystem: ecosystem, Packages: batch})
			if err != nil {
				log.Warn("dependency check failed: NOT checked (fail-open)", "file", it.label, "packages", len(batch), "err", err.Error())
				t.missed[it.label] = true
				continue
			}
			flagged := 0
			for _, p := range resp.Packages {
				if p.Security != nil && p.Security.NeedsFix {
					flagged++
				}
			}
			verdict := answer(resp, flagged)
			t.checked[it.label] = true
			t.issues += resp.Issues
			t.malicious += resp.Malicious
			t.needsFix += flagged
			log.Info("dependency check: answered", "file", it.label, "packages", len(batch),
				"verdict", verdict, "needs_fix", flagged, "unchecked", resp.Unchecked)
			if resp.Unchecked > 0 {
				// A clean verdict here means "nothing found", not "everything checked".
				log.Warn("dependency check: PARTIAL, some packages couldn't be fully checked", "file", it.label, "unchecked", resp.Unchecked)
			}
			hasNotice := resp.Messages.Developer != nil && strings.TrimSpace(*resp.Messages.Developer) != ""
			switch {
			case hasNotice:
				md := *resp.Messages.Developer // a server older than the markdown sends text only
				if m := resp.Messages.DeveloperMarkdown; m != nil && strings.TrimSpace(*m) != "" {
					md = *m
				}
				r.notices = append(r.notices, fileNotice{it.label, *resp.Messages.Developer, md})
			case verdict == wire.VerdictTriggered:
				log.Warn("dependency check: something needs fixing but the server sent no notice", "file", it.label, "needs_fix", flagged)
			}
		}
	}
	log.Info("dependency check: done", "notices", len(r.notices), "files_checked", len(t.checked),
		"files_not_checked", len(t.missed), "issues", t.issues, "malicious", t.malicious, "took_ms", time.Since(start).Milliseconds())
	return r
}

// escapeMarkdown keeps a file path from becoming markup in the markdown notice.
var escapeMarkdown = strings.NewReplacer(`\`, `\\`, "`", "\\`", `*`, `\*`, `_`, `\_`, `[`, `\[`, `]`, `\]`, `<`, `\<`, `>`, `\>`).Replace

// heading is how the server's dependency notice starts ("🛡️ LeoPrevent · dependency check (1 package)").
const heading = "🛡️ LeoPrevent · "

// labelled names the file a notice is about: on the server's heading line when the notice starts
// with one ("🛡️ LeoPrevent · dependency check (1 package) · web/package-lock.json"), otherwise on
// a line of its own above it.
//
// ⚠️ IT EDITS THE SERVER'S FIRST LINE, the one place the plugin touches server wording. It goes
// once file paths are on the wire (LEO-513) and the server names the file itself.
func labelled(path, notice string) string {
	first, rest, _ := strings.Cut(notice, "\n")
	if strings.HasPrefix(first, heading) {
		if rest == "" {
			return first + " · " + path
		}
		return first + " · " + path + "\n" + rest
	}
	return fmt.Sprintf("%s:\n%s", path, notice)
}

// tally adds up a turn's answers, one request per dependency file, for the summary line.
type tally struct {
	checked, missed             map[string]bool // files answered; files not (fully) checked
	issues, malicious, needsFix int
}

// summary is the line above the per-file notices when two or more files were checked and
// something needs fixing: "🛡️ LeoPrevent · dependency check: 3 high or critical issues across
// 2 dependency files". The issue counts are the server's (decided by its policy), so this only
// adds them up; a server older than those counts is summarised by packages instead.
//
// ⚠️ PLACEHOLDER WORDING, WRITTEN HERE. Every other notice is worded by the server. When the
// results are combined at Stop (LEO-620), this line becomes a server-overridable template, as the
// review's banner is ("{count} {files}" in Messaging).
func (t tally) summary() string {
	files := len(t.checked)
	if files < 2 || (t.issues == 0 && t.needsFix == 0) {
		return ""
	}
	var line string
	switch {
	case t.issues == 0: // a server older than the issue counts
		line = fmt.Sprintf("%d %s need fixing across %d dependency files", t.needsFix, plural(t.needsFix, "package", "packages"), files)
	case t.malicious == 0:
		line = fmt.Sprintf("%d high or critical %s across %d dependency files", t.issues, plural(t.issues, "issue", "issues"), files)
	default:
		line = fmt.Sprintf("%d %s needing a fix across %d dependency files, %d of them malicious", t.issues, plural(t.issues, "issue", "issues"), files, t.malicious)
	}
	if n := len(t.missed); n > 0 {
		line += fmt.Sprintf(" (%d %s couldn't be checked)", n, plural(n, "file", "files"))
	}
	return "🛡️ LeoPrevent · dependency check: " + line
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// read reads the file now and at the start of the turn, and marks each dependency: only what
// the turn changed, or with whole, every dependency (the changes still marked). ok is false when
// the file couldn't be read now (logged).
func read(it item, turnStart TurnStart, log *slog.Logger) ([]deps.Marked, string, bool) {
	after, reader, err := deps.All.ReadWith(it.path, deps.Disk)
	if err != nil {
		n := deps.Note{Code: deps.NoteFileUnreadable, File: it.label, Reason: err.Error()}
		log.Warn("dependency check: file NOT checked", "file", it.label, "note", n.Code, "reason", n.Reason)
		return nil, "", false
	}
	for _, n := range after.Notes {
		log.Info("dependency check: note", "file", it.label, "note", n.String())
	}
	pick := func(c deps.Comparison) []deps.Marked {
		if it.whole {
			return c.Whole()
		}
		return c.Changes
	}
	if turnStart == nil || it.root == "" {
		log.Info("dependency check: no start-of-turn copy, so no change is marked", "file", it.label)
		return deps.Unmarked(after.Dependencies), reader.Ecosystem(), true
	}
	before, _, err := deps.All.ReadWith(it.path, turnStart(it.root))
	switch {
	case err == nil:
		return pick(deps.Compare(before.Dependencies, after.Dependencies)), reader.Ecosystem(), true
	case errors.Is(err, fs.ErrNotExist):
		return pick(deps.Compare(nil, after.Dependencies)), reader.Ecosystem(), true // created this turn
	default:
		log.Info("dependency check: start-of-turn copy unreadable, so no change is marked", "file", it.label, "err", err.Error())
		return deps.Unmarked(after.Dependencies), reader.Ecosystem(), true
	}
}

// onDisk is where the changed file is now: under its repository's root on the git path (its
// FilePath carries the repository's label as a prefix when the turn spans several), or as the
// transcript recorded it, under cwd. ok is false when that place isn't inside the root or cwd:
// the path comes from the agent's own record of the turn, so a "../" path or a symlinked folder
// must never make the plugin read a file outside the project.
func onDisk(ch transcript.Change, cwd string) (path string, ok bool) {
	root := cwd
	switch {
	case ch.RepoRoot != "":
		root = ch.RepoRoot
		rel := ch.FilePath
		if ch.RepoDir != "" {
			rel = strings.TrimPrefix(rel, ch.RepoDir+"/")
		}
		path = filepath.Join(root, filepath.FromSlash(rel))
	case filepath.IsAbs(ch.FilePath):
		path = ch.FilePath
	default:
		path = filepath.Join(cwd, ch.FilePath)
	}
	if root == "" {
		return "", false
	}
	return path, within(root, path)
}

// within reports whether path is root or inside it, once symlinks in either are resolved.
func within(root, path string) bool {
	rel, err := filepath.Rel(resolved(root), resolved(path))
	return err == nil && !filepath.IsAbs(rel) && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// resolved is path with its symlinks resolved: the whole path when it exists, else its folder
// (a file can be missing at the start of the turn), else just cleaned.
func resolved(path string) string {
	path = filepath.Clean(path)
	if r, err := filepath.EvalSymlinks(path); err == nil {
		return r
	}
	if dir, err := filepath.EvalSymlinks(filepath.Dir(path)); err == nil {
		return filepath.Join(dir, filepath.Base(path))
	}
	return path
}

// answer is the response's verdict. A server older than the field (before PR #1061) sends none,
// so it's worked out the same way the server does: triggered when any package needs fixing.
func answer(resp wire.DependenciesResponse, needsFix int) string {
	if resp.Verdict != "" {
		return resp.Verdict
	}
	if needsFix > 0 {
		return wire.VerdictTriggered
	}
	return wire.VerdictClean
}
