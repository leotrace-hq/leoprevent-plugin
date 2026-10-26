// Package depcheck is the end-of-turn dependency check (LEO-511, decision D58): for the
// dependency files a turn changed, it reads them now and as they were at the start of the turn,
// sends what changed to POST /dependencies, and returns the server's developer notice.
//
// ⚠️ THE SERVER IS THE SWITCH. The plugin has none: it runs on the cloud tier wherever the server
// answers /dependencies. A server with no dependency check answers 404 (LEOPREVENT_DEPENDENCY_CHECK
// =off, or no store), and the plugin then stops asking for the session and never mentions the
// check to the developer (ErrUnavailable). Nothing it does changes the code review.
//
// Which files it looks at comes only from the readers (deps.All): nothing here names a file.
package depcheck

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/deps"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
	"github.com/leotrace-hq/leoprevent-plugin/pathgate"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

// maxLocations is the server's MaxDependencyLocations: the locations sent with one package; the
// rest are counted.
const maxLocations = 50

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

// ErrUnavailable is what a Checker returns when the server has no dependency check at all (it
// answered /dependencies with 404). Unlike any other failure, nothing is said to the developer,
// not even that a file couldn't be checked: they're never told about a check they don't have.
var ErrUnavailable = errors.New("the server has no dependency check")

// Run checks the dependency files among changes and returns the developer notice, as plain text
// and as markdown (with each advisory linked), both "" when there's nothing to say, and what the
// server put to the agent ("" when nothing; the caller decides whether to wake it). It fails
// open: any error is logged and that file is skipped. It logs counts and the file path (on the
// developer's own machine), never package names.
func Run(changes []transcript.Change, cwd string, turnStart TurnStart, c Checker, log *slog.Logger) (text, markdown, agent string) {
	r := check(turnItems(changes, cwd, nil, log), turnStart, c, log)
	if r.unavailable || len(r.notices) == 0 {
		return "", "", r.agentText()
	}
	// One file needs no summary, just its name; several get a summary line, then each named.
	text, markdown = r.compose(r.t.summary())
	return text, markdown, r.agentText()
}

// ⚠️ A TEST AREA'S DEPENDENCIES ARE REPORTED ONLY WHEN THEY'RE MALWARE (decided 22 Oct 2026, reversing
// LEO-658's "test folders are scanned"). A dependency file in a test area (testdata/, fixtures/,
// __fixtures__/, or what the review counts as test code: test/, tests/, __tests__/, e2e/, cypress/,
// playwright/) is sent as it is, so the server checks and records it truthfully and malware
// anywhere is found. Its answer is then used only when the file has malware: otherwise its notice
// is dropped and its issues aren't counted, and whatever it would put to the agent (instructions,
// offer, follow-up) is never used, malware or not. Fixture lockfiles are vulnerable on purpose (the
// dependency readers' own testdata) and e2e installs are tooling, so their vulnerable versions were
// noise beside the project's own.

// fixtureSegments are folder names that hold fixtures rather than code, beside the review's test paths.
var fixtureSegments = map[string]bool{"testdata": true, "fixtures": true, "__fixtures__": true, "fixture": true}

// testArea reports a dependency file in a test area, by its path in the repository.
func testArea(it item) bool {
	if it.rel != "" {
		return TestArea(it.rel)
	}
	return TestArea(it.label)
}

// TestArea reports a dependency file's path (as sent to the server) in a test area, whose answer
// is never put to the agent, so the engine records nothing from it as asked.
func TestArea(p string) bool {
	p = filepath.ToSlash(p)
	segs := strings.Split(path.Dir(p), "/")
	for _, seg := range segs {
		if fixtureSegments[seg] {
			return true
		}
	}
	return pathgate.IsTestPath(p)
}

// item is one dependency file to check: label is how it's named (in the notice and the log),
// root its repository (for the start-of-turn copy), rel its path as sent (relative to its
// repository, "" when it can't be made relative), whole whether every dependency is sent or only
// the turn's changes.
type item struct {
	label, path, root, rel string
	whole                  bool
}

type fileNotice struct{ path, notice, markdown string }

// results are a check's notices, one per file that has one, what it puts to the agent (one per
// file that has something), and its tally.
type results struct {
	// unavailable is a server with no dependency check: the check says nothing at all.
	unavailable bool
	notices     []fileNotice
	agent       []string
	// offers are the session scan's offers (LEO-673), one per file that has one.
	offers []string
	t      tally
}

// agentText is everything the check puts to the agent, one file after another, or "".
func (r results) agentText() string { return strings.Join(r.agent, "\n\n") }

// offerText is the session scan's offers, one file after another, or "".
func (r results) offerText() string { return strings.Join(r.offers, "\n\n") }

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
		items = append(items, item{label: ch.FilePath, path: path, root: ch.RepoRoot, rel: wirePath(ch.FilePath, cwd)})
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
		inTests := testArea(it)
		for _, m := range deps.Collapse(marked) {
			if m.Private {
				private++ // never sent: it may be the customer's own package
				continue
			}
			locs, more := m.Locations, 0
			if len(locs) > maxLocations {
				locs, more = locs[:maxLocations], len(locs)-maxLocations
			}
			pkgs = append(pkgs, wire.DependencyVersion{Name: m.Name, Version: m.Version, Line: m.Line,
				Locations: locs, MoreLocations: more,
				DependencyContext: wire.DependencyContext{Indirect: m.Indirect, Dev: m.Dev, DevOptional: m.DevOptional, Change: m.Change, Previous: m.Previous}})
		}
		log.Info("dependency check: read", "file", it.label, "ecosystem", ecosystem, "whole", it.whole,
			"marked", len(marked), "to_send", len(pkgs), "private_withheld", private, "test_area", inTests)
		for i := 0; i < len(pkgs); i += maxPerRequest {
			if time.Since(start) > budget {
				log.Warn("dependency check: out of time, the rest was NOT checked", "file", it.label, "unsent", len(pkgs)-i)
				t.missed[it.label] = true
				break
			}
			batch := pkgs[i:min(i+maxPerRequest, len(pkgs))]
			resp, err := c.CheckDependencies(wire.DependenciesRequest{Ecosystem: ecosystem, Packages: batch, Path: it.rel})
			if errors.Is(err, ErrUnavailable) {
				// Not a failure to report: the developer is never told about a check their server
				// doesn't have, so nothing is shown, not even "couldn't be checked".
				log.Info("dependency check: the server has none, so nothing is said", "file", it.label, "err", err.Error())
				return results{unavailable: true}
			}
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
			if inTests {
				// A test area: only its malware is reported, and nothing in it is the agent's to fix.
				if resp.Malicious == 0 {
					log.Info("dependency check: test area, no malware, so nothing is said", "file", it.label, "packages", len(batch), "needs_fix", flagged)
					continue
				}
				t.issues += resp.Malicious
				t.malicious += resp.Malicious
				t.needsFix += resp.Malicious
				t.maliciousPackages += maliciousIn(resp.Packages)
				log.Info("dependency check: test area with malware, reported", "file", it.label, "malicious", resp.Malicious)
				if hasNotice := resp.Messages.Developer != nil && strings.TrimSpace(*resp.Messages.Developer) != ""; hasNotice {
					md := *resp.Messages.Developer
					if m := resp.Messages.DeveloperMarkdown; m != nil && strings.TrimSpace(*m) != "" {
						md = *m
					}
					r.notices = append(r.notices, fileNotice{it.label, *resp.Messages.Developer, md})
				}
				continue
			}
			// What the developer has answered is counted on the reminder line, not as issues to fix.
			t.issues += resp.Issues - resp.QuietIssues
			t.malicious += resp.Malicious
			t.maliciousPackages += maliciousIn(resp.Packages)
			t.needsFix += flagged - len(resp.Quieted)
			t.quieted += len(resp.Quieted)
			log.Info("dependency check: answered", "file", it.label, "packages", len(batch),
				"verdict", verdict, "needs_fix", flagged, "quieted", len(resp.Quieted), "unchecked", resp.Unchecked)
			if resp.Unchecked > 0 {
				// A clean verdict here means "nothing found", not "everything checked".
				log.Warn("dependency check: PARTIAL, some packages couldn't be fully checked", "file", it.label, "unchecked", resp.Unchecked)
			}
			if m := resp.Messages.Agent; m != nil && strings.TrimSpace(*m) != "" {
				r.agent = append(r.agent, *m)
			}
			if m := resp.Messages.AgentOffer; m != nil && strings.TrimSpace(*m) != "" {
				r.offers = append(r.offers, *m)
			}
			hasNotice := resp.Messages.Developer != nil && strings.TrimSpace(*resp.Messages.Developer) != ""
			switch {
			case hasNotice:
				md := *resp.Messages.Developer // a server older than the markdown sends text only
				if m := resp.Messages.DeveloperMarkdown; m != nil && strings.TrimSpace(*m) != "" {
					md = *m
				}
				r.notices = append(r.notices, fileNotice{it.label, *resp.Messages.Developer, md})
			case verdict == wire.VerdictTriggered && flagged > len(resp.Quieted):
				log.Warn("dependency check: something needs fixing but the server sent no notice", "file", it.label, "needs_fix", flagged)
			}
		}
	}
	log.Info("dependency check: done", "notices", len(r.notices), "files_checked", len(t.checked),
		"files_not_checked", len(t.missed), "issues", t.issues, "malicious", t.malicious, "took_ms", time.Since(start).Milliseconds())
	return r
}

// wirePath is a changed file's path as /dependencies takes it: relative to its repository, with
// forward slashes, as a /review ChangedFile's path is on the git path. A path the agent recorded
// as absolute (the no-git fallback) is made relative to cwd; one that can't be is "", never sent
// absolute, since it would carry the developer's home folder.
func wirePath(p, cwd string) string {
	if !filepath.IsAbs(p) {
		return relativeOnly(filepath.ToSlash(filepath.Clean(p)))
	}
	if cwd == "" {
		return ""
	}
	rel, err := filepath.Rel(cwd, p)
	if err != nil {
		return ""
	}
	return relativeOnly(filepath.ToSlash(rel))
}

// relativeOnly drops a path that steps outside with "..".
func relativeOnly(p string) string {
	if p == "." || p == ".." || strings.HasPrefix(p, "../") || strings.HasPrefix(p, "/") {
		return ""
	}
	return p
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
	// maliciousPackages counts the packages with a malicious advisory (malicious counts the
	// advisories), for the scan's line, which counts packages.
	maliciousPackages int
	// quieted counts the packages left out because the developer answered the scan's offer
	// (internal/depquiet), for the reminder line.
	quieted int
}

// maliciousIn counts the packages with a malicious advisory.
func maliciousIn(ps []wire.DependencyCheck) int {
	n := 0
	for _, p := range ps {
		if p.Security == nil {
			continue
		}
		for _, a := range p.Security.Advisories {
			if a.Malicious {
				n++
				break
			}
		}
	}
	return n
}

// summary is the line above the per-file notices when two or more files were checked and
// something needs fixing: "🛡️ LeoPrevent · dependency check: 3 packages with high or critical
// issues across 2 dependency files". It counts packages, as each file's notice and the scan's line
// do (LEO-695): an issue count above notices that count packages read as two counts of one thing.
// The counts are the server's (decided by its policy), so this only adds them up; a server that
// counts issues but lists no packages is summarised by issues instead.
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
	case t.needsFix == 0: // a server that counts issues but lists no packages
		line = fmt.Sprintf("%d high or critical %s to fix across %d dependency files", t.issues, plural(t.issues, "issue", "issues"), files)
	case t.maliciousPackages == 0:
		line = fmt.Sprintf("%d %s with high or critical issues across %d dependency files", t.needsFix, plural(t.needsFix, "package", "packages"), files)
	default:
		line = fmt.Sprintf("%d %s to fix across %d dependency files, %d of them malicious", t.needsFix, plural(t.needsFix, "package", "packages"), files, t.maliciousPackages)
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
