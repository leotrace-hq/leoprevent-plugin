// Package depcheck is the end-of-turn dependency check (LEO-511, decision D58): for the
// dependency files a turn changed, it reads them now and as they were at the start of the turn,
// sends what changed (and what the turn removed) to POST /dependencies, and returns the server's
// developer notice.
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

// BranchTeller is a Checker that can also say whether the repository holding dir (its root, or a
// folder inside it) has its default branch checked out (vcs.OnDefaultBranch), for every request's
// DefaultBranch (LEO-513): nil when it can't tell. A Checker without it sends none.
type BranchTeller interface {
	DefaultBranch(dir string) *bool
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
// noise beside the project's own. One that can't be read (an old format kept to test a parser) is
// logged and left out of "couldn't be checked" too: it's no gap in the project's own coverage.

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
// the turn's changes. deleted is a file the turn deleted: only what it held at the start of the
// turn is sent, as removed (LEO-513), and it never has a notice or counts as checked.
type item struct {
	label, path, root, rel string
	whole, deleted         bool
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

// turnItems are the dependency files among changes, each sending only the turn's changes (a
// deleted one, what it held). A file already in skip (by its path on disk) is left out.
func turnItems(changes []transcript.Change, cwd string, skip map[string]bool, log *slog.Logger) []item {
	var items []item
	for _, ch := range changes {
		if ch.Virtual {
			continue
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
		items = append(items, item{label: ch.FilePath, path: path, root: ch.RepoRoot, rel: wirePath(ch.FilePath, cwd), deleted: ch.Deleted})
	}
	return items
}

// movedAway is the deleted dependency files a turn may have moved rather than removed: the same turn
// added a file of the same name, in the same repository, that wasn't there at its start (LEO-513).
//
// ⚠️ A MOVE MUST NEVER READ AS A FIX. git pairs a plain rename and reports only the new path, but a
// lockfile moved and regenerated in the same turn can differ too much to pair, and then reads as one
// file deleted and another added. Sent as deleted, the old path's packages would be recorded as
// removed and its findings as fixed, while the same versions sit at the new path. So such a deletion
// isn't sent, which leaves it as a paired rename does: the old path's findings stay open, never
// fixed. Carrying them over to the new path is LEO-766. Only a NEW file of that name counts, so a
// monorepo turn that deletes one project's lockfile and changes another's still sends the deletion.
// Without a turn-start copy nothing is deleted to begin with (a deletion needs it), so it never asks.
func movedAway(items []item, turnStart TurnStart) map[string]bool {
	if turnStart == nil {
		return nil
	}
	type named struct{ root, name string }
	added := map[named]bool{}
	for _, it := range items {
		if it.deleted || it.root == "" {
			continue
		}
		if _, err := turnStart(it.root)(it.path); errors.Is(err, fs.ErrNotExist) {
			added[named{it.root, filepath.Base(it.path)}] = true
		}
	}
	moved := map[string]bool{}
	for _, it := range items {
		if it.deleted && added[named{it.root, filepath.Base(it.path)}] {
			moved[it.label] = true
		}
	}
	return moved
}

// checkable counts the items that can have a notice: every one but a deleted file.
func checkable(items []item) int {
	n := 0
	for _, it := range items {
		if !it.deleted {
			n++
		}
	}
	return n
}

// check reads and sends each item within the budget, and gathers the answers.
func check(items []item, turnStart TurnStart, c Checker, log *slog.Logger) results {
	start := time.Now()
	r := results{t: tally{checked: map[string]bool{}, missed: map[string]bool{}}}
	t := &r.t
	branch := branches(c)
	moved := movedAway(items, turnStart)
	for _, it := range items {
		if it.deleted && moved[it.label] {
			log.Info("dependency check: deleted file looks moved, so its packages aren't sent as removed", "file", it.label)
			continue
		}
		if time.Since(start) > budget {
			log.Warn("dependency check: out of time, file NOT checked", "file", it.label)
			t.missed[it.label] = true
			continue
		}
		inTests := testArea(it)
		if it.deleted {
			rd, ok := readDeleted(it, turnStart, log)
			if ok && sendRemoved(it, rd, removedNow(rd.removed, nil, log, it.label), branch(it), start, c, t, log) {
				return results{unavailable: true}
			}
			continue
		}
		rd, ok := read(it, turnStart, log)
		if !ok {
			if inTests {
				// A fixture is often unreadable on purpose (Renovate keeps an npm 6 lockfile to test
				// its own parser). Logged by read; not counted as "couldn't be checked", which would
				// read as a gap in the project's own coverage.
				continue
			}
			t.missed[it.label] = true
			continue
		}
		var pkgs []wire.DependencyVersion
		private := 0
		for _, m := range deps.Collapse(rd.marked) {
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
		removed := removedNow(rd.removed, rd.now, log, it.label)
		log.Info("dependency check: read", "file", it.label, "ecosystem", rd.ecosystem, "whole", rd.whole,
			"marked", len(rd.marked), "to_send", len(pkgs), "removed", len(removed), "private_withheld", private, "test_area", inTests)
		if len(pkgs) == 0 {
			if len(removed) > 0 {
				// Only removals: one request with no packages, as evidence of a fix (LEO-513).
				if sendRemoved(it, rd, removed, branch(it), start, c, t, log) {
					return results{unavailable: true}
				}
			}
			continue
		}
		// Whole only when one request carries the file: a part of it says nothing about the rest.
		whole := rd.whole && len(pkgs) <= maxPerRequest
		for i := 0; i < len(pkgs); i += maxPerRequest {
			if time.Since(start) > budget {
				log.Warn("dependency check: out of time, the rest was NOT checked", "file", it.label, "unsent", len(pkgs)-i)
				t.missed[it.label] = true
				break
			}
			batch := pkgs[i:min(i+maxPerRequest, len(pkgs))]
			req := wire.DependenciesRequest{Ecosystem: rd.ecosystem, Packages: batch, Path: it.rel, LockfileVersion: rd.lockfileVersion, Whole: whole,
				DefaultBranch: branch(it)}
			if i == 0 {
				req.Removed = removed // once per file, on its first request
			}
			resp, err := c.CheckDependencies(req)
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

// branches answers whether each file's repository is on its default branch, asking c at most
// once per repository root for the check (a turn can span several repositories). A file with no
// root (the transcript fallback) is asked about by its folder, which git resolves to its
// repository if it has one. nil when c can't tell, or has no BranchTeller.
func branches(c Checker) func(it item) *bool {
	bt, ok := c.(BranchTeller)
	known := map[string]*bool{}
	return func(it item) *bool {
		where := it.root
		if where == "" && it.path != "" {
			where = filepath.Dir(it.path)
		}
		if !ok || where == "" {
			return nil
		}
		if b, seen := known[where]; seen {
			return b
		}
		b := bt.DefaultBranch(where)
		known[where] = b
		return b
	}
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

// reading is one dependency file read for sending: marked is what's sent (only what the turn
// changed, or with whole, every dependency, the changes still marked); removed is what the turn
// took out, one per copy, and now the file as it is, to tell a version still installed elsewhere.
// lockfileVersion is an npm lockfile's, 0 for any other file.
type reading struct {
	marked          []deps.Marked
	removed, now    []deps.Dependency
	ecosystem       string
	lockfileVersion int
	// whole: marked is every dependency in the file (the scan, or no start-of-turn copy).
	whole bool
}

// read reads the file now and at the start of the turn, and marks each dependency. ok is false
// when the file couldn't be read now (logged).
func read(it item, turnStart TurnStart, log *slog.Logger) (reading, bool) {
	after, reader, err := deps.All.ReadWith(it.path, deps.Disk)
	if err != nil {
		n := deps.Note{Code: deps.NoteFileUnreadable, File: it.label, Reason: err.Error()}
		log.Warn("dependency check: file NOT checked", "file", it.label, "note", n.Code, "reason", n.Reason)
		return reading{}, false
	}
	for _, n := range after.Notes {
		log.Info("dependency check: note", "file", it.label, "note", n.String())
	}
	rd := reading{now: after.Dependencies, ecosystem: reader.Ecosystem(), lockfileVersion: after.LockfileVersion, whole: it.whole}
	compared := func(c deps.Comparison) (reading, bool) {
		rd.marked, rd.removed = c.Changes, c.Removed
		if it.whole {
			rd.marked = c.Whole()
		}
		return rd, true
	}
	unmarked := func() (reading, bool) {
		rd.marked, rd.whole = deps.Unmarked(after.Dependencies), true
		return rd, true
	}
	if turnStart == nil || it.root == "" {
		log.Info("dependency check: no start-of-turn copy, so no change is marked", "file", it.label)
		return unmarked()
	}
	before, _, err := deps.All.ReadWith(it.path, turnStart(it.root))
	switch {
	case err == nil:
		return compared(deps.Compare(before.Dependencies, after.Dependencies))
	case errors.Is(err, fs.ErrNotExist):
		return compared(deps.Compare(nil, after.Dependencies)) // created this turn
	default:
		log.Info("dependency check: start-of-turn copy unreadable, so no change is marked", "file", it.label, "err", err.Error())
		return unmarked()
	}
}

// readDeleted reads a file the turn deleted as it was at the start of the turn: everything in it
// is removed. ok is false when there's no start-of-turn copy to read (logged): nothing is sent,
// and it isn't counted as "couldn't be checked", since there was nothing to check.
func readDeleted(it item, turnStart TurnStart, log *slog.Logger) (reading, bool) {
	if turnStart == nil || it.root == "" {
		log.Info("dependency check: deleted, no start-of-turn copy, nothing sent", "file", it.label)
		return reading{}, false
	}
	before, reader, err := deps.All.ReadWith(it.path, turnStart(it.root))
	if err != nil {
		log.Info("dependency check: deleted, start-of-turn copy unreadable, nothing sent", "file", it.label, "err", err.Error())
		return reading{}, false
	}
	return reading{removed: before.Dependencies, ecosystem: reader.Ecosystem(), lockfileVersion: before.LockfileVersion}, true
}

// sendRemoved sends a file's removals with no packages: what a turn took out of a file it kept, or
// everything in a file it deleted. Nothing is looked up, so the answer is never shown, put to the
// agent or counted; a failure counts the file as not checked, as any other does. It reports a
// server with no dependency check.
func sendRemoved(it item, rd reading, removed []wire.RemovedDependency, onDefault *bool, start time.Time, c Checker, t *tally, log *slog.Logger) (unavailable bool) {
	if time.Since(start) > budget {
		log.Warn("dependency check: out of time, removals NOT sent", "file", it.label, "removed", len(removed))
		t.missed[it.label] = true
		return false
	}
	_, err := c.CheckDependencies(wire.DependenciesRequest{Ecosystem: rd.ecosystem, Packages: []wire.DependencyVersion{},
		Path: it.rel, LockfileVersion: rd.lockfileVersion, Removed: removed, Deleted: it.deleted, DefaultBranch: onDefault})
	switch {
	case errors.Is(err, ErrUnavailable):
		log.Info("dependency check: the server has none, so nothing is said", "file", it.label, "err", err.Error())
		return true
	case err != nil:
		log.Warn("dependency check failed: removals NOT sent (fail-open)", "file", it.label, "removed", len(removed), "deleted", it.deleted, "err", err.Error())
		t.missed[it.label] = true
	default:
		log.Info("dependency check: removals sent", "file", it.label, "removed", len(removed), "deleted", it.deleted)
	}
	return false
}

// removedNow is what the turn took out of the file, one entry per package and version: a version
// still installed anywhere in the file now (another folder) isn't removed, and a private one is
// never sent. Copies of one version are merged towards the strictest reading, as Collapse does:
// direct if any copy was, development only if every copy was. At most maxPerRequest.
func removedNow(removed, now []deps.Dependency, log *slog.Logger, label string) []wire.RemovedDependency {
	type id struct{ name, version string }
	present := make(map[id]bool, len(now))
	for _, d := range now {
		present[id{d.Name, d.Version}] = true
	}
	index := map[id]int{}
	var out []wire.RemovedDependency
	for _, d := range removed {
		k := id{d.Name, d.Version}
		if d.Private || present[k] {
			continue
		}
		if i, ok := index[k]; ok {
			out[i].Indirect = out[i].Indirect && d.Indirect
			out[i].Dev = out[i].Dev && d.Dev
			continue
		}
		index[k] = len(out)
		out = append(out, wire.RemovedDependency{Name: d.Name, Version: d.Version, Indirect: d.Indirect, Dev: d.Dev})
	}
	if len(out) > maxPerRequest {
		log.Warn("dependency check: too many removed, the rest NOT sent", "file", label, "unsent", len(out)-maxPerRequest)
		out = out[:maxPerRequest]
	}
	return out
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

// resolved is path with its symlinks resolved: the whole path when it exists, else its nearest
// folder that does, with the rest joined on (a file can be missing at the start of the turn, or
// deleted with its folder this turn; what doesn't exist can't be a symlink), else just cleaned.
func resolved(path string) string {
	path = filepath.Clean(path)
	for dir, rest := path, ""; ; {
		if r, err := filepath.EvalSymlinks(dir); err == nil {
			return filepath.Join(r, rest)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return path
		}
		dir, rest = parent, filepath.Join(filepath.Base(dir), rest)
	}
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
