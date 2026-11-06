package engine

import (
	"time"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/depcheck"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/depquiet"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/notify"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/vcs"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

// lockfileCheck is the mid-session check (LEO-819, depcheck/lockfile.go): the dependency files
// covering the code this turn changed, each scanned whole once per session, with the scan's
// quiet and offer. What it finds was already there, so it's offered, never force-fixed: the
// server's offer asks the developer first. It's on for everyone the dependency check is on for.
type lockfileCheck struct {
	dependencyCheck
	files []depcheck.ScanFile
}

func (lockfileCheck) name() string             { return "dependency check (covering file)" }
func (l lockfileCheck) runsWithoutFiles() bool { return len(l.files) > 0 }

func (lockfileCheck) selectFiles([]transcript.Change) []transcript.Change { return nil }

func (l lockfileCheck) run(t stopTurn, _ []transcript.Change) stopResult {
	put := &askedKeys{}
	c := stamped{checker: l.checker, meta: dependencyMeta(t), trigger: wire.DependencyTriggerScan, scope: wire.DependencyScopeLockfile,
		scanID: newScanID(), sessionID: t.ev.SessionID, put: put}
	repo := vcs.RepoIdentity(t.ev.Cwd)
	fixSession := repo != "" && startedToFix(t)
	c.loadQuiet(repo, t.now, fixSession)
	text, md, agent, offer, checked := depcheck.ScanLockfiles(l.files, turnStart(t), c, t.log)
	// Once per file per session whatever the answer: a 400 (a server older than scope, too many
	// packages) or a file with nothing to send would otherwise be sent whole again on every Stop.
	// A timeout isn't retried either; the developer can ask with /leoprevent:sca.
	var record []string
	for _, f := range l.files {
		record = append(record, lockfileKey(f.Key()))
	}
	var pending *depquiet.Pending
	if c.seen != nil && !fixSession {
		_, listed := c.seen.snapshot()
		pending = pendOffer(repo, offer, listed)
	}
	t.log.Info("dependency check: covering files", "files", len(l.files), "answered", len(checked), "notice", text != "", "offer", offer != "")
	return stopResult{notice: text, noticeMarkdown: md, agent: agent, offer: offer, asked: put.list(), record: record, pending: pending}
}

// The scans' share of the developer's quiet (D60): the session scan, the mid-session check and
// /leoprevent:sca each load it the same way and leave their offer pending the same way.

// loadQuiet puts the developer's running answer for repo on the scan's requests, with fixSession
// the session started to fix an offer (quietExisting), and gathers what each answer quietened.
// It reports whether there is a repo to key the quiet by: without one there's no quiet at all.
func (c *stamped) loadQuiet(repo string, now time.Time, fixSession bool) bool {
	if repo == "" {
		return false
	}
	c.quiet, c.seen, c.quietExisting = depquiet.Load(repo, now), &scanSeen{}, fixSession
	return true
}

// startedToFix reports a session the adapter says was started to fix a scan's offer.
func startedToFix(t stopTurn) bool {
	r, ok := t.a.(scanFixSessionReader)
	return ok && r.ScanFixSession(t.ev.TranscriptPath)
}

// pendOffer is the scan's offer to leave awaiting the developer's answer (addPending), so the
// answer starts the quiet for what it listed (settleScanAnswer); nil when there's no offer or
// nothing it listed can be quietened.
func pendOffer(repo, offer string, listed []depquiet.Entry) *depquiet.Pending {
	if offer == "" || repo == "" || len(listed) == 0 {
		return nil
	}
	return &depquiet.Pending{Repo: repo, Entries: listed}
}

// addPending records an offer awaiting the developer's answer, keeping any earlier one of the
// same repository's that is still unanswered: the mid-session check can make an offer on one
// Stop and another on a later one, and /leoprevent:sca one beside either, and one answer covers
// every offer still waiting (D60). The Stop calls it once its checks have finished (runChecks).
// An offer that lists nothing leaves the earlier one as it is.
func addPending(sessionID string, p depquiet.Pending) {
	if sessionID == "" || p.Repo == "" || len(p.Entries) == 0 {
		return
	}
	if old, ok := depquiet.TakePending(sessionID); ok && old.Repo == p.Repo {
		seen := map[string]bool{}
		var merged []depquiet.Entry
		for _, e := range append(old.Entries, p.Entries...) {
			k := e.Path + "\x00" + e.Name + "\x00" + e.Version
			if !seen[k] {
				seen[k] = true
				merged = append(merged, e)
			}
		}
		p.Entries = merged
	}
	depquiet.SetPending(sessionID, p)
}

// lockfileKey marks a dependency file the mid-session check has reported this session, by its
// depcheck.ScanFile.Key: once per file per session.
func lockfileKey(key string) string { return lockfilePrefix + key }

const lockfilePrefix = "deps-lockfile:"

// lockfilesToCheck is the dependency files covering this turn's code that the mid-session check
// hasn't reported this session.
func lockfilesToCheck(t stopTurn) []depcheck.ScanFile {
	if t.ev.SessionID == "" {
		return nil // "once per session" needs a session to count in
	}
	done := map[string]bool{}
	for _, k := range notify.Recorded(t.ev.SessionID, lockfilePrefix) { // the keys, less the prefix
		done[k] = true
	}
	var want []depcheck.ScanFile
	for _, f := range depcheck.Covering(t.changes, t.ev.Cwd, t.log) {
		if !done[f.Key()] {
			want = append(want, f)
		}
	}
	if len(want) == 0 {
		return nil
	}
	// Only a file the session scan would send: listed by git (never a gitignored one, D49), not
	// vendored, within its 50. The scan's own entry is used, so its label is the scan's.
	listed := map[string]depcheck.ScanFile{}
	for _, f := range depcheck.Find(t.ev.Cwd, projectLister, t.log).Files {
		listed[f.Key()] = f
	}
	var out []depcheck.ScanFile
	var dropped []string
	for _, f := range want {
		if g, ok := listed[f.Key()]; ok {
			out = append(out, g)
		} else {
			dropped = append(dropped, lockfileKey(f.Key()))
		}
	}
	// A file the scan wouldn't send is never this check's either: recorded so a later Stop doesn't
	// list the repository's files again to find that out.
	notify.Record(t.ev.SessionID, dropped...)
	return out
}
