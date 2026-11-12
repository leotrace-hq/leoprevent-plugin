package engine

import (
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/depcheck"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/notify"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/vcs"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

// The dependency check in a folder with no git repository (LEO-659, decided 21 Oct 2026). With no
// start-of-turn copy nothing can be marked as changed, and the transcript doesn't see what a shell
// command (npm install) writes. So every Stop walks the folder and sends the dependency files
// whose content hasn't been checked this session, each whole, with baseline "none": the server
// then puts every package that needs fixing to the agent, whatever its change, since a folder
// without git is most likely a new project. The usual guards hold: one wake per turn, none on the
// Stop after a wake, and each package version asked at most once per session.

// noRepository reports a session folder with no git repository at or beneath it, the case the
// session scan walks (depcheck.Find). usedGit is whether this Stop had a git baseline.
func noRepository(cwd string, usedGit bool) bool {
	return !usedGit && cwd != "" && vcs.ProjectRepos(cwd).Skip == vcs.SkipNoRepository
}

// seenPrefix marks a dependency file's content as checked this session
// ("deps-seen:package-lock.json:<sha256>"). A file is sent again only when its content changes.
const seenPrefix = "deps-seen:"

// unseen is the files in the folder at cwd whose content hasn't been checked this session, and
// the keys to record once they have been. A file that can't be read is sent anyway, so the check reports it as not
// checked. A file whose check fails is recorded all the same, and sent again only once it changes:
// the notice says it couldn't be checked.
func unseen(sessionID, cwd string, files []depcheck.ScanFile) ([]depcheck.ScanFile, []string) {
	seen := map[string]bool{}
	for _, k := range notify.Recorded(sessionID, seenPrefix) {
		seen[k] = true
	}
	var out []depcheck.ScanFile
	var keys []string
	for _, f := range files {
		sum := depcheck.Fingerprint(cwd, f.Label)
		if sum == "" {
			out = append(out, f)
			continue
		}
		if k := f.Label + ":" + sum; !seen[k] {
			out = append(out, f)
			keys = append(keys, seenPrefix+k)
		}
	}
	return out, keys
}

// gitlessCheck is the dependency check on every Stop after the first in a folder with no
// repository: the walked dependency files that changed since they were last checked, and the
// turn's own changed dependency files the walk didn't find. It runs even when the transcript
// shows no changed file, since npm install's lockfile isn't in it.
type gitlessCheck struct{ dependencyCheck }

func (gitlessCheck) runsWithoutFiles() bool { return true }

func (g gitlessCheck) run(t stopTurn, files []transcript.Change) stopResult {
	w := depcheck.Find(t.ev.Cwd, projectLister, t.log)
	send, keys := unseen(t.ev.SessionID, t.ev.Cwd, w.Files)
	if len(send) == 0 && len(files) == 0 {
		return stopResult{}
	}
	put := &askedKeys{}
	c := stamped{checker: g.checker, meta: dependencyMeta(t), trigger: wire.DependencyTriggerTurn, baseline: wire.DependencyBaselineNone, sessionID: t.ev.SessionID, put: put}
	text, md, agent := depcheck.RunWhole(send, w.Files, files, t.ev.Cwd, c, t.log)
	notify.Record(t.ev.SessionID, keys...)
	return stopResult{notice: text, noticeMarkdown: md, agent: agent, asked: put.list()}
}

// recheckWithoutRepository is the re-check on the Stop after a wake in a folder with no
// repository: the dependency files that changed since the wake (the agent's fix), and the turn's
// own. "" when nothing changed, or when the check has nothing to say.
func recheckWithoutRepository(t stopTurn, c depcheck.Checker, files []transcript.Change) (string, bool) {
	w := depcheck.Find(t.ev.Cwd, projectLister, t.log)
	send, keys := unseen(t.ev.SessionID, t.ev.Cwd, w.Files)
	if len(send) == 0 && len(files) == 0 {
		return "", false
	}
	sc := stamped{checker: c, meta: dependencyMeta(t), trigger: wire.DependencyTriggerRecheck, baseline: wire.DependencyBaselineNone, sessionID: t.ev.SessionID}
	text, _, _ := depcheck.RunWhole(send, w.Files, files, t.ev.Cwd, sc, t.log)
	notify.Record(t.ev.SessionID, keys...)
	return text, true
}
