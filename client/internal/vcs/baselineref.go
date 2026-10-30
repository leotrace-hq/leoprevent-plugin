package vcs

import (
	"errors"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"
)

// Pinning the turn-start stash commit (LEO-394).
//
// ⚠️ WHY A REF. `git stash create` writes a commit that NOTHING references: no branch,
// no tag, not even refs/stash (that is `stash store`, which would show up in the
// developer's own `git stash list`). An unreferenced commit is exactly what `git gc`
// and `git prune` delete, so between the turn-start capture and the Stop the baseline
// could vanish and the Stop reported SkipBaselineGone and fell back to the transcript.
// Observed live on a Codex session in the langchain monorepo, where the agent ran no
// git command itself: whatever pruned it (a `gc --auto` with a short gc.pruneExpire, an
// IDE's maintenance task, `git maintenance`), the baseline was ours to protect.
//
// A ref under refs/leoprevent/ keeps the commit reachable for as long as the ref exists.
// That namespace is outside refs/heads, refs/tags, refs/remotes and refs/stash, so it
// never shows in `git branch`, `git tag`, `git stash list`, `git status` or a plain
// `git push`; `git log --all` and `git for-each-ref` do list it, which is why the refs
// are kept few and short-lived (see pruneBaselineRefs).
//
// ⚠️ THE NAME IS <session key>/<commit id>, AND BOTH HALVES ARE NEEDED. The commit id
// half: a session holds more than one live baseline at a time, the current one (which
// /outcome re-diffs after a block, after the first Stop has already consumed it) and a
// STAGED next one (StageBaseline, promoted only after the review), so one name per
// session would move under the baseline still being diffed. The session half: two
// sessions that snapshot the identical tree get the identical stash commit, and a pin
// named by the commit alone was SHARED, so the first session's ClearBaseline deleted the
// other's live pin and the next gc removed its baseline. The session key is a hex hash
// of the agent's session id and the commit id is validated hex, so neither needs
// sanitising.
//
// Not deleted when the Stop consumes it, for the same reason: the re-wake's guard Stop
// and /outcome diff against the same baseline after the first Stop. Instead every
// capture prunes this repository's pins older than baselineRefTTL, across all sessions,
// and ClearBaseline (the end of a headless run) removes the session's own and no other.
const baselineRefPrefix = "refs/leoprevent/baselines/"

// baselineRefTTL is how long a pin outlives its capture. Generously past the 6h scratch
// sweep (cleanupStale): once the scratch file naming a baseline is gone the pin is
// useless, and a pin pruned too early would reinstate the bug for a very long turn.
var baselineRefTTL = 24 * time.Hour

// isObjectID reports whether s is a full SHA-1 or SHA-256 object id, so it is safe to
// splice into a ref name.
func isObjectID(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

// sessionPinPrefix is the ref namespace holding one session's pins. sessionID is the
// agent's own session id, not the repository-scoped one, so every repository the session
// captures uses the same key.
func sessionPinPrefix(sessionID string) string {
	return baselineRefPrefix + keyFor(sessionID)[:16] + "/"
}

// pinBaseline keeps the turn-start stash commit sha reachable until it is pruned, and
// prunes this repository's expired pins. Best-effort: a failure (a read-only .git, a
// locked ref) is logged and the capture proceeds exactly as it did before pinning
// existed, with a dangling commit.
func pinBaseline(dir, sessionID, sha string) {
	if !isObjectID(sha) {
		return
	}
	if _, err := git(dir, "update-ref", sessionPinPrefix(sessionID)+sha, sha); err != nil {
		slog.Warn("vcs: could not pin the turn-start baseline commit; it stays unreferenced until the Stop", "err", err)
	}
	pruneBaselineRefs(dir, time.Now())
}

// pruneBaselineRefs deletes this repository's baseline pins whose commit is older than
// baselineRefTTL. The stash commit's committer date is its capture time, so no side
// record is needed. Each delete names the value it expects, so a pin another session
// re-pointed in the meantime is left alone.
func pruneBaselineRefs(dir string, now time.Time) {
	out, err := git(dir, "for-each-ref", "--format=%(refname) %(objectname) %(committerdate:unix)", baselineRefPrefix)
	if err != nil {
		return
	}
	cutoff := now.Add(-baselineRefTTL).Unix()
	for _, ln := range strings.Split(strings.TrimSpace(out), "\n") {
		f := strings.Fields(ln)
		if len(f) < 2 || !strings.HasPrefix(f[0], baselineRefPrefix) {
			continue
		}
		// A pin with no readable date (not a commit, or a mangled ref) is not ours to
		// keep either: nothing in this package ever pins anything but a commit.
		if len(f) == 3 {
			if at, perr := strconv.ParseInt(f[2], 10, 64); perr == nil && at >= cutoff {
				continue
			}
		}
		_, _ = git(dir, "update-ref", "-d", f[0], f[1])
	}
}

// unpinSessionRefs removes every pin the session holds in the repository at dir, and
// no other session's. Best-effort.
func unpinSessionRefs(dir, sessionID string) {
	if dir == "" {
		return
	}
	out, err := git(dir, "for-each-ref", "--format=%(refname) %(objectname)", sessionPinPrefix(sessionID))
	if err != nil {
		return
	}
	for _, ln := range strings.Split(strings.TrimSpace(out), "\n") {
		if f := strings.Fields(ln); len(f) == 2 {
			_, _ = git(dir, "update-ref", "-d", f[0], f[1])
		}
	}
}

// baselineObjectMissing reports whether the baseline object ref is absent from the
// repository at dir. It separates "git lost the baseline" (SkipBaselineGone) from a diff that
// failed for some other reason with the baseline still there.
func baselineObjectMissing(dir, ref string) bool {
	_, err := git(dir, "cat-file", "-e", ref)
	return err != nil && !errors.Is(err, errGitTimedOut)
}

// unpinSession removes the session's pins from every repository its scratch still names:
// the current baseline's, the staged next one's and each discovered repository's.
// Called by ClearBaseline before the scratch is deleted, since afterwards nothing names
// those repositories. sessionID is the agent's own id, scopedID the scratch key.
func unpinSession(cwd, scopedID, sessionID string) {
	var data []byte
	for _, p := range []string{scratchPath(scopedID), stagedPath(scopedID)} {
		if b, err := os.ReadFile(p); err == nil {
			if len(b) > 0 && b[len(b)-1] != '\n' {
				b = append(b, '\n')
			}
			data = append(data, b...)
		}
	}
	data = append(data, readDiscovered(scopedID)...)
	seen := map[string]bool{}
	for _, s := range parseBaselines(data) {
		if d := s.dir(cwd); !seen[d] {
			seen[d] = true
			unpinSessionRefs(d, sessionID)
		}
	}
}
