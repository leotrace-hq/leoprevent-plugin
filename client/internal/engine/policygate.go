package engine

import (
	"fmt"
	"io"
	"sort"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/notify"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/policycheck"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/vcs"
)

// turnRepos names every repository this turn would send something about: cwd's own, and each
// changed repository's. "" stands for a repository with no remote (or a folder that isn't one),
// which the server matches against the literal `no-remote` exclusion.
func turnRepos(cwd string, changes []transcript.Change) []string {
	seen := map[string]bool{}
	var out []string
	add := func(r string) {
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	cwdIsRepo := false
	for _, c := range changes {
		if c.RepoDir == "" {
			cwdIsRepo = true
		}
	}
	if len(changes) == 0 || cwdIsRepo {
		add(vcs.RepoOrigin(cwd))
	}
	for _, root := range changedRepoRoots(cwd, changes) {
		add(vcs.RepoOrigin(root))
	}
	sort.Strings(out)
	return out
}

// policyGate runs the organisation's exclusion check before anything for this turn is sent
// (docs/enterprise.md § Policies on reviews). It reports true when the turn must send nothing:
// a repository it touches is excluded, or the check couldn't be made for a license known to
// exclude something. Then it shows a non-blocking notice once per session and the stop proceeds
// (fail-open: never a block). A failed check for any other license lets the turn proceed. A
// reviewer with no check (none today but the cloud tier has one) never skips.
func policyGate(t stopTurn, stdout io.Writer) bool {
	pc, ok := t.r.(policycheck.Checker)
	if !ok {
		return false
	}
	res := policycheck.Check(pc, licenseKey(), turnRepos(t.ev.Cwd, t.changes), t.now)
	if !res.Skip {
		if res.Unchecked != "" {
			t.log.Warn("policy check failed; no known exclusions, so the turn proceeds", "repo", res.Repo, "reason", res.Unchecked)
		}
		return false
	}
	t.log.Warn("turn not sent: organisation review policy", "notice", res.NoticeID, "repo", res.Repo, "reason", res.Reason)
	if !notify.FirstThisSession(t.ev.SessionID, res.NoticeID) {
		return true
	}
	if out, err := t.a.DeliverNotice(res.Notice); err == nil {
		fmt.Fprint(stdout, string(out))
	}
	return true
}
