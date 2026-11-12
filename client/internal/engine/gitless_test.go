package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/depquiet"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/notify"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

// In a folder with no git repository (LEO-659), the session scan tells the server there's no
// baseline, and every later Stop sends the dependency files whose content changed since they were
// last checked, each whole, with baseline "none", even though the transcript shows no change (a
// lockfile npm install wrote). An unchanged folder sends nothing. The Stop after a wake re-checks
// what changed since. A repository keeps the usual per-turn check.
func TestWithoutARepositoryEveryStopChecksWhatChanged(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, "package-lock.json")
	write := func(v string) {
		if err := os.WriteFile(lockPath, []byte(npmLock(v)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("4.17.10")
	rec := &recordingChecker{}
	turn := routerTurn()
	turn.r = &scanChecker{}
	turn.ev.Cwd, turn.ev.SessionID = dir, "router-gitless-"+filepath.Base(dir)
	notify.Clear(turn.ev.SessionID)
	t.Cleanup(func() { notify.Clear(turn.ev.SessionID) })

	sent := func() string {
		var s []string
		for _, r := range rec.got {
			s = append(s, r.Trigger+":"+r.Baseline+":"+r.Path)
		}
		rec.got = nil
		return strings.Join(s, ",")
	}

	checks := stopChecks(turn)
	scan, ok := checks[1].(sessionScanCheck)
	if !ok {
		t.Fatalf("first Stop: %T", checks[1])
	}
	scan.checker = rec
	scan.run(turn, nil)
	if got := sent(); got != "scan:none:package-lock.json" {
		t.Errorf("the scan: %q", got)
	}

	checks = stopChecks(turn)
	later, ok := checks[1].(gitlessCheck)
	if !ok || !later.runsWithoutFiles() {
		t.Fatalf("a later Stop without a repository: %T", checks[1])
	}
	later.checker = rec
	later.run(turn, nil)
	if got := sent(); got != "" {
		t.Errorf("nothing changed, nothing sent: %q", got)
	}
	write("4.17.15") // npm install, not the agent's edit tools: no transcript change
	later.run(turn, nil)
	if got := sent(); got != "turn:none:package-lock.json" {
		t.Errorf("the changed lockfile: %q", got)
	}
	later.run(turn, nil)
	if got := sent(); got != "" {
		t.Errorf("checked once per content: %q", got)
	}

	write("4.18.1") // the agent's fix
	if _, ran := recheckWithoutRepository(turn, rec, nil); !ran {
		t.Error("the re-check runs for a changed file")
	}
	if got := sent(); got != "recheck:none:package-lock.json" {
		t.Errorf("the re-check: %q", got)
	}
	if _, ran := recheckWithoutRepository(turn, rec, nil); ran {
		t.Error("nothing changed since: no re-check")
	}

	turn.usedGit = true
	if _, ok := stopChecks(turn)[1].(dependencyCheck); !ok {
		t.Errorf("with a git baseline, the usual check: %T", stopChecks(turn)[1])
	}
}

// A repository's requests never carry a baseline.
func TestARepositorysRequestsHaveNoBaseline(t *testing.T) {
	rec := &recordingChecker{}
	if _, err := (stamped{checker: rec, trigger: wire.DependencyTriggerTurn}).CheckDependencies(wire.DependenciesRequest{Ecosystem: "npm"}); err != nil {
		t.Fatal(err)
	}
	if rec.got[0].Baseline != "" {
		t.Errorf("baseline %q", rec.got[0].Baseline)
	}
}

// gitlessServer answers a folder with no repository as the server does: lodash needs a fix on
// its major, so it's in the notice and put to the agent, unless the request's quiet covers it.
type gitlessServer struct{ got []wire.DependenciesRequest }

func (s *gitlessServer) CheckDependencies(req wire.DependenciesRequest) (wire.DependenciesResponse, error) {
	s.got = append(s.got, req)
	resp := wire.DependenciesResponse{Ecosystem: req.Ecosystem}
	for _, p := range req.Packages {
		c := wire.DependencyCheck{Name: p.Name, Version: p.Version, Security: &wire.DependencySecurity{NeedsFix: true,
			Advisories: []wire.DependencyAdvisory{{IDs: []string{"GHSA-lodash"}, Severity: "high"}}}}
		resp.Packages = append(resp.Packages, c)
		if len(req.Quiet) > 0 {
			resp.Quieted = append(resp.Quieted, req.Quiet...)
			continue
		}
		resp.Issues++
		resp.Verdict = wire.VerdictTriggered
		notice := "🛡️ LeoPrevent · dependency scan (1 package)\n- lodash " + p.Version
		agent := "🛡️ LeoPrevent · dependency check: this folder isn't under git. Move lodash in " + req.Path + "."
		resp.Messages.Developer, resp.Messages.Agent = &notice, &agent
		resp.Messages.AgentPackages = []string{p.Name + "@" + p.Version}
	}
	return resp, nil
}

// Without a repository, five dependency files with a notice make the scan brief too (LEO-778):
// the must-fix instructions become one question that says the folder isn't under git, the offer
// waits for the developer's answer under the folder, and once answered the next session's scan
// sends it back as each file's quiet.
func TestWithoutARepositoryABriefScanAsksAndQuietensByFolder(t *testing.T) {
	scanQuietScratch(t)
	dir := t.TempDir()
	for i := 0; i < 5; i++ {
		sub := filepath.Join(dir, fmt.Sprintf("app%d", i))
		if err := os.MkdirAll(sub, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(sub, "package-lock.json"), []byte(npmLock("4.17.10")), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	srv := &gitlessServer{}
	turn := routerTurn()
	turn.r = &scanChecker{}
	turn.now = time.Now()
	turn.ev.Cwd, turn.ev.SessionID = dir, "router-gitless-brief-"+filepath.Base(dir)
	notify.Clear(turn.ev.SessionID)
	t.Cleanup(func() { notify.Clear(turn.ev.SessionID) })

	res := sessionScanCheck{dependencyCheck{checker: srv}}.run(turn, nil)
	if res.agent != "" {
		t.Errorf("nothing is put to the agent to fix; it's offered:\n%s", res.agent)
	}
	if !strings.Contains(res.offer, "This folder isn't a git repository, so LeoPrevent can't tell which of these were already here.") ||
		strings.Count(res.offer, "Ask once") != 1 || !strings.Contains(res.offer, "Move lodash in app4/package-lock.json.") {
		t.Errorf("one question, with each file's instructions behind it:\n%s", res.offer)
	}
	if !strings.Contains(res.notice, "- 5 high\n- 5 files have a fix on the same major version\n") || !strings.Contains(res.notice, "no git repo here") {
		t.Errorf("brief, with the no-git warning:\n%s", res.notice)
	}
	if len(res.asked) != 5 {
		t.Errorf("what's offered is recorded as asked once the agent is woken: %v", res.asked)
	}
	p, ok := depquiet.TakePending(turn.ev.SessionID)
	if !ok || p.Repo != folderIdentity(dir) || len(p.Entries) != 5 {
		t.Fatalf("pending under the folder: %+v %v", p, ok)
	}
	depquiet.Answer(p.Repo, p.Entries, turn.now)

	next := turn
	next.ev.SessionID += "-next"
	notify.Clear(next.ev.SessionID)
	t.Cleanup(func() { notify.Clear(next.ev.SessionID) })
	srv.got = nil
	res = sessionScanCheck{dependencyCheck{checker: srv}}.run(next, nil)
	for _, req := range srv.got {
		if len(req.Quiet) != 1 || req.Quiet[0].Name != "lodash" {
			t.Errorf("%s: the answer is sent back as its quiet: %+v", req.Path, req.Quiet)
		}
	}
	if res.offer != "" || res.agent != "" || !strings.Contains(res.notice, "answered earlier") {
		t.Errorf("answered: a reminder only\nnotice %s\noffer %s\nagent %s", res.notice, res.offer, res.agent)
	}
}

// The folder's identity is its resolved path, so a symlink to it shares the quiet, and another
// folder has its own.
func TestFolderIdentityResolvesTheFolder(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if a, b := folderIdentity(dir), folderIdentity(link); a == "" || a != b || !strings.HasPrefix(a, "folder:") {
		t.Errorf("%q and %q", a, b)
	}
	if folderIdentity(t.TempDir()) == folderIdentity(dir) || folderIdentity("") != "" {
		t.Error("another folder, or none, shares it")
	}
}
