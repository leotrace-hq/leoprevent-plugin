package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

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
