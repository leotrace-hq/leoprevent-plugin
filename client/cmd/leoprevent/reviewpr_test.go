package main

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

func mainSource(t *testing.T) string {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate this test's own file")
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(self), "main.go"))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// TestReviewPRIsDispatchedBeforeTheHookPath. A CI job's stdin is EMPTY, so reaching
// run() would have the payload read as an unparseable hook event and fail open
// silently — a review-pr invocation that appears to work and reviews nothing. The
// dispatch order is the whole guarantee, and it lives in main(), which calls
// os.Exit and so cannot be driven from a test; a source assertion is what is
// available, and it is the same shape manifest_test.go uses.
func TestReviewPRIsDispatchedBeforeTheHookPath(t *testing.T) {
	src := mainSource(t)
	dispatch := strings.Index(src, `os.Args[1] == "review-pr"`)
	hook := strings.Index(src, "os.Exit(run(os.Args[1:]")
	if dispatch < 0 {
		t.Fatal(`main() does not dispatch "review-pr"`)
	}
	if hook < 0 {
		t.Fatal("cannot find the hook-path dispatch")
	}
	if dispatch > hook {
		t.Error(`"review-pr" must be dispatched BEFORE run(): a CI job has no hook event on stdin`)
	}
}

// TestCIEnvironmentNeverGuessesARuntime. A wrong bucket is invisible and silently
// inflates a real surface; an honest unknown announces itself and names its own fix
// in environment_raw. Same call execEnvironment and every agent adapter make.
func TestCIEnvironmentNeverGuessesARuntime(t *testing.T) {
	for _, k := range []string{"GITHUB_ACTIONS", "GITLAB_CI", "CI"} {
		t.Setenv(k, "")
	}

	t.Run("github actions is named", func(t *testing.T) {
		t.Setenv("GITHUB_ACTIONS", "true")
		name, raw := ciEnvironment()
		if name != wire.EnvGitHubActions || raw != "github_actions" {
			t.Errorf("got (%q, %q), want (%q, %q)", name, raw, wire.EnvGitHubActions, "github_actions")
		}
	})

	t.Run("another provider is unknown with its own raw value", func(t *testing.T) {
		t.Setenv("GITLAB_CI", "true")
		name, raw := ciEnvironment()
		if name != wire.EnvUnknown {
			t.Errorf("name = %q, want %q — a provider earns a constant when its raw value shows up, not before", name, wire.EnvUnknown)
		}
		if raw == "" {
			t.Error("environment_raw must name what we actually saw, or the unknown is undiagnosable")
		}
	})

	t.Run("not CI at all is absent, not unknown", func(t *testing.T) {
		name, raw := ciEnvironment()
		if name != "" || raw != "" {
			t.Errorf(`got (%q, %q), want empty: absent means "no signal", which is true, where unknown would claim a runtime that is not there`, name, raw)
		}
	})
}

// TestTheDefaultIsAdvisory. This is the no-blocking-gate non-negotiable in its second
// costume, and it is stronger here than on the Stop hook: a false positive that blocks
// one turn costs one developer a minute, while one in a merge queue blocks a team —
// and the team's answer is to delete the workflow.
func TestTheDefaultIsAdvisory(t *testing.T) {
	_, self, _, _ := runtime.Caller(0)
	data, err := os.ReadFile(filepath.Join(filepath.Dir(self), "reviewpr.go"))
	if err != nil {
		t.Fatal(err)
	}
	src := string(data)

	flagDecl := regexp.MustCompile(`fs\.Bool\("fail-on-findings",\s*false\b`)
	if !flagDecl.MatchString(src) {
		t.Error("--fail-on-findings must default to FALSE; a customer opts in to a blocking posture, never out of one")
	}
	// EXACTLY ONE failing exit, and it must sit directly under the opt-in test. Any
	// other `return 1` is a build failure the customer did not ask for — and counting
	// them is what makes adding one break this test rather than pass review.
	lines := strings.Split(src, "\n")
	found := 0
	for i, line := range lines {
		if strings.TrimSpace(line) != "return 1" {
			continue
		}
		found++
		if i == 0 || !strings.Contains(lines[i-1], "failOn") {
			prev := ""
			if i > 0 {
				prev = strings.TrimSpace(lines[i-1])
			}
			t.Errorf("a failing exit must sit directly under the --fail-on-findings test; its guard reads %q", prev)
		}
	}
	if found != 1 {
		t.Errorf("found %d failing exits, want exactly 1 (the opt-in)", found)
	}
}

// TestQualifyBaseLeavesAnExplicitValueAlone. A caller naming a SHA or a
// fully-qualified ref must not have origin/ prepended to it; only the zero-config
// branch name is rewritten, because a pull_request checkout holds the base branch as
// a remote-tracking ref only.
func TestQualifyBaseLeavesAnExplicitValueAlone(t *testing.T) {
	if got := qualifyBase(t.TempDir(), ""); got != "" {
		t.Errorf("qualifyBase(_, %q) = %q, want unchanged", "", got)
	}
	// Outside a repository nothing resolves, so the value is returned untouched
	// rather than being decorated with a remote that does not exist.
	if got := qualifyBase(t.TempDir(), "deadbeef"); got != "deadbeef" {
		t.Errorf("qualifyBase = %q, want %q untouched", got, "deadbeef")
	}
}
