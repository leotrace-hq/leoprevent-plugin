package engine

// The Stop's output, recorded (LEO-620, decision D59). Every scenario runs on the Claude terminal
// and the desktop app, and in two modes:
//
//   - dependency check off: the output is compared with the recorded golden file;
//   - dependency check on, the server answering "nothing to report": the output must be EXACTLY
//     the same as with it off;
//   - dependency check on, the server reporting an issue: for a scenario that changes a
//     dependency file, compared with its own golden file (*.issues.golden), so what the developer
//     and the agent get is recorded for every combination; for any other, the same as off.
//
// The second comparison is the guarantee that the dependency check has no effect on /review or
// /outcome when it has nothing to say, and every change that runs the two checks side by side
// must keep it. Regenerate the golden files only when the code review's own output is meant to
// change:
//
//	go test ./client/internal/engine -run TestStopOutputIsUnchanged -update-stop-golden

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/agent/claude"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/config"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/notify"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/outcome"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/review"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/scratch"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/vcs"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

var updateStopGolden = flag.Bool("update-stop-golden", false, "rewrite testdata/stop/*.golden from the current output")

// quietDeps is the cloud reviewer with a dependency check that has nothing to report, or, with
// notice set, one issue to report in that wording.
type quietDeps struct {
	fakeReviewer
	calls  int
	notice string
	// agent, when set, is what the server puts to the agent about lodash, as the real one does:
	// only when the turn added or changed it, and only until the client sends it back as asked,
	// and then (the fix's re-check) clean.
	agent string
	// offer, when set, is the session scan's offer (LEO-673) about lodash, as the real server makes
	// it: on a scan, when the turn didn't change lodash, and until it's sent back as asked.
	offer string
	// triggers is what each request said ran it, in order.
	triggers []string
}

// goldenIssue is what the server says about lodash 4.17.15, as it words it on dev.
const goldenIssue = "🛡️ LeoPrevent · dependency check (1 package)\nlodash 4.17.15 (was 4.17.10) has 3 high vulnerabilities (GHSA-35jh-r3h4-6jhm and 2 more). The advisories name 4.18.0 as the fix."

func (q *quietDeps) CheckDependencies(req wire.DependenciesRequest) (wire.DependenciesResponse, error) {
	q.calls++
	q.triggers = append(q.triggers, req.Trigger)
	if q.notice == "" || q.agent != "" && slices.Contains(req.Asked, "lodash@4.17.15") {
		return wire.DependenciesResponse{Ecosystem: req.Ecosystem, Verdict: wire.VerdictClean}, nil
	}
	msg := q.notice
	resp := wire.DependenciesResponse{Ecosystem: req.Ecosystem, Verdict: wire.VerdictTriggered, Issues: 1,
		Messages: wire.DependencyMessages{Developer: &msg}}
	changed := slices.ContainsFunc(req.Packages, func(p wire.DependencyVersion) bool {
		return p.Name == "lodash" && (p.Change == wire.DependencyAdded || p.Change == wire.DependencyChanged)
	})
	if q.agent != "" && changed {
		ask := q.agent
		resp.Messages.Agent, resp.Messages.AgentPackages = &ask, []string{"lodash@4.17.15"}
	}
	if q.offer != "" && !changed && req.Trigger == wire.DependencyTriggerScan && !slices.Contains(req.Asked, "lodash@4.17.10") {
		offer := q.offer
		resp.Messages.AgentOffer, resp.Messages.AgentOfferPackages = &offer, []string{"lodash@4.17.10"}
	}
	return resp, nil
}

// goldenOffer is the session scan's offer about lodash 4.17.10, as the server words it (LEO-673).
const goldenOffer = "🛡️ LeoPrevent · dependency scan: this project already has dependencies with high or critical vulnerabilities (package-lock.json). These weren't added this session, so don't change them unless the developer agrees. Ask once, in one short question at the end of your reply: \"Fix the 1 dependency that has a fix on the same major version?\" Change nothing unless they say yes.\n\n" +
	"If they say yes:\n" +
	"- lodash 4.17.10 (1 critical and 3 high): change it to 4.18.0, the lowest version that fixes them all.\n" +
	"Make each change in package.json and update the lockfile. Change no other dependency.\n" +
	"These versions come from current advisory data. If LeoPrevent's security review names a different version for the same package, use the one here."

// goldenAsk is what the server puts to the agent about lodash 4.17.15, as it words it.
const goldenAsk = "🛡️ LeoPrevent · dependency check: this turn added or changed dependencies with high or critical vulnerabilities (package-lock.json).\n" +
	"- lodash 4.17.15 (3 high): change it to 4.18.0.\n" +
	"Make each change in package.json and update the lockfile. Change no other dependency. If the developer asked for one of these versions, don't change it: tell them instead.\n" +
	"These versions come from current advisory data. If LeoPrevent's security review names a different version for the same package, use the one here."

var sqlFinding = wire.Finding{Rule: "sql-injection", Name: "SQL Injection", Location: "app.py:2", Severity: "high"}

// stopScenario is one Stop, or a blocked Stop and the one after the agent's fix.
type stopScenario struct {
	name string
	// writes are the turn's changes: path to content.
	writes map[string]string
	// reviewer builds the code review's behaviour for the first Stop.
	reviewer func() fakeReviewer
	// fix, when set, is the agent's re-wake work: written, then the second Stop runs.
	fix map[string]string
	// firstCleanShown claims the one-time first-clean notice before the turn.
	firstCleanShown bool
	// depsChanged says the turn changes a dependency file, so the check must have run.
	depsChanged bool
	// sessionScan plays the session's first Stop, where every dependency file in the project is
	// scanned (LEO-549). Without it the scan is marked done, so the Stop is a later turn's.
	sessionScan bool
}

var stopScenarios = []stopScenario{
	{name: "nothing-changed", reviewer: func() fakeReviewer { return fakeReviewer{} }},
	{name: "docs-only", writes: map[string]string{"README.md": "# docs\n"}, reviewer: func() fakeReviewer { return fakeReviewer{} }},
	{name: "lockfile-only", writes: map[string]string{"package-lock.json": npmLock("4.17.15")},
		reviewer: func() fakeReviewer { return fakeReviewer{} }, depsChanged: true},
	{name: "code-clean-first-clean-due", writes: map[string]string{"app.py": "import os\nx = 1\n"},
		reviewer: func() fakeReviewer { return fakeReviewer{} }},
	{name: "code-clean", writes: map[string]string{"app.py": "import os\nx = 1\n"},
		reviewer: func() fakeReviewer { return fakeReviewer{} }, firstCleanShown: true},
	{name: "code-and-lockfile-clean-first-clean-due", writes: map[string]string{"app.py": "import os\nx = 1\n", "package-lock.json": npmLock("4.17.15")},
		reviewer: func() fakeReviewer { return fakeReviewer{} }, depsChanged: true},
	{name: "code-and-lockfile-clean", writes: map[string]string{"app.py": "import os\nx = 1\n", "package-lock.json": npmLock("4.17.15")},
		reviewer: func() fakeReviewer { return fakeReviewer{} }, firstCleanShown: true, depsChanged: true},
	{name: "code-findings", writes: map[string]string{"app.py": "import os\nq = f\"SELECT {x}\"\n"},
		reviewer: func() fakeReviewer {
			return fakeReviewer{prompt: "FIX THESE FINDINGS", findings: []wire.Finding{sqlFinding},
				pending: &outcome.Pending{ReviewID: "rid-golden", Findings: []wire.Finding{sqlFinding}}}
		}},
	{name: "code-and-lockfile-findings", writes: map[string]string{"app.py": "import os\nq = f\"SELECT {x}\"\n", "package-lock.json": npmLock("4.17.15")},
		reviewer: func() fakeReviewer {
			return fakeReviewer{prompt: "FIX THESE FINDINGS", findings: []wire.Finding{sqlFinding},
				pending: &outcome.Pending{ReviewID: "rid-golden", Findings: []wire.Finding{sqlFinding}}}
		}, depsChanged: true},
	// A classified failure shows the "not reviewed" notice; an unclassified one is silent by design.
	{name: "review-unreachable", writes: map[string]string{"app.py": "import os\nx = 1\n"},
		reviewer: func() fakeReviewer {
			return fakeReviewer{err: &review.SkipError{Reason: review.SkipUnreachable, Err: errors.New("dial tcp: connection refused")}}
		}},
	{name: "review-unclassified-error", writes: map[string]string{"app.py": "import os\nx = 1\n"},
		reviewer: func() fakeReviewer { return fakeReviewer{err: errors.New("something unexpected")} }},
	{name: "fix-cleared", writes: map[string]string{"app.py": "import os\nq = f\"SELECT {x}\"\n"},
		reviewer: func() fakeReviewer {
			return fakeReviewer{prompt: "FIX THESE FINDINGS", findings: []wire.Finding{sqlFinding},
				pending: &outcome.Pending{ReviewID: "rid-golden", Findings: []wire.Finding{sqlFinding}}}
		}, fix: map[string]string{"app.py": "import os\nq = run(\"SELECT ?\", x)\n"}},
	{name: "fix-still-firing", writes: map[string]string{"app.py": "import os\nq = f\"SELECT {x}\"\n"},
		reviewer: func() fakeReviewer {
			return fakeReviewer{prompt: "FIX THESE FINDINGS", findings: []wire.Finding{sqlFinding},
				pending:            &outcome.Pending{ReviewID: "rid-golden", Findings: []wire.Finding{sqlFinding}},
				outcomeStillFiring: []wire.Finding{sqlFinding}}
		}, fix: map[string]string{"app.py": "import os\nq = f\"SELECT {x!r}\"\n"}},
	{name: "fix-with-lockfile", writes: map[string]string{"app.py": "import os\nq = f\"SELECT {x}\"\n"},
		reviewer: func() fakeReviewer {
			return fakeReviewer{prompt: "FIX THESE FINDINGS", findings: []wire.Finding{sqlFinding},
				pending: &outcome.Pending{ReviewID: "rid-golden", Findings: []wire.Finding{sqlFinding}}}
		}, fix: map[string]string{"app.py": "import os\nq = run(\"SELECT ?\", x)\n", "package-lock.json": npmLock("4.17.21")}},
	// The session's first Stop scans the committed lockfile even though nothing changed.
	{name: "session-scan-nothing-changed", reviewer: func() fakeReviewer { return fakeReviewer{} }, sessionScan: true},
	// With review findings and a changed lockfile: the review's wake as ever, and the lockfile
	// sent once, whole, by the scan (never a second time by the turn's own check).
	{name: "session-scan-code-and-lockfile-findings", writes: map[string]string{"app.py": "import os\nq = f\"SELECT {x}\"\n", "package-lock.json": npmLock("4.17.15")},
		reviewer: func() fakeReviewer {
			return fakeReviewer{prompt: "FIX THESE FINDINGS", findings: []wire.Finding{sqlFinding},
				pending: &outcome.Pending{ReviewID: "rid-golden", Findings: []wire.Finding{sqlFinding}}}
		}, depsChanged: true, sessionScan: true},
}

func TestStopOutputIsUnchanged(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	for _, sc := range stopScenarios {
		for _, surface := range []string{"cli", "claude-desktop"} {
			t.Run(sc.name+"/"+surface, func(t *testing.T) {
				t.Setenv("CLAUDE_CODE_ENTRYPOINT", surface)
				off := runStopScenario(t, sc, "off", nil)
				deps := &quietDeps{}
				on := runStopScenario(t, sc, "on", deps)
				if on != off {
					t.Errorf("the dependency check, with nothing to report, changed the Stop's output:\n--- off\n%s\n--- on\n%s", off, on)
				}
				if sc.depsChanged && deps.calls == 0 {
					t.Error("a dependency file changed, so the check must have run")
				}
				if !sc.depsChanged && !sc.sessionScan && sc.fix == nil && deps.calls != 0 {
					t.Errorf("no dependency file changed, yet the check was called %d times", deps.calls)
				}
				if sc.sessionScan && deps.calls != 1 {
					t.Errorf("the project has one lockfile, so the scan sends it once: %d requests", deps.calls)
				}
				compareGolden(t, filepath.Join("testdata", "stop", sc.name+"."+surface+".golden"), off)

				issues := runStopScenario(t, sc, "issues", &quietDeps{notice: goldenIssue})
				switch {
				case sc.depsChanged || sc.sessionScan:
					compareGolden(t, filepath.Join("testdata", "stop", sc.name+"."+surface+".issues.golden"), issues)
				case issues != off:
					t.Errorf("no dependency file changed, so an issue the check would report can't appear:\n--- off\n%s\n--- issues\n%s", off, issues)
				}

				// The agent is asked about what the turn brought in (LEO-620): one wake, the review's
				// own prompt first and unchanged, then the dependency section; the Stop after it
				// re-checks and never wakes.
				askDeps := &quietDeps{notice: goldenIssue, agent: goldenAsk}
				ask := runStopScenario(t, sc, "ask", askDeps)
				switch {
				case sc.depsChanged:
					compareGolden(t, filepath.Join("testdata", "stop", sc.name+"."+surface+".ask.golden"), ask)
					if rv := firstReason(t, off); rv != "" && rv != review.FirstCleanRelayPrompt() && !strings.HasPrefix(firstReason(t, ask), rv) {
						t.Errorf("the review's prompt must come first, unchanged:\n--- review\n%s\n--- with dependencies\n%s", rv, firstReason(t, ask))
					}
					if !strings.Contains(firstReason(t, ask), goldenAsk) {
						t.Errorf("the agent wasn't asked: %s", ask)
					}
					// The Stop after the wake re-checks, and says so, so the server doesn't record it again.
					if n := len(askDeps.triggers); n < 2 || askDeps.triggers[n-1] != wire.DependencyTriggerRecheck {
						t.Errorf("the re-check must be sent as recheck: %v", askDeps.triggers)
					}
				case strings.Contains(ask, "change it to 4.18.0"):
					t.Errorf("nothing the turn changed can be put to the agent:\n%s", ask)
				}

				// The session scan offers what was already there (LEO-673): in the same wake as
				// everything else, last, and the scan's notice an addendum to it, never the
				// print-only relay that would forbid the question.
				if sc.sessionScan {
					offer := runStopScenario(t, sc, "offer", &quietDeps{notice: goldenIssue, offer: goldenOffer})
					compareGolden(t, filepath.Join("testdata", "stop", sc.name+"."+surface+".offer.golden"), offer)
					switch {
					case sc.depsChanged && strings.Contains(offer, "Fix the 1 dependency"):
						t.Errorf("the turn changed lodash, so it's the turn's to fix, not an offer: %s", offer)
					case !sc.depsChanged && !strings.Contains(firstReason(t, offer), goldenOffer):
						t.Errorf("the scan's offer must wake the agent: %s", offer)
					}
					if strings.Contains(offer, "and nothing else") {
						t.Errorf("never the print-only relay with an offer: %s", offer)
					}
				}
			})
		}
	}
}

// runStopScenario plays one scenario and returns everything the Stop(s) printed, normalised.
// With deps nil the dependency check is off; otherwise it's on, answered by deps.
func runStopScenario(t *testing.T, sc stopScenario, mode string, deps *quietDeps) string {
	t.Helper()
	restore := config.SetUserConfigDirForTest(t.TempDir())
	t.Cleanup(restore)
	// The output must not depend on the shell the tests run in: Claude Code sets this for its own
	// sessions, and it adds an AskUserQuestion instruction to the offer and to suggest-only findings.
	t.Setenv("CLAUDE_CODE_ENABLE_ASK_USER_QUESTION_TOOL", "")
	withLicense(t, "lp_test_golden")
	if sc.firstCleanShown {
		config.ClaimFirstClean("lp_test_golden")
	}
	dir := t.TempDir()
	gitCmd := func(args ...string) {
		c := exec.Command("git", append([]string{"-C", dir}, args...)...)
		c.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	write := func(files map[string]string) {
		for rel, body := range files {
			if err := os.WriteFile(filepath.Join(dir, rel), []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	gitCmd("init", "-q")
	write(map[string]string{"app.py": "import os\n", "package-lock.json": npmLock("4.17.10")})
	gitCmd("add", "-A")
	gitCmd("commit", "-q", "-m", "init")

	session := fmt.Sprintf("golden-%s-%s-%s", sc.name, os.Getenv("CLAUDE_CODE_ENTRYPOINT"), mode)
	// Start and end clean: the session's baseline, any pending review, and the once-per-session
	// notice markers, so a run never depends on the one before it.
	notify.Clear(session)
	outcome.Take(session)
	if !sc.sessionScan {
		notify.FirstThisSession(session, sessionScanKey) // a later turn: the scan already ran
	}
	t.Cleanup(func() {
		_ = os.Remove(filepath.Join(scratch.Dir("baselines"), session))
		outcome.Take(session)
		notify.Clear(session)
	})
	if err := vcs.CaptureBaseline(dir, session); err != nil {
		t.Fatal(err)
	}
	write(sc.writes)

	fr := sc.reviewer()
	var r Reviewer = &fr
	if deps != nil {
		deps.fakeReviewer = fr
		r = deps
	}
	stdin := fmt.Sprintf(`{"stop_hook_active":false,"hook_event_name":"Stop","cwd":%q,"session_id":%q}`, dir, session)
	_, first, _ := runWith(claude.New(), r, stdin)
	out := "== first Stop\n" + first
	fix := sc.fix
	if fix == nil && mode == "ask" && strings.Contains(first, "change it to 4.18.0") {
		fix = map[string]string{"package-lock.json": npmLock("4.18.0")} // the agent did as asked
	}
	if fix != nil {
		write(fix)
		stdin = fmt.Sprintf(`{"stop_hook_active":true,"hook_event_name":"Stop","cwd":%q,"session_id":%q,"last_assistant_message":"Fixed the SQL injection."}`, dir, session)
		_, second, _ := runWith(claude.New(), r, stdin)
		out += "\n== second Stop\n" + second
		// Where the second Stop relays the dependency re-check (the desktop app), the relay's own
		// Stop must have nothing left to say: the turn ends there.
		if mode == "ask" && strings.Contains(second, `"decision":"block"`) {
			_, third, _ := runWith(claude.New(), r, stdin)
			out += "\n== third Stop\n" + third
			if strings.TrimSpace(third) != "" {
				t.Errorf("the relay's own Stop printed something, so the turn wouldn't end: %s", third)
			}
		}
	}
	return strings.ReplaceAll(out, dir, "<repo>")
}

func compareGolden(t *testing.T, path, got string) {
	t.Helper()
	if *updateStopGolden {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("no golden file %s (run with -update-stop-golden to record it): %v", path, err)
	}
	if string(want) != got {
		t.Errorf("the Stop's output changed (%s):\n--- want\n%s\n--- got\n%s", path, want, got)
	}
}

// firstReason is the reason the first Stop's hook output gives the agent, or "" when it doesn't wake it.
func firstReason(t *testing.T, out string) string {
	t.Helper()
	first, _, _ := strings.Cut(strings.TrimPrefix(out, "== first Stop\n"), "\n== second Stop")
	var hook struct {
		Decision string `json:"decision"`
		Reason   string `json:"reason"`
	}
	if strings.TrimSpace(first) == "" || json.Unmarshal([]byte(first), &hook) != nil || hook.Decision != "block" {
		return ""
	}
	return hook.Reason
}
