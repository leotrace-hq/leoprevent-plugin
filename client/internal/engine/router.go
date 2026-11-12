package engine

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/agent"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/depcheck"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/deps"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/notify"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/vcs"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

// The checks LeoPrevent runs at the end of a turn (LEO-620, decision D59). Each check decides
// which changed files it looks at; the router only runs the checks and combines what they say,
// so adding a check is one more stopCheck, with no change here. The code review and the
// dependency check are separate checks against separate endpoints, and neither feeds the other.
//
// ⚠️ FIRST SLICE: SAME OUTPUT AS BEFORE. The code review runs exactly as it did, and the
// dependency check's notice is attached the way the placeholder attached it. The golden test
// (TestStopOutputIsUnchanged) holds this to the byte. Relaying the notice in the desktop app,
// and the dependency check's own follow-up on the second Stop, come later (LEO-620, LEO-626).

// stopTurn is what a check may look at.
type stopTurn struct {
	a            agent.Agent
	r            Reviewer
	ev           agent.Event
	log          *slog.Logger
	now          time.Time
	recovered    bool
	failOpen     func(error) int
	changes      []transcript.Change
	usedGit      bool
	baselineSkip vcs.SkipReason
	baseInfo     vcs.BaselineInfo
}

// stopCheck is one check run at the end of a turn.
type stopCheck interface {
	name() string
	// selectFiles picks the changed files this check looks at. The check decides; the router
	// never does.
	selectFiles(changes []transcript.Change) []transcript.Change
	// runsWithoutFiles says whether the check runs even when it selected nothing.
	runsWithoutFiles() bool
	run(t stopTurn, files []transcript.Change) stopResult
}

// stopResult is what one check has to say.
type stopResult struct {
	// output is the hook output the check would print on its own (the code review's: a wake,
	// a notice, or nothing).
	output []byte
	// notice is text for the developer only, never for the agent (the dependency check's), and
	// noticeMarkdown the same as markdown, for a surface that renders it ("" means use notice).
	notice, noticeMarkdown string
	// code is the hook's exit code, from the check that owns it (the code review).
	code int
}

// stopChecks are the checks for this turn: the code review always, and the dependency check
// when it's switched on and the tier has it. On the session's first Stop the dependency check is
// the session scan, which checks every dependency file in the project and covers this turn's
// own files too, so they're never sent twice.
func stopChecks(t stopTurn) []stopCheck {
	checks := []stopCheck{codeReviewCheck{}}
	if !depcheck.Enabled() {
		return checks
	}
	c, ok := t.r.(depcheck.Checker)
	if !ok {
		t.log.Debug("dependency check: not available on this tier")
		return checks
	}
	if notify.FirstThisSession(t.ev.SessionID, sessionScanKey) {
		return append(checks, sessionScanCheck{dependencyCheck{checker: c}})
	}
	return append(checks, dependencyCheck{checker: c})
}

// sessionScanKey marks a session whose dependency files have been scanned (once per session).
const sessionScanKey = "deps_session_scan"

// runChecks runs every check that has files (or runs without them) at the same time, then
// combines their results into what this Stop prints, and returns the code review's exit code.
func runChecks(t stopTurn, checks []stopCheck, stdout io.Writer) int {
	results := make([]stopResult, len(checks))
	ran := make([]bool, len(checks))
	var wg sync.WaitGroup
	for i, c := range checks {
		files := c.selectFiles(t.changes)
		if len(files) == 0 && !c.runsWithoutFiles() {
			continue
		}
		ran[i] = true
		wg.Add(1)
		go func(i int, c stopCheck, files []transcript.Change) {
			defer wg.Done()
			results[i] = c.run(t, files)
		}(i, c, files)
	}
	wg.Wait()

	var output []byte
	var notices, markdowns []string
	code := 0
	for i, res := range results {
		if !ran[i] {
			continue
		}
		if len(res.output) > 0 {
			output = append(output, res.output...)
		}
		if res.notice != "" {
			md := res.noticeMarkdown
			if md == "" {
				md = res.notice
			}
			notices, markdowns = append(notices, res.notice), append(markdowns, md)
		}
		if res.code != 0 {
			code = res.code
		}
	}
	if len(notices) > 0 {
		output = deliverForDeveloper(t, output, strings.Join(notices, "\n\n"), strings.Join(markdowns, "\n\n"))
	}
	fmt.Fprint(stdout, string(output))
	return code
}

// developerRelayer is an adapter that can show a developer-only notice on every surface it has,
// relaying it through the agent's reply where a systemMessage isn't shown (the Claude adapter).
type developerRelayer interface {
	RelayForDeveloper(out []byte, notice, markdown string) ([]byte, string, error)
}

// deliverForDeveloper adds the checks' developer notices to the Stop's output. An adapter that
// can relay them does; for any other the notice joins the systemMessage, as before. When the
// agent is asked to print the notice, the exact text is remembered so the next Stop removes it
// from the agent's reply before /outcome (see takeRelayed). Where it's relayed, the markdown is
// what the agent prints; the systemMessage is always the plain text.
func deliverForDeveloper(t stopTurn, output []byte, notice, markdown string) []byte {
	dr, ok := t.a.(developerRelayer)
	if !ok {
		return attachNotice(t.a, output, notice, t.log)
	}
	out, dictated, err := dr.RelayForDeveloper(output, notice, markdown)
	if err != nil {
		t.log.Warn("developer notice not relayed, attached instead", "err", err.Error())
		return attachNotice(t.a, output, notice, t.log)
	}
	if dictated != "" {
		rememberRelayed(t.ev.SessionID, dictated, t.log)
	}
	return out
}

// codeReviewCheck is the code review, wrapped exactly as it was. It takes every changed file and
// runs even when there are none: its own gate decides what is reviewed, and an empty or inert
// turn still reports its cost (telemetry). Separating its second-Stop follow-up is LEO-626.
type codeReviewCheck struct{}

func (codeReviewCheck) name() string           { return "code review" }
func (codeReviewCheck) runsWithoutFiles() bool { return true }

func (codeReviewCheck) selectFiles(changes []transcript.Change) []transcript.Change {
	return changes
}

func (codeReviewCheck) run(t stopTurn, files []transcript.Change) stopResult {
	t.changes = files
	var out bytes.Buffer
	code := codeReview(t, &out)
	return stopResult{output: out.Bytes(), code: code}
}

// dependencyCheck is the dependency check (off unless LEOPREVENT_SEND_DEPENDENCIES=on; see
// internal/depcheck). It looks only at the files a reader reads, and its notice is for the
// developer only: it never blocks, never wakes the agent and never reaches /review or /outcome.
type dependencyCheck struct {
	checker depcheck.Checker
}

func (dependencyCheck) name() string           { return "dependency check" }
func (dependencyCheck) runsWithoutFiles() bool { return false }

func (dependencyCheck) selectFiles(changes []transcript.Change) []transcript.Change {
	var out []transcript.Change
	for _, c := range changes {
		if c.Deleted || c.Virtual {
			continue
		}
		if _, ok := deps.All.For(c.FilePath); ok {
			out = append(out, c)
		}
	}
	return out
}

func (d dependencyCheck) run(t stopTurn, files []transcript.Change) stopResult {
	c := stamped{checker: d.checker, meta: dependencyMeta(t), trigger: wire.DependencyTriggerTurn}
	text, md := depcheck.Run(files, t.ev.Cwd, turnStart(t), c, t.log)
	return stopResult{notice: text, noticeMarkdown: md}
}

// stamped puts who and where the check is for on every request: the turn's identity, what ran
// the check, and the scan it belongs to, so the server can record what it found against the
// repository (the activity log), as review events are.
type stamped struct {
	checker depcheck.Checker
	meta    *wire.TurnMeta
	trigger string
	scanID  string
}

func (s stamped) CheckDependencies(req wire.DependenciesRequest) (wire.DependenciesResponse, error) {
	req.Meta, req.Trigger, req.ScanID = s.meta, s.trigger, s.scanID
	return s.checker.CheckDependencies(req)
}

// dependencyMeta is the identity half of the turn's metadata, the same values /review gets:
// agent, model, repository, developer, platform, client version and environment. Never the
// prompt, token counts or durations, which are about the agent's turn, not the dependency file.
func dependencyMeta(t stopTurn) *wire.TurnMeta {
	full := withDiscovery(turnMeta(t.a, t.ev, t.log, t.now), t.ev, t.changes, t.usedGit, t.baselineSkip, t.baseInfo, t.log)
	return &wire.TurnMeta{
		Agent: full.Agent, AgentModel: full.AgentModel, Repo: full.Repo,
		Developer: full.Developer, DeveloperSource: full.DeveloperSource,
		OS: full.OS, Arch: full.Arch, ClientVersion: full.ClientVersion,
		Environment: full.Environment, EnvironmentRaw: full.EnvironmentRaw,
	}
}

// newScanID names one session scan, so its requests (one per dependency file) can be grouped.
func newScanID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ""
	}
	return hex.EncodeToString(b[:])
}

// turnStart reads files as they were at the start of the turn, when there's a git baseline.
func turnStart(t stopTurn) depcheck.TurnStart {
	if !t.usedGit {
		return nil
	}
	ts, ok := vcs.LoadTurnStart(t.ev.Cwd, t.ev.SessionID)
	if !ok {
		return nil
	}
	return func(root string) deps.Opener { return ts.Opener(root) }
}

// sessionScanCheck is the dependency check on a session's first Stop (LEO-549, decision D51):
// every dependency file in the project, read whole, for the developer's information only, plus
// this turn's own dependency files. It runs even when the turn changed no files. Like the
// dependency check, it never blocks, never wakes the agent to act and never reaches /review or
// /outcome; in the desktop app the agent is only asked to print it.
type sessionScanCheck struct{ dependencyCheck }

func (sessionScanCheck) name() string           { return "dependency scan" }
func (sessionScanCheck) runsWithoutFiles() bool { return true }

func (s sessionScanCheck) run(t stopTurn, files []transcript.Change) stopResult {
	w := depcheck.Find(t.ev.Cwd, projectLister, t.log)
	c := stamped{checker: s.checker, meta: dependencyMeta(t), trigger: wire.DependencyTriggerScan, scanID: newScanID()}
	text, md := depcheck.Scan(w, files, t.ev.Cwd, turnStart(t), c, t.log)
	return stopResult{notice: text, noticeMarkdown: md}
}

// projectLister is how the scan finds the project: the repositories vcs decides the session is
// in, and the files git lists in each.
var projectLister = depcheck.Lister{
	Projects: func(cwd string) ([]string, string) {
		p := vcs.ProjectRepos(cwd)
		return p.Roots, p.Skip
	},
	Files: vcs.TrackedFiles,
}
