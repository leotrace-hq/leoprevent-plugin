package engine

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/agent"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/apiclient"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/depcheck"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/depquiet"
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
	// agent is what the check puts to the agent, "" when nothing: the dependency check's
	// instructions for what the turn brought in (LEO-620). It wakes the agent once, after the
	// code review's own prompt, which stays as it is.
	agent string
	// asked is what to record for the session once the agent has been woken with agent or offer,
	// so the same package version is never put to it again (see askKey).
	asked []string
	// offer is the session scan's offer to fix what was already there (LEO-673): the agent is to
	// ask the developer once, and is told what to do on a yes. It goes after every check's agent
	// text in the same wake, so the agent asks after doing what it must.
	offer string
}

// stopChecks are the checks for this turn: the code review always, and the dependency check
// when the tier has it and the session's server hasn't answered 404 (the server is the switch). On the session's first Stop the dependency check is
// the session scan, which checks every dependency file in the project and covers this turn's
// own files too, so they're never sent twice.
func stopChecks(t stopTurn) []stopCheck {
	checks := []stopCheck{codeReviewCheck{}}
	c, ok := t.r.(depcheck.Checker)
	if !ok {
		t.log.Debug("dependency check: not available on this tier")
		return checks
	}
	if dependenciesUnavailable(t.ev.SessionID) {
		t.log.Debug("dependency check: off for this session, the server has no /dependencies")
		return checks
	}
	if notify.FirstThisSession(t.ev.SessionID, sessionScanKey) {
		return append(checks, sessionScanCheck{dependencyCheck{checker: c}})
	}
	if noRepository(t.ev.Cwd, t.usedGit) {
		return append(checks, gitlessCheck{dependencyCheck{checker: c}})
	}
	return append(checks, dependencyCheck{checker: c})
}

// sessionScanKey marks a session whose dependency files have been scanned (once per session).
const sessionScanKey = "deps_session_scan"

// unavailableKey marks a session whose server answered /dependencies with 404: it has no
// dependency check (the plugin's switch is on, the server's isn't, or the server predates it).
// That won't change during the session, so the check is off for the rest of it rather than
// sending a request that 404s every time a dependency file changes. A timeout, a 429 or a 5xx
// is passing, and only fails that one Stop.
const unavailableKey = "deps-unavailable"

// dependenciesUnavailable reports a session whose server has no /dependencies.
func dependenciesUnavailable(sessionID string) bool {
	return sessionID != "" && len(notify.Recorded(sessionID, unavailableKey)) > 0
}

// A 404 is also never shown to the developer, not even as "couldn't be checked": a developer
// whose server has no dependency check is never told there is one (depcheck.ErrUnavailable).

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
	var notices, markdowns, agents, offers, asked []string
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
		if res.agent != "" {
			agents = append(agents, res.agent)
		}
		if res.offer != "" {
			offers = append(offers, res.offer)
		}
		if res.agent != "" || res.offer != "" {
			asked = append(asked, res.asked...)
		}
	}
	if len(offers) > 0 {
		offer := strings.Join(offers, "\n\n")
		if q, ok := t.a.(offerQuestioner); ok {
			offer += q.OfferQuestion()
		}
		agents = append(agents, offer)
	}
	var depPrompt string
	if len(agents) > 0 {
		depPrompt = strings.Join(agents, "\n\n")
		output = wakeForDependencies(t, output, depPrompt, asked, strings.Join(notices, "\n\n"))
	}
	if len(notices) > 0 {
		// The notice is printed before the dependency instructions are acted on (depPrompt).
		output = deliverForDeveloper(t, output, strings.Join(notices, "\n\n"), strings.Join(markdowns, "\n\n"), depPrompt)
	}
	fmt.Fprint(stdout, string(output))
	return code
}

// offerQuestioner is an adapter that asks for the scan's offer to be put to the developer its own
// way (Claude's AskUserQuestion, where it's switched on). It returns text to add after the offer,
// or "" to leave the offer's plain one-line question as it is.
type offerQuestioner interface {
	OfferQuestion() string
}

// dependencyWaker is an adapter that can wake the agent with the dependency check's instructions,
// after whatever this Stop's hook output already asks of it (LEO-620).
type dependencyWaker interface {
	WakeForDependencies(out []byte, prompt string) ([]byte, error)
}

// wakeForDependencies wakes the agent with what the dependency check puts to it: once per turn,
// since the Stop after a wake never runs the checks, and never twice for a package version in a
// session, since what it was asked is recorded here and sent back as asked. An adapter that can't
// wake for it yet leaves out as it is: the developer's notice still says it all. notice is the
// developer notice shown with the wake, kept so the re-check doesn't show it again unchanged.
func wakeForDependencies(t stopTurn, out []byte, prompt string, asked []string, notice string) []byte {
	w, ok := t.a.(dependencyWaker)
	if !ok {
		t.log.Info("dependency check: this agent isn't woken for it yet, notice only", "agent", t.a.Name())
		return out
	}
	woken, err := w.WakeForDependencies(out, prompt)
	if err != nil {
		t.log.Warn("dependency check: agent NOT woken, notice only", "err", err.Error())
		return out
	}
	notify.Record(t.ev.SessionID, asked...)
	rememberDependencyWake(t.ev.SessionID, notice, t.log)
	t.log.Info("dependency check: agent woken", "packages", len(asked))
	return woken
}

// developerRelayer is an adapter that can show a developer-only notice on every surface it has,
// relaying it through the agent's reply where a systemMessage isn't shown (the Claude adapter).
type developerRelayer interface {
	RelayForDeveloper(out []byte, notice, markdown, before string) ([]byte, string, error)
}

// deliverForDeveloper adds the checks' developer notices to the Stop's output. An adapter that
// can relay them does; for any other the notice joins the systemMessage, as before. When the
// agent is asked to print the notice, the exact text is remembered so the next Stop removes it
// from the agent's reply before /outcome (see takeRelayed). Where it's relayed, the markdown is
// what the agent prints; the systemMessage is always the plain text.
func deliverForDeveloper(t stopTurn, output []byte, notice, markdown, before string) []byte {
	dr, ok := t.a.(developerRelayer)
	if !ok {
		return attachNotice(t.a, output, notice, t.log)
	}
	out, dictated, err := dr.RelayForDeveloper(output, notice, markdown, before)
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

// dependencyCheck is the dependency check (on the cloud tier wherever the server has one; see
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
	put := &askedKeys{}
	c := stamped{checker: d.checker, meta: dependencyMeta(t), trigger: wire.DependencyTriggerTurn, sessionID: t.ev.SessionID, put: put}
	text, md, agent := depcheck.Run(files, t.ev.Cwd, turnStart(t), c, t.log)
	return stopResult{notice: text, noticeMarkdown: md, agent: agent, asked: put.list()}
}

// askKey is the session's record that a package version in a file has been put to the agent
// ("deps-ask:web/package-lock.json:lodash@4.17.15"). askPrefix is a file's part of it.
func askKey(path, pkg string) string { return askPrefix(path) + pkg }
func askPrefix(path string) string   { return "deps-ask:" + path + ":" }

// askedKeys gathers the askKeys of what a check's responses put to the agent, to be recorded only
// once the agent has actually been woken with them.
type askedKeys struct {
	mu   sync.Mutex
	keys []string
}

func (a *askedKeys) add(keys ...string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.keys = append(a.keys, keys...)
}

func (a *askedKeys) list() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.keys...)
}

// stamped puts who and where the check is for on every request: the turn's identity, what ran
// the check, and the scan it belongs to, so the server can record what it found against the
// repository (the activity log), as review events are.
//
// With a session, each request also says which packages in its file the agent has already been
// asked about this session (asked), so the server leaves them out; with put, what the response
// puts to the agent is gathered there for recording once the agent is woken.
type stamped struct {
	checker   depcheck.Checker
	meta      *wire.TurnMeta
	trigger   string
	scanID    string
	baseline  string // wire.DependencyBaselineNone in a folder with no repository
	sessionID string
	put       *askedKeys
	// The session scan's quiet (scanquiet.go): the developer's running answer, sent back file by
	// file; quietExisting from the session started to fix the offer; seen gathers what each
	// answer quietened and still showed.
	quiet         depquiet.Timer
	quietExisting bool
	seen          *scanSeen
}

func (s stamped) CheckDependencies(req wire.DependenciesRequest) (wire.DependenciesResponse, error) {
	if dependenciesUnavailable(s.sessionID) {
		return wire.DependenciesResponse{}, depcheck.ErrUnavailable
	}
	req.Meta, req.Trigger, req.ScanID, req.Baseline = s.meta, s.trigger, s.scanID, s.baseline
	if asked := notify.Recorded(s.sessionID, askPrefix(req.Path)); len(asked) > 0 {
		sort.Strings(asked)
		req.Asked = asked
	}
	if s.trigger == wire.DependencyTriggerScan && req.Path != "" {
		req.Quiet, req.QuietExisting = s.quiet.For(req.Path), s.quietExisting
	}
	resp, err := s.checker.CheckDependencies(req)
	if err == nil && s.seen != nil && req.Path != "" && !depcheck.TestArea(req.Path) {
		s.seen.add(req.Path, resp)
	}
	var status *apiclient.StatusError
	if errors.As(err, &status) && status.Status == 404 {
		if s.sessionID != "" {
			notify.Record(s.sessionID, unavailableKey)
		}
		return resp, fmt.Errorf("%w: %w", depcheck.ErrUnavailable, err)
	}
	if depcheck.TestArea(req.Path) {
		return resp, err // nothing in a test area reaches the agent, so nothing is asked
	}
	if err == nil && s.put != nil && resp.Messages.Agent != nil {
		for _, p := range resp.Messages.AgentPackages {
			s.put.add(askKey(req.Path, p))
		}
	}
	if err == nil && s.put != nil && resp.Messages.AgentOffer != nil {
		// Offered is asked: a "not now" isn't repeated this session (LEO-673).
		for _, p := range resp.Messages.AgentOfferPackages {
			s.put.add(askKey(req.Path, p))
		}
	}
	return resp, err
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
	put := &askedKeys{}
	c := stamped{checker: s.checker, meta: dependencyMeta(t), trigger: wire.DependencyTriggerScan, scanID: newScanID(), sessionID: t.ev.SessionID, put: put}
	if w.Walked {
		// No repository: nothing can be marked as changed, so the server is told (LEO-659), and
		// what was checked is recorded for the later Stops' gitlessCheck.
		c.baseline = wire.DependencyBaselineNone
	}
	// The developer's quiet (scanquiet.go), in a repository only: a folder without one has no offer.
	repo := ""
	if !w.Walked {
		repo = vcs.RepoIdentity(t.ev.Cwd)
	}
	fixSession := false
	if r, ok := t.a.(scanAnswerReader); ok && repo != "" {
		c.quiet, c.seen = depquiet.Load(repo, t.now), &scanSeen{}
		// The session started to fix the offer: what was already there is its job, not a question.
		fixSession = r.ScanFixSession(t.ev.TranscriptPath)
		c.quietExisting = fixSession
		w.QuietUntil = c.quiet.Until
		if fixSession && !c.quiet.Active(t.now) {
			w.QuietUntil = t.now.Add(depquiet.Window) // the timer this session's answer starts
		}
	}
	text, md, agent, offer := depcheck.Scan(w, files, t.ev.Cwd, turnStart(t), c, t.log)
	if w.Walked {
		_, keys := unseen(t.ev.SessionID, t.ev.Cwd, w.Files)
		notify.Record(t.ev.SessionID, keys...)
	}
	if c.seen != nil {
		quieted, listed := c.seen.snapshot()
		switch {
		case fixSession:
			depquiet.Answer(repo, quieted, t.now)
			t.log.Info("dependency scan: the fix session, what was already there is quiet", "packages", len(quieted))
		case offer != "":
			depquiet.SetPending(t.ev.SessionID, depquiet.Pending{Repo: repo, Entries: listed})
		}
	}
	return stopResult{notice: text, noticeMarkdown: md, agent: agent, offer: offer, asked: put.list()}
}

// recheckedClean is the second Stop's line when nothing the turn changed is still high or
// critical in current data. The re-check sends only the turn's changed dependencies, so the line
// leads with that scope and says the rest weren't checked again: after the scan's offer, "nothing
// is left" read as the whole project being clean while the packages the offer left out (a fix on
// a new major) were still open. ⚠️ PLACEHOLDER WORDING, written here like the scan's summary line;
// it becomes a server-overridable template with the rest of the Stop's wording (LEO-620).
const recheckedClean = "🛡️ LeoPrevent · dependency check: the dependencies this turn changed have nothing high or critical left in current advisory data. Dependencies it didn't change weren't checked again."

// recheckResult is what the re-check after a wake has to say: notice for the developer, and the
// follow-up (LEO-672), the pins for what the agent's fix left behind or brought in, with the
// packages it covers to record as asked once the agent is woken with it.
type recheckResult struct {
	notice, markdown string
	followUp         string
	asked            []string
}

// recheckDependencies is the dependency check on the Stop after it woke the agent: the turn's
// dependency files checked again, to say what's still open or that nothing is, and, once, what
// the fix left to pin (see deliverAfterWake for when that wakes the agent). It records nothing,
// here or on the server. Empty when it can't run.
func recheckDependencies(a agent.Agent, r Reviewer, ev agent.Event, log *slog.Logger, now time.Time) recheckResult {
	c, ok := r.(depcheck.Checker)
	if !ok || dependenciesUnavailable(ev.SessionID) {
		return recheckResult{}
	}
	changes, usedGit, baselineSkip, baseInfo, err := changedFiles(a, ev, log)
	if err != nil {
		log.Info("dependency re-check skipped: changed files", "err", err.Error())
		return recheckResult{}
	}
	files := dependencyCheck{}.selectFiles(changes)
	t := stopTurn{a: a, r: r, ev: ev, log: log, now: now, changes: changes, usedGit: usedGit, baselineSkip: baselineSkip, baseInfo: baseInfo}
	if noRepository(ev.Cwd, usedGit) {
		res, ran := recheckWithoutRepository(t, c, files)
		if ran && res.notice == "" && res.followUp == "" && !dependenciesUnavailable(ev.SessionID) {
			res.notice, res.markdown = recheckedClean, recheckedClean
		}
		return res
	}
	if len(files) == 0 {
		return recheckResult{}
	}
	// A re-check: the server answers it as a turn's check, but doesn't record it (the first Stop's
	// record holds what the turn brought in). What it puts to the agent is only the follow-up.
	put := &askedKeys{}
	sc := stamped{checker: c, meta: dependencyMeta(t), trigger: wire.DependencyTriggerRecheck, sessionID: ev.SessionID, put: put}
	text, md, agent := depcheck.Run(files, ev.Cwd, turnStart(t), sc, log)
	if text == "" && agent == "" && !dependenciesUnavailable(ev.SessionID) {
		text, md = recheckedClean, recheckedClean // never beside a follow-up, which says something is left
	}
	return recheckResult{notice: text, markdown: md, followUp: agent, asked: put.list()}
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
