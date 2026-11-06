package engine

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/agent"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/apiclient"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/depcheck"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/depquiet"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/notify"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/review"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/scratch"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/vcs"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

// ScanReport is the session scan shown on demand (/leoprevent:sca, LEO-819): with the first
// Stop's scan said to no one (showSessionScan), typing the command is how a developer opts in to
// it. It is the same scan, in its current form: every dependency file in the project read whole,
// the developer's 24-hour quiet honoured, and the offer to fix what was already there.
type ScanReport struct {
	// Notice is the scan's notice for the developer, as the first Stop would show it, or "" when
	// nothing high or critical was found; Markdown the same with each advisory linked ("" when
	// the server gave none).
	Notice, Markdown string
	// Agent is what the server put to the agent beyond the offer (only ever in a folder with no
	// repository, where nothing can be marked as already there); Offer is the offer, with its
	// one question. Both "" when there's nothing to ask.
	Agent, Offer string
	// Files is how many dependency files were found; Unavailable is set when the server answered
	// 404: the dependency check is off for the account or the repository, or the server refused
	// the key (noticeFor).
	Files       int
	Unavailable bool
	// Asked is what Agent and Offer put to the agent (askKey), recorded for the session once the
	// agent has been woken with them.
	Asked []string
	// Pending is the offer to leave awaiting the developer's answer (pendOffer), left only once
	// the offer is delivered: settleScanAnswer runs before the Stop's checks, so an earlier answer
	// in the session can't settle an offer that hasn't been asked yet.
	Pending *depquiet.Pending `json:",omitempty"`
	// SavedAt is when SaveForStop kept the report; an old one is never delivered (maxReportAge).
	SavedAt time.Time `json:",omitempty"`
}

// RunScanReport runs the session scan for cwd as the first Stop runs it, through c (the cloud
// reviewer, delivery.Cloud), stamped with meta. sessionID, when the agent passed one, is the
// session the command was typed in: the offer is recorded against it, as the first Stop's is, so
// the developer's answer starts the quiet, and its packages count as asked for the rest of that
// session. Without one the report is the same, and an answer starts no quiet.
func RunScanReport(c depcheck.Checker, meta *wire.TurnMeta, cwd, sessionID string, log *slog.Logger, now time.Time) ScanReport {
	if dependenciesUnavailable(sessionID) {
		// The session's server already answered 404: the scan would send nothing and say
		// nothing, which must not read as a clean project.
		return ScanReport{Unavailable: true}
	}
	w := depcheck.Find(cwd, projectLister, log)
	put := &askedKeys{}
	u := &unavailableSeen{Checker: c}
	sc := stamped{checker: u, meta: meta, trigger: wire.DependencyTriggerScan, scanID: newScanID(), sessionID: sessionID, put: put, askAgain: true}
	if w.Walked {
		sc.baseline = wire.DependencyBaselineNone
	}
	repo := folderIdentity(cwd)
	if !w.Walked {
		repo = vcs.RepoIdentity(cwd)
	}
	if sc.loadQuiet(repo, now, false) {
		w.QuietUntil = sc.quiet.Until
	}
	text, md, agent, offer := depcheck.Scan(w, nil, cwd, nil, sc, log)
	var pending *depquiet.Pending
	if sc.seen != nil {
		_, listed := sc.seen.snapshot()
		pending = pendOffer(repo, offer, listed)
	}
	if sessionID != "" {
		// The scan the first Stop would send has been sent: a session whose first prompt is the
		// command doesn't send every file again when that turn ends. In a walked folder what was
		// checked is recorded too, as the first Stop's scan records it, so gitlessCheck on that
		// turn's Stop doesn't send it all again.
		notify.FirstThisSession(sessionID, sessionScanKey)
		if w.Walked {
			_, keys := unseen(sessionID, cwd, w.Files)
			notify.Record(sessionID, keys...)
		}
	}
	return ScanReport{Notice: text, Markdown: md, Agent: agent, Offer: offer, Files: len(w.Files), Unavailable: u.seen(), Asked: put.list(), Pending: pending}
}

// The report reaches the developer from the Stop hook where it can (LEO-819). A command's output
// goes to the agent partway through its turn, and with the offer's question in the same output the
// agent went straight to AskUserQuestion and never wrote the notice (three runs of three in the
// Claude desktop app, 6 Nov 2026), while the same offer in the Stop's wake was printed first every
// time. So with a session to keep it for, the command saves the report and the agent ends its turn;
// that turn's Stop delivers it (scaReportCheck) exactly as the shown session scan's notice and
// offer are delivered. Without a session (Copilot and Cursor can't pass one) the command prints it
// itself (CommandOutput).

// scaReportDir holds the reports waiting for their session's Stop, one file per session.
const scaReportDir = "sca-report"

// SaveForStop keeps the report for sessionID's next Stop. It reports whether it was kept; the
// command prints the report itself when it wasn't.
func (r ScanReport) SaveForStop(sessionID string, now time.Time) bool {
	if !safeSessionFile(sessionID) {
		return false
	}
	r.SavedAt = now
	data, err := json.Marshal(r)
	if err != nil {
		return false
	}
	dir := scratch.Dir(scaReportDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return false
	}
	sweepScanReports(dir, now)
	// Written whole, then renamed into place, so the Stop never reads half of it.
	tmp, err := os.CreateTemp(dir, sessionID+".*.tmp")
	if err != nil {
		return false
	}
	_, werr := tmp.Write(data)
	cerr := tmp.Close()
	if werr != nil || cerr != nil || os.Rename(tmp.Name(), filepath.Join(dir, sessionID+".json")) != nil {
		_ = os.Remove(tmp.Name())
		return false
	}
	return true
}

// maxReportAge is how long a saved report waits for its Stop. The Stop comes when the agent's
// one-line reply ends the turn, seconds later; one that doesn't (the developer pressed Esc, the
// hook failed open) mustn't deliver an old scan, with an old offer, on some later turn.
const maxReportAge = 15 * time.Minute

// sweepScanReports removes reports, and half-written ones, older than maxReportAge. Best-effort.
func sweepScanReports(dir string, now time.Time) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if info, err := e.Info(); err == nil && now.Sub(info.ModTime()) > maxReportAge {
			_ = os.Remove(filepath.Join(dir, e.Name()))
		}
	}
}

// hasScanReport reports a report waiting for sessionID's Stop.
func hasScanReport(sessionID string) bool {
	if !safeSessionFile(sessionID) {
		return false
	}
	_, err := os.Stat(filepath.Join(scratch.Dir(scaReportDir), sessionID+".json"))
	return err == nil
}

// takeScanReport returns the report waiting for sessionID's Stop and removes it, so it's
// delivered once; never one older than maxReportAge, or one that can't be read.
func takeScanReport(sessionID string, now time.Time) (ScanReport, bool) {
	if !safeSessionFile(sessionID) {
		return ScanReport{}, false
	}
	path := filepath.Join(scratch.Dir(scaReportDir), sessionID+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		return ScanReport{}, false
	}
	_ = os.Remove(path)
	var r ScanReport
	if json.Unmarshal(data, &r) != nil || now.Sub(r.SavedAt) > maxReportAge {
		return ScanReport{}, false
	}
	return r, true
}

// safeSessionFile is a session id that can name a file: no separators, dots or anything else.
func safeSessionFile(id string) bool {
	if id == "" || len(id) > 128 {
		return false
	}
	for _, r := range id {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

// AwaitStopLine is the command's output when the report waits for the Stop: the agent says one
// line and ends its turn, and the report follows from the Stop hook.
const AwaitStopLine = "[For the agent: LeoPrevent's dependency scan has run. LeoPrevent shows its report, and asks any question, when this turn ends. Reply with only this line, then end your turn: \"LeoPrevent's dependency scan has run. Its report follows.\"]"

// scaReportCheck delivers the report /leoprevent:sca saved for this session (SaveForStop) on
// that turn's Stop: its notice, what it puts to the agent and its offer, through runChecks like
// any dependency check, so the notice is printed and the offer asked the way the shown session
// scan's are.
type scaReportCheck struct{}

func (scaReportCheck) name() string                                        { return "dependency scan (/leoprevent:sca)" }
func (scaReportCheck) runsWithoutFiles() bool                              { return true }
func (scaReportCheck) selectFiles([]transcript.Change) []transcript.Change { return nil }

func (scaReportCheck) run(t stopTurn, _ []transcript.Change) stopResult {
	r, ok := takeScanReport(t.ev.SessionID, t.now)
	if !ok {
		return stopResult{}
	}
	text, md := r.noticeFor()
	return stopResult{notice: text, noticeMarkdown: md, agent: r.Agent, offer: r.Offer, asked: r.Asked, pending: r.Pending}
}

// noticeFor is the notice the developer sees, as text and markdown: the scan's, or a line saying
// why there's none, since the developer asked.
func (r ScanReport) noticeFor() (text, markdown string) {
	text, markdown = strings.TrimRight(r.Notice, "\n"), strings.TrimRight(r.Markdown, "\n")
	var line string
	switch {
	case r.Unavailable:
		// The server answers with the same 404 for every reason the check can't run: a key it
		// refuses (unknown, revoked, suspended: api.refusalAsNoCheck), an account without
		// feature_dependency_check, or the repository's Dependency check control off. That keeps
		// the Stop's own checks silent; the command can't tell the reasons apart. All but a bad
		// key are the account admin's to fix, so it points there first, and to Plugin setup,
		// where the developer makes their own key.
		line = "🛡️ LeoPrevent · dependency scan: not available with this license key. The dependency check may be off for your account or this repository, or the key may be invalid or revoked. Ask your LeoPrevent admin, or check your key under Plugin setup in the dashboard."
	case text != "":
		if markdown == "" {
			markdown = text
		}
		return text, markdown
	case r.Files == 0:
		line = "🛡️ LeoPrevent · dependency scan of this project: no dependency files LeoPrevent reads (package-lock.json, npm-shrinkwrap.json, pnpm-lock.yaml, go.mod) were found."
	default:
		unit := "files"
		if r.Files == 1 {
			unit = "file"
		}
		line = fmt.Sprintf("🛡️ LeoPrevent · dependency scan of this project: nothing high or critical in the %d dependency %s checked.", r.Files, unit)
	}
	return line, line
}

// unavailableSeen notes a server with no dependency check, which the scan otherwise reports as
// nothing to say: the command must tell the developer why there's no report.
type unavailableSeen struct {
	depcheck.Checker
	mu   sync.Mutex
	none bool
}

func (u *unavailableSeen) CheckDependencies(req wire.DependenciesRequest) (wire.DependenciesResponse, error) {
	resp, err := u.Checker.CheckDependencies(req)
	u.note(err)
	return resp, err
}

// CheckDependencyBatch passes a batch through when the checker can batch, so the command sends
// what the first Stop sends.
func (u *unavailableSeen) CheckDependencyBatch(b wire.DependenciesBatchRequest) (wire.DependenciesBatchResponse, error) {
	bc, ok := u.Checker.(dependencyBatcher)
	if !ok {
		return wire.DependenciesBatchResponse{}, depcheck.ErrNoBatches
	}
	resp, err := bc.CheckDependencyBatch(b)
	u.note(err)
	return resp, err
}

func (u *unavailableSeen) note(err error) {
	if err == nil {
		return
	}
	var status *apiclient.StatusError
	if errors.As(err, &status) && status.Status == 404 {
		u.mu.Lock()
		u.none = true
		u.mu.Unlock()
	}
}

func (u *unavailableSeen) seen() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.none
}

// CommandOutput is the report as /leoprevent:sca prints it for the agent when there's no session
// to keep it for (SaveForStop): the notice as markdown in the relay's fence, then DependencyPrompt,
// the same instructions and question the Stop's wake would carry for a. The notice comes first and
// is to be written as message text before any tool call (review.DeveloperNoticeMidTurn); with
// nothing to ask, the hook's own relay prompt.
func (r ScanReport) CommandOutput(a agent.Agent) string {
	_, md := r.noticeFor()
	md = review.DeveloperMarkdown(md)
	head := "[For the agent: the user cannot see this output. LeoPrevent's instructions follow.]\n\n"
	prompt := DependencyPrompt(a, []string{r.Agent}, []string{r.Offer})
	if prompt == "" {
		return head + review.DeveloperRelayPrompt(md)
	}
	return head + review.DeveloperNoticeMidTurn(md) + "\n" + prompt + "\n"
}
