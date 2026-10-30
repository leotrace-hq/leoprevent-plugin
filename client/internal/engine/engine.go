// Package engine is leoprevent's agent-agnostic Stop-hook run loop:
// per-turn guard → changed files → inert gate → review → deliver re-wake. The
// agent-specific I/O (stdin shape, changed-file discovery, re-wake format) is
// supplied by an agent.Agent; HOW the review prompt is produced (the cloud-tier
// server /review) is supplied by a Reviewer.
//
// Contract: FAIL OPEN. Any error → log to stderr, exit 0, never block the stop.
// The hook must never trap the developer. The one thing it may print on the
// fail-open path is a NON-BLOCKING notice (systemMessage, no decision) when a
// review couldn't run — so an outage isn't silently mistaken for "all clear" —
// throttled to once per session per reason (see notifyReviewSkipped).
package engine

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/leotrace-hq/leoprevent-plugin/buildinfo"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/agent"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/config"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/enroll"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/gate"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/notify"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/outcome"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/review"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/vcs"
	"github.com/leotrace-hq/leoprevent-plugin/limits"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

type Result struct {
	Prompt   string
	Pending  *outcome.Pending
	Findings []wire.Finding
	// Summary is the server's one-line account of the review (wire.ReviewResponse.Summary),
	// empty when the server sent none or the turn needed several /review batches.
	Summary string
	// ContextHint is the server's repository-context reminder (wire.ReviewResponse.ContextHint).
	// The engine appends it to a delivered block at most once per session.
	ContextHint string
}

// Reviewer turns the changed code this turn into a Result. The implementation owns
// the tier (cloud: call /review). meta is the coding agent's own turn activity
// (analytics), forwarded to the server.
type Reviewer interface {
	// Review judges this turn's changes. cwd is the agent's working directory —
	// the cloud tier uses it to resolve cross-file imported context on-device. meta is the coding agent's own turn
	// activity (analytics), forwarded by cloud.
	// proposedID is the review id the caller has already recorded as in-flight; cloud
	// offers it to the server (first batch only: continuations chain to it).
	// Empty means "mint one", which is every caller that does not track it.
	Review(cwd string, changes []transcript.Change, meta wire.TurnMeta, proposedID string) (Result, error)
	// ShipOutcome reports the agent's fix after a prior block and SYNCHRONOUSLY
	// re-verifies it (cloud: POST /outcome, server re-judges, bounded + fail-open).
	// It returns (1) the INTRODUCED findings the re-judge still flags —
	// so the engine can warn the dev in-turn that the fix is still vulnerable — and
	// (2) the PRE-EXISTING findings that still fire, which the engine carries forward in
	// the cross-turn ledger so a later turn can credit them once fixed. meta is the
	// FULL-TURN agent metadata, captured at this FINAL Stop so it spans the re-wake fix.
	// Contract: err == nil implies the server re-judge actually RAN — an accepted-but-
	// unscored response (capacity skip / re-judge failure) surfaces as an error wrapping
	// outcome.ErrUnscored, so empty still-firing sets with a nil error always mean a real
	// clean verdict, never "not judged".
	ShipOutcome(p outcome.Pending, after []transcript.Change, agentResponse string, meta wire.TurnMeta) (introStillFiring, preStillFiring []wire.Finding, err error)
	// ShipResolution re-judges findings a PRIOR block left unresolved (carried in the
	// ledger — pre-existing surfaced AND introduced declined/failed) against this turn's
	// code, for the cross-turn "the dev fixed it a few turns later" case. It returns ALL
	// findings STILL firing (both classes; empty ⇒ everything resolved → drop the ledger
	// entry); the cleared ones are credited server-side in a `kind:"resolution"` event
	// (pre-existing → PreexistingFixed, introduced → IntroducedResolved). Cloud: POST
	// /outcome with Resolution=true. Same scored contract as ShipOutcome:
	// an unscored response is an error (outcome.ErrUnscored), so an empty stillFiring
	// with a nil error genuinely means everything resolved.
	ShipResolution(p outcome.Pending, after []transcript.Change, meta wire.TurnMeta) (stillFiring []wire.Finding, err error)
	// ShipReasons asks the server to record WHY the carried findings are still open, from
	// this turn's own words, re-judging nothing. It exists because the developer's decision
	// usually lands on a LATER turn than the block — see wire.OutcomeRequest.ReasonsOnly.
	// Cloud POSTs /outcome with Resolution+ReasonsOnly. Best-effort: the
	// ledger is never changed by it, so a failure costs a label and nothing else.
	ShipReasons(p outcome.Pending, prompt, reply string, meta wire.TurnMeta) error
	// ShipTelemetry reports the coding agent's turn metadata for a turn that did NOT
	// trigger a review (no changed files, or every change inert), so per-prompt
	// cost/latency analytics covers EVERY turn — not only reviewed ones. Cloud POSTs
	// /telemetry (fail-open, off the dev's path). Never blocks the
	// stop. reason is wire.TelemetryNoChange|TelemetryInert; changedFiles is the
	// inert-dropped count (0 for no_change).
	ShipTelemetry(meta wire.TurnMeta, reason string, changedFiles int) error
}

// nowFunc returns the wall-clock used as the turn's end timestamp (see turnMeta).
// A package var so tests can pin it; production is time.Now.
var nowFunc = time.Now

// Run executes the Stop-hook review pipeline for the given agent + reviewer
// against an already-parsed event. Always returns 0 (fail-open). UserPromptSubmit
// is routed to baseline capture by the caller, not here.
func Run(a agent.Agent, r Reviewer, ev agent.Event, stdout, stderr io.Writer) int {
	log := slog.With("agent", a.Name())
	failOpen := func(err error) int {
		log.Error("failing open", "err", err.Error())
		fmt.Fprintf(stderr, "leoprevent[%s]: %v (failing open)\n", a.Name(), err)
		return 0
	}

	// now ≈ the turn's end: a Stop hook fires when the agent stops, so this hook-entry
	// wall-clock is the turn-end used for the agent's duration (see turnMeta — it beats
	// the transcript's last-message timestamp, which the hook reads mid-write). Captured
	// once so the outcome (final-Stop) and the review capture share one clock.
	now := nowFunc()

	// Per-turn guard: the Stop after a re-wake has StopHookActive=true → this turn
	// was already reviewed → allow the stop. Before doing so, if THIS turn blocked
	// (a pending outcome exists), the agent has now had its chance to fix — capture
	// what it did and ship it for async server-side scoring. This is the only extra
	// work here and it's deliberately cheap + fail-open: a local git diff plus a
	// fire-and-forget POST the reviewer makes with a short timeout, so the developer
	// never waits on the re-review.
	recovered := false
	if !ev.StopHookActive {
		recovered = shipRecovery(r, ev.SessionID, log)
	}
	// A marker left by an earlier Stop means a /review was posted and its reply never
	// consumed, the turn died while waiting. The server judged that code and kept any
	// findings, and nothing will ever score them, so they are stranded as Unconfirmed.
	// Say so explicitly: an operator reading this log can now tell "we asked and never
	// heard back" from "we never asked", which the empty scratch dir alone could not.
	// Reporting it to the SERVER needs a wire change and is deliberately not done here.
	if m, ok := outcome.TakeInFlight(ev.SessionID); ok {
		log.Warn("previous turn's review was never delivered: its findings cannot be scored",
			"review_id", m.ReviewID, "posted_at", m.At.Format(time.RFC3339),
			"changed_files", m.ChangedFiles, "repo", m.Repo)
	}
	// An answer to the session scan's offer, given since the Stop that made it, quietens what the
	// scan listed for this developer (scanquiet.go).
	settleScanAnswer(a, ev, now, log)
	if ev.StopHookActive {
		// Whatever the last Stop asked the agent to relay is consumed now, used or not.
		relayed := takeRelayed(ev.SessionID)
		// When the last Stop woke the agent for the dependency check, check the turn's dependency
		// files again and say what's still open. Never a wake, never part of /outcome (LEO-620).
		var dep recheckResult
		shown := wakeNotice(ev.SessionID)
		if takeDependencyWake(ev.SessionID) {
			// The Stop after a follow-up (LEO-672) only reports: one follow-up per dependency wake.
			afterFollowUp := takeDependencyWake(ev.SessionID + followUpSuffix)
			dep = recheckDependencies(a, r, ev, log, now)
			if afterFollowUp {
				dep.followUp, dep.asked = "", nil
			}
			dep = withoutRepeat(dep, shown, log)
		}
		if p, ok := outcome.Take(ev.SessionID); ok {
			raw, usedGit, baselineSkip, baseInfo, _ := changedFiles(a, ev, log)
			after := withoutDeletedFiles(raw)
			after = withFlaggedFiles(after, p, log)
			// Re-parse turn meta NOW (final Stop): ParseTurnMeta scopes from the last
			// genuine user message — a "Stop hook feedback:" re-wake is NOT one — so this
			// capture spans the whole turn incl. the fix, unlike the first-Stop /review meta.
			fullMeta := turnMeta(a, ev, log, now)
			// The full-turn wall-clock (prompt→final stop) includes the time the FIRST
			// Stop hook sat BLOCKED on LeoPrevent's /review — during which the agent was
			// idle, waiting on us, not working. Subtract it so the recorded latency is the
			// agent's OWN work (incl. the re-wake fix we forced) but NOT the wait on us —
			// the same baseline a clean turn uses. ReviewBlockMs was measured at the first
			// Stop and stashed on the Pending. Clamp at 0 (defensive).
			if p.ReviewBlockMs > 0 {
				rawDur := fullMeta.DurationMs
				if fullMeta.DurationMs -= p.ReviewBlockMs; fullMeta.DurationMs < 0 {
					fullMeta.DurationMs = 0
				}
				log.Info("blocked-turn latency: excluded the wait on LeoPrevent",
					"raw_ms", rawDur, "review_wait_ms", p.ReviewBlockMs, "agent_ms", fullMeta.DurationMs)
			}
			fresh := make(chan []wire.Finding, 1)
			go func() {
				if len(baseInfo.HeadAnchored) > 0 {
					fresh <- nil
					return
				}
				fixMeta := withDiscovery(fullMeta, ev, raw, usedGit, baselineSkip, baseInfo, log)
				fresh <- reviewFixTurn(r, ev.Cwd, p, raw, fixMeta, log)
			}()
			// The reply loses any notice the agent was only asked to relay for the developer.
			reply := review.WithoutRelayed(agentReply(a, ev, log), relayed)
			stillFiring, preStillFiring, err := r.ShipOutcome(p, after, reply, fullMeta)
			var notices []string
			switch {
			case errors.Is(err, outcome.ErrTransient):
				// Lost on OUR side (unreachable, 5xx, at capacity), not the developer's:
				// keep the fix as it stands now so a later Stop delivers it (LEO-496).
				parkUndelivered(ev.SessionID, p, after, reply, fullMeta, err, log)
			case errors.Is(err, outcome.ErrUnscored):
				// The server ACCEPTED the outcome but produced NO verdict (capacity
				// skip / re-judge failure). There is nothing to warn the dev about —
				// a "still vulnerable" notice needs a verdict — and the empty
				// still-firing sets mean "not judged", not "all clear", so nothing is
				// seeded either (the err != nil guard below skips seedLedger).
				log.Info("outcome accepted but not scored — no verdict, no notice, ledger untouched", "review_id", p.ReviewID)
			case err != nil:
				log.Info("ship outcome failed (best-effort, ignoring)", "review_id", p.ReviewID, "err", err.Error())
			case len(stillFiring) > 0:
				// The re-verify says the agent's introduced fix is STILL vulnerable. Warn
				// the dev in-turn (non-blocking) — before they close the agent thinking
				// it's done. Fail-open: the stop still proceeds.
				log.Info("fix still vulnerable after re-wake", "review_id", p.ReviewID, "still_firing", len(stillFiring))
				notices = append(notices, review.FixStillVulnerableNotice(stillFiring))
			default:
				log.Info("shipped fix outcome — re-verify clean", "review_id", p.ReviewID)
			}
			// Carry the still-firing findings forward — BOTH the surfaced-but-unfixed
			// pre-existing ones AND the introduced ones the agent declined/failed to fix
			// in-turn. If the dev fixes any of them a later turn, that turn re-judges +
			// credits them (see resolveLedger): a pre-existing fix lands in PreexistingFixed,
			// an introduced fix rescues this block out of the rejected/failed verdict. Seed
			// only when the outcome actually SCORED: err == nil implies the server re-judge
			// ran and returned real verdicts (an accepted-but-unscored response — capacity
			// skip, re-judge failure — surfaces as outcome.ErrUnscored via apiclient), so
			// empty sets here can only mean "genuinely nothing open", never "nothing was
			// judged". On any error the open set is unknown → leave any prior ledger entry
			// untouched. Best-effort.
			if err == nil {
				seedLedger(ev.SessionID, p, stillFiring, preStillFiring, log)
			}
			if newFindings := <-fresh; len(newFindings) > 0 {
				notices = append(notices, review.FixTurnFindingsNotice(newFindings))
			}
			// The fix check above is complete (sent, recorded, its notices built) before any
			// dependency follow-up is added to this Stop's output.
			deliverAfterWake(a, ev, notices, dep, true, log, stdout)
		} else if dep.notice != "" || dep.followUp != "" {
			// A wake for the dependency check alone: no review is pending, so no /outcome.
			deliverAfterWake(a, ev, nil, dep, false, log, stdout)
		}
		log.Debug("stop_hook_active guard: already reviewed this turn, allowing stop")
		return 0
	}

	changes, usedGit, baselineSkip, baseInfo, err := changedFiles(a, ev, log)
	if err != nil {
		return failOpen(fmt.Errorf("changed files: %w", err))
	}
	// The checks LeoPrevent runs at the end of a turn (LEO-620, decision D59): each picks its own
	// changed files, they run at the same time, and their results are combined into the one
	// thing this Stop prints. See router.go.
	t := stopTurn{a: a, r: r, ev: ev, log: log, now: now, recovered: recovered, failOpen: failOpen,
		changes: changes, usedGit: usedGit, baselineSkip: baselineSkip, baseInfo: baseInfo}
	return runChecks(t, stopChecks(t), stdout)
}

func withDiscovery(
	meta wire.TurnMeta,
	ev agent.Event,
	changes []transcript.Change,
	usedGit bool,
	baselineSkip vcs.SkipReason,
	baseInfo vcs.BaselineInfo,
	log *slog.Logger,
) wire.TurnMeta {
	// Record HOW this turn's changes were discovered. A fallback turn is a materially
	// weaker review (no full-file context, no real line numbers, no Bash-write
	// detection) that is otherwise indistinguishable server-side, so without this a
	// developer silently stuck on it looks exactly like one who is fine.
	meta.GitBaseline, meta.BaselineSkip = usedGit, string(baselineSkip)
	// turnMeta resolves Repo from cwd, which names nothing when cwd is a folder
	// HOLDING repositories rather than being one. Name the repository that actually
	// changed instead — even in a workspace the ordinary turn touches one project — so
	// these turns keep the per-app analytics dimension they used to lose entirely.
	// Silent when several changed: see soleRepoOrigin.
	if meta.Repo == "" {
		meta.Repo = soleRepoOrigin(ev.Cwd, changes)
	}
	// Same correction for the identity: turnMeta read it from cwd, which holds no git
	// config of its own when cwd is a folder HOLDING repositories. Retry against the
	// roots that actually changed before settling for what git could synthesize.
	if meta.DeveloperSource != wire.DevSourceConfig {
		meta.Developer, meta.DeveloperSource = vcs.DeveloperFrom(ev.Cwd, changedRepoRoots(ev.Cwd, changes)...)
	}
	// ⚠️ SAY SO WHEN THERE IS NO CONFIGURED IDENTITY. Every turn from such a machine is
	// attributed by its seat alone, and an address git assembled from the hostname is not
	// a real one — a fact worth one line on the developer's own machine, since the
	// alternative is what already happened once: two weeks of turns whose attribution
	// nobody could explain from either side.
	if meta.DeveloperSource != wire.DevSourceConfig && meta.DeveloperSource != wire.DevSourceRepo {
		log.Info("no configured git identity for this turn",
			"developer_source", meta.DeveloperSource,
			"hint", "set git user.name and user.email to attribute turns by git identity as well as by seat")
	}
	// Where the tree started, and how many files were excluded as already-published
	// (a mid-turn checkout/pull/merge imports somebody else's merged commits). The
	// second is the one worth watching: it is the only step that removes code from
	// review, so an over-subtraction would otherwise just look like a quiet turn.
	meta.BaselineHead, meta.ImportedDropped = baseInfo.Head, baseInfo.ImportedDropped
	// A HEAD-anchored repo is weaker evidence than a baselined one, so the fact travels
	// with the turn rather than staying in the client log: the server records it on the
	// review event and the internal console flags the row (see wire.TurnMeta).
	meta.HeadAnchoredRepos = baseInfo.HeadAnchored
	return meta
}

// licenseKey is the licence this turn is reviewed under, for once-per-licence state. A package
// var so tests can name a licence; empty (no config, local dev) is one anonymous licence.
var licenseKey = func() string {
	if cfg, err := config.Load(); err == nil {
		return cfg.LicenseKey
	}
	return ""
}

// notifyReviewSkipped surfaces a NON-BLOCKING developer notice when the review
// could not run (server unreachable, license invalid, server fault), so the
// developer learns this turn was unprotected instead of it failing silently. It is
// itself fail-open — any problem just means no notice — and writes a systemMessage
// with NO block decision, so the stop still proceeds. Two guards keep it quiet:
// only a classified review.SkipError notifies (an unclassified error stays silent,
// the conservative default), and notify.FirstThisSession throttles it to once per
// session per reason so a sustained outage doesn't spam every Stop. This is the
// PLUGIN client log (client.log), not the server log.
func notifyReviewSkipped(a agent.Agent, ev agent.Event, err error, log *slog.Logger, stdout io.Writer) {
	var se *review.SkipError
	if !errors.As(err, &se) {
		return
	}
	log.Warn("review skipped", "reason", se.Reason.String(), "err", se.Error())
	// ⚠️ RECORD A REJECTED KEY BEFORE THE THROTTLE, not after. The notice is deliberately
	// shown once per session, but the FACT that the server refused this credential has to be
	// recorded on every occurrence: it is what lets the next turn's enrolment treat the key as
	// invalid and re-mint, which is the only way a machine holding an unrecognised key ever
	// recovers. Suppressing the record along with the notice would leave it stuck forever.
	//
	// Unauthorized ONLY. A timeout, an unreachable server or a 5xx say nothing about whether
	// the key is valid, and discarding a good credential because the server blipped would
	// rotate the developer's other machines out over a transient fault.
	if se.Reason == review.SkipUnauthorized && !se.KeepKey {
		enroll.MarkStaleKey()
	}
	notice := review.SkipNotice(se.Reason)
	noticeID := se.Reason.String()
	if se.Notice != nil {
		notice = se.Notice.Message
		noticeID = "server." + se.Notice.ID
		if se.Notice.ActionURL != "" {
			notice += " " + se.Notice.ActionURL
		}
	}
	if !notify.FirstThisSession(ev.SessionID, noticeID) {
		log.Debug("skip notice already shown this session, suppressing", "reason", se.Reason.String())
		return
	}
	out, derr := a.DeliverNotice(notice)
	if derr != nil {
		log.Debug("deliver skip notice failed (continuing)", "err", derr.Error())
		return
	}
	fmt.Fprint(stdout, string(out))
}

// deliverAfterWake prints the Stop after a wake's notices: the review's, as deliverNotices does, and
// the dependency re-check's, which goes the way a dependency notice always does, so it's relayed
// where a systemMessage isn't shown (the Claude desktop app). The relay's own Stop has nothing
// left to say, so it ends there.
//
// The re-check's follow-up (LEO-672) wakes the agent once more, after the review's notices, to pin
// what its dependency fix left behind or brought in. It's called only after the code review's fix
// check on this Stop has finished (reviewed says one ran), so nothing about it changes: the
// follow-up's reply is never sent to /outcome, and the Stop after it only reports. On Cursor,
// whose hook stops after two follow-ups, there's none after a review's fix check, so the review's
// follow-up and this Stop keep their places.
func deliverAfterWake(a agent.Agent, ev agent.Event, notices []string, dep recheckResult, reviewed bool, log *slog.Logger, stdout io.Writer) {
	followUp := dep.followUp
	if followUp != "" && reviewed && a.Name() == "cursor" {
		log.Info("dependency follow-up skipped: Cursor's follow-ups are spent on the review's fix", "packages", len(dep.asked))
		followUp = ""
	}
	if dep.notice == "" && followUp == "" {
		deliverNotices(a, notices, log, stdout)
		return
	}
	var out []byte
	if len(notices) > 0 {
		o, err := a.DeliverNotice(strings.Join(notices, "\n\n"))
		if err != nil {
			log.Debug("deliver notices failed (continuing)", "err", err.Error())
		} else {
			out = o
		}
	}
	t := stopTurn{a: a, ev: ev, log: log}
	if followUp != "" {
		woken := wakeForDependencies(t, out, followUp, dep.asked, dep.notice)
		if string(woken) != string(out) {
			rememberDependencyWake(ev.SessionID+followUpSuffix, "", log)
		}
		out = woken
	}
	if dep.notice != "" {
		md := dep.markdown
		if md == "" {
			md = dep.notice
		}
		out = deliverForDeveloper(t, out, dep.notice, md, followUp)
	}
	fmt.Fprint(stdout, string(out))
}

// withoutRepeat drops the re-check's notice when the wake already showed it word for word: the
// agent left those packages as they were (it may rightly have, when the developer asked for that
// version), so it says nothing new, and showing it again only invites the agent to carry it on to
// later replies (LEO-695). A follow-up keeps its notice, since it says something is left to pin.
func withoutRepeat(dep recheckResult, shown string, log *slog.Logger) recheckResult {
	if dep.followUp == "" && dep.notice != "" && dep.notice == shown {
		log.Info("dependency re-check: unchanged since the wake, not shown again")
		dep.notice, dep.markdown = "", ""
	}
	return dep
}

// followUpSuffix marks a dependency wake that was the re-check's follow-up (LEO-672), so the Stop
// after it reports only. It sits beside the session's wake mark and is claimed the same way.
const followUpSuffix = ".followup"

func deliverNotices(
	a agent.Agent,
	notices []string,
	log *slog.Logger,
	stdout io.Writer,
) {
	if len(notices) == 0 {
		return
	}
	out, derr := a.DeliverNotice(strings.Join(notices, "\n\n"))
	if derr != nil {
		log.Debug("deliver fix-turn notice failed (continuing)", "err", derr.Error())
		return
	}
	fmt.Fprint(stdout, string(out))
}

// seedLedger records (or refreshes) the cross-turn entry for a just-scored block: the
// findings the re-judge still flags after the in-turn re-wake — the introduced ones the
// agent declined/failed to fix AND the surfaced pre-existing ones — are the ones not yet
// resolved, so a later turn can credit them once fixed. Each carries its own Preexisting
// flag (set by the server), which the resolution re-judge reads back to credit it to the
// right bucket. An empty set means nothing is open for this review_id → drop any prior
// entry. Best-effort (a scratch failure just means the cross-turn credit is missed, never
// a broken hook).
func seedLedger(sessionID string, p outcome.Pending, introStillFiring, preStillFiring []wire.Finding, log *slog.Logger) {
	entries := outcome.LoadLedger(sessionID)
	kept := entries[:0]
	for _, e := range entries {
		if e.ReviewID != p.ReviewID { // replace this review's entry, keep the rest
			kept = append(kept, e)
		}
	}
	open := make([]wire.Finding, 0, len(introStillFiring)+len(preStillFiring))
	open = append(open, introStillFiring...)
	open = append(open, preStillFiring...)
	if len(open) > 0 {
		kept = append(kept, outcome.Pending{
			ReviewID:   p.ReviewID,
			Repo:       p.Repo,
			Developer:  p.Developer,
			AgentModel: p.AgentModel,
			Findings:   open,
			Before:     p.Before,
		})
	}
	if err := outcome.SaveLedger(sessionID, kept); err != nil {
		log.Debug("seed cross-turn ledger failed (continuing)", "err", err.Error())
	}
}

// resolveBudget caps the wall-clock of ONE WHOLE resolution pass. Each ShipResolution
// call independently waits up to OutcomeVerifyDeadline, so a ledger with several
// touched entries used to spend up to N×deadline SEQUENTIALLY — on the Stop hook's
// critical path, BEFORE this turn's own /review, which alone needs its 345s
// ClientReviewDeadline inside the agent's fixed Stop-hook timeout. One deadline for
// the whole pass keeps resolution + review inside that budget; entries not reached
// simply stay in the ledger for a later turn (that's the ledger's design anyway).
// A package var so tests can shrink it; production is the config constant.
var resolveBudget = limits.OutcomeVerifyDeadline

// resolveLedger re-judges any carried-over findings whose file the agent touched THIS
// turn — both pre-existing surfaced earlier AND introduced findings a prior block left
// still-firing — crediting the ones now fixed (server records a kind:"resolution" event:
// pre-existing → PreexistingFixed, introduced → IntroducedResolved) and shrinking the
// ledger to what still fires. It RETURNS the origin review_ids that had ≥1 finding
// resolved this turn — so the caller can stamp them on this turn's /review (marking it a
// re-review). Off the critical path and fail-open: any error — including an accepted-
// but-UNSCORED response (outcome.ErrUnscored: the server skipped or failed the
// re-judge, so there is no verdict) — credits nothing, stamps nothing, and leaves the
// entry intact to retry on a later turn. The whole pass is bounded by resolveBudget
// (see above); entries past the budget are deferred, not dropped.
func resolveLedger(r Reviewer, sessionID string, changes []transcript.Change, meta wire.TurnMeta, log *slog.Logger) []string {
	entries := outcome.LoadLedger(sessionID)
	if len(entries) == 0 {
		return nil
	}
	deadline := time.Now().Add(resolveBudget)
	var resolvedIDs []string
	byPath := make(map[string]transcript.Change, len(changes))
	for _, c := range changes {
		byPath[c.FilePath] = c
	}
	var kept []outcome.Pending
	for _, e := range entries {
		// Only re-judge findings whose file changed this turn — those are the ones we
		// have new code for. A rule judged without its file present would look "fixed"
		// (no code to fire against), so findings on untouched files stay open verbatim.
		var touched, untouched []wire.Finding
		var afterFiles []transcript.Change
		seenFile := map[string]bool{}
		for _, f := range e.Findings {
			path := fileFromLocation(f.Location)
			if c, ok := byPath[path]; ok {
				touched = append(touched, f)
				if !seenFile[path] {
					seenFile[path] = true
					if c.Deleted {
						continue // see withoutDeletedFiles: a deletion never resolves a finding
					}
					afterFiles = append(afterFiles, c)
				}
			} else {
				untouched = append(untouched, f)
			}
		}
		if len(touched) == 0 {
			kept = append(kept, e) // nothing changed for this entry → carry it as-is
			continue
		}
		if !time.Now().Before(deadline) {
			// The pass's wall-clock budget is spent — each ShipResolution is another
			// bounded wait on the dev's path, so defer the rest to a later turn
			// (kept in the ledger, exactly like an untouched entry).
			log.Info("cross-turn resolution budget spent — entry deferred to a later turn", "review_id", e.ReviewID, "open", len(e.Findings))
			kept = append(kept, e)
			continue
		}
		sub := e
		sub.Findings = touched
		stillFiring, err := r.ShipResolution(sub, afterFiles, meta)
		if err != nil {
			// No verdict — a transport failure OR an accepted-but-unscored response
			// (outcome.ErrUnscored: capacity skip / re-judge failure). Either way
			// nothing was judged, so credit nothing and retain the entry VERBATIM;
			// treating the unscored empty lists as "all resolved" is what used to
			// silently delete the whole entry with zero server-side credit.
			log.Debug("cross-turn resolution unscored or failed (best-effort, entry retained)", "review_id", e.ReviewID, "err", err.Error())
			kept = append(kept, e) // retry on a later turn
			continue
		}
		open := append(untouched, stillFiring...)
		if resolved := len(touched) - len(stillFiring); resolved > 0 {
			log.Info("cross-turn finding resolved", "review_id", e.ReviewID, "resolved", resolved, "still_open", len(open))
			resolvedIDs = append(resolvedIDs, e.ReviewID)
		}
		e.Findings = open
		if len(open) > 0 {
			kept = append(kept, e)
		}
	}
	if err := outcome.SaveLedger(sessionID, kept); err != nil {
		log.Debug("update cross-turn ledger failed (continuing)", "err", err.Error())
	}

	// ⚠️ THE DECISION USUALLY LANDS ON A TURN THAT CHANGED NO FLAGGED FILE, so everything
	// above misses it. `/outcome` fires at the SECOND Stop of the turn that blocked, which
	// means its reply predates the developer answering: "generate some code" blocks, the
	// agent explains, and the ticket is raised on the NEXT turn in response to "create an
	// issue". That turn edits nothing the ledger names, so the loop above carries every
	// entry untouched and the ticket is never recorded — on the exact shape LEO-138 exists
	// for.
	//
	// So when this turn's own words suggest a follow-up was arranged, ask the server to
	// CLASSIFY the still-open findings and re-judge nothing. Gated because this runs on
	// every ordinary turn while the ledger holds anything; best-effort because it changes
	// no state — a failure costs a label and the entry stays exactly as it is.
	if len(kept) > 0 && review.MentionsFollowUp(meta.Prompt, meta.AgentNote) {
		for _, e := range kept {
			if err := r.ShipReasons(e, meta.Prompt, meta.AgentNote, meta); err != nil {
				log.Debug("reasons-only resolution failed (best-effort, ignoring)", "review_id", e.ReviewID, "err", err.Error())
				continue
			}
			log.Info("classified why carried findings are still open", "review_id", e.ReviewID, "open", len(e.Findings))
		}
	}
	return resolvedIDs
}

// fileFromLocation strips the trailing :line[:col] from a finding location
// ("main.py:44" → "main.py"), so it can be matched against a changed file's path.
// No colon → the whole string (already a bare path).
func fileFromLocation(loc string) string {
	if i := strings.IndexByte(loc, ':'); i >= 0 {
		return loc[:i]
	}
	return loc
}

// shipTelemetry reports a NO-REVIEW turn's metadata for per-prompt analytics: it
// builds the same turn meta a reviewed turn would carry and hands it to the
// reviewer's ShipTelemetry (cloud → /telemetry fire-and-forget).
// Best-effort and off the dev's critical path: any failure is logged and ignored,
// so analytics never delays or breaks the fail-open stop. Fires ONLY on a
// no-review exit — reviewed turns already carry their meta on /review, so this
// never double-counts.
// ⚠️ IT MUST CARRY THE BASELINE FACTS, and they are passed IN rather than read off
// turnMeta: the review path sets them further down Run (after both calls to this), so
// a telemetry meta built from turnMeta alone reports neither. That is not cosmetic —
// these are the NO-REVIEW turns, i.e. exactly the ones where "why was there nothing to
// review" is the whole question, and the field that answers it was blank on every one
// of them. A pilot ran a weekend of unreviewed turns whose events could not say why.
// shipTelemetry reports a turn that ran no review — no change, or every change inert — so the
// per-prompt analytics stay complete. Cloud only, fail-open, metadata with no prompt or code.
//
// ⚠️ IT TAKES THE CHANGES, AND IT APPLIES THE SAME `soleRepoOrigin` CORRECTION THE REVIEW PATH
// DOES (LEO-194). `turnMeta` resolves `Repo` from cwd, which names nothing when cwd is a folder
// HOLDING repositories rather than being one, and this path had no correction at all — so a
// workspace turn whose only edits were comments lost its repository while the identical turn
// with reviewable code kept it. That is not a cosmetic gap: `Repo` is the dimension the
// Repositories tab counts turns by, so the same account's turn count and review count came off
// different populations, and a repo whose recent work was all inert simply looked idle.
//
// The no-change caller passes an empty slice, where the correction is a no-op by construction:
// nothing changed, so there is no repository to name and the field stays honestly blank.
func shipTelemetry(a agent.Agent, r Reviewer, ev agent.Event, reason string,
	changes []transcript.Change, usedGit bool, baselineSkip vcs.SkipReason,
	log *slog.Logger, now time.Time) {
	meta := turnMeta(a, ev, log, now)
	meta.GitBaseline, meta.BaselineSkip = usedGit, string(baselineSkip)
	if meta.Repo == "" {
		meta.Repo = soleRepoOrigin(ev.Cwd, changes)
	}
	if err := r.ShipTelemetry(meta, reason, len(changes)); err != nil {
		log.Debug("ship telemetry failed (best-effort, ignoring)", "reason", reason, "err", err.Error())
	}
}

// agentReply is the agent's reaction to our block, shipped as /outcome's
// agent_response.
//
// ⚠️ THE STOP STDIN'S last_assistant_message IS THE FALLBACK, NOT THE SOURCE. It
// carries the turn's last assistant MESSAGE, and a turn is not one message — an
// agent that interleaves tool calls with prose emits several, so the reasoning
// lands in an earlier one and the last is a short sign-off. Shipping that captured
// a closing sentence and dropped the argument, which on a push-back is exactly the
// false-positive signal the field exists to collect. The adapter reads the whole
// post-re-wake segment out of the transcript instead.
//
// Fail-open like every other analytics read: a parse error, or an adapter that could
// not locate its re-wake boundary, leaves the previous behaviour in place rather than
// shipping nothing. An empty parse is treated as a miss for the same reason — "" would
// blank a field that had a usable value.
func agentReply(a agent.Agent, ev agent.Event, log *slog.Logger) string {
	reply, err := a.AgentReply(ev)
	if err != nil {
		log.Debug("agent-reply parse failed, using last_assistant_message", "err", err.Error())
		return ev.LastAssistantMessage
	}
	if reply == "" {
		return ev.LastAssistantMessage
	}
	if last := strings.TrimSpace(ev.LastAssistantMessage); last != "" && !strings.Contains(reply, last) {
		return reply + "\n\n" + last
	}
	return reply
}

// turnMeta assembles the coding agent's own turn activity for analytics: the
// transcript-derived fields (model, prompt, tokens, wall-clock) from the agent
// adapter, plus the repo + developer from git (agent-independent). All best-effort
// — a meta failure is logged and the zero/partial value is used; it never aborts
// the review (analytics is never on the fail-open critical path).
func turnMeta(a agent.Agent, ev agent.Event, log *slog.Logger, now time.Time) wire.TurnMeta {
	m, err := a.TurnMeta(ev)
	if err != nil {
		log.Debug("turn meta extraction failed (analytics only, continuing)", "err", err.Error())
	}
	// Turn wall-clock. An adapter that fills PromptTime (Claude) is signalling that its
	// transcript END timestamp is unreliable: the Stop hook reads the transcript before
	// the agent's FINAL message is flushed, so lastAssistant−prompt under-reports the
	// duration (a 13s turn was logged as 5s). The Stop hook fires AT turn end, so
	// now−PromptTime is the true wall-clock — it matches the agent's own "crunched for X"
	// timer. An adapter that leaves PromptTime zero (Codex — it reads a SETTLED rollout
	// after the turn, no flush race) keeps its own accurate DurationMs.
	dur := m.DurationMs
	if !m.PromptTime.IsZero() && now.After(m.PromptTime) {
		dur = now.Sub(m.PromptTime).Milliseconds()
	}
	// Read SEPARATELY from a.TurnMeta above, and deliberately after its error is
	// swallowed: the surface comes from the process environment or the hook dialect,
	// never the transcript, so a transcript that failed to parse must not cost us a
	// fact we still know. Total by contract — no error to handle.
	env := a.Environment(ev)
	// Resolved from cwd here; Run retries against the changed repositories' roots when
	// that came back with nothing, exactly as it does for Repo.
	dev, devSrc := vcs.DeveloperFrom(ev.Cwd)
	return wire.TurnMeta{
		Agent:               a.Name(),
		AgentModel:          m.AgentModel,
		Repo:                vcs.RepoOrigin(ev.Cwd),
		Developer:           dev,
		DeveloperSource:     devSrc,
		OS:                  runtime.GOOS,      // the dev machine's platform — compiled in, always known
		Arch:                runtime.GOARCH,    // NB on ARM Windows this reads amd64: we ship one x64 exe
		ClientVersion:       buildinfo.Version, // which plugin build produced this turn ("dev" when unstamped)
		Environment:         env.Name,          // which product surface — terminal / desktop / web / …
		EnvironmentRaw:      env.Raw,           // the unmapped signal, so a NEW surface is visible before we ship support for it
		Prompt:              m.Prompt,
		AgentNote:           ev.LastAssistantMessage, // the agent's own end-of-turn note (moving-baseline signal)
		InputTokens:         m.InputTokens,
		CacheCreationTokens: m.CacheCreationTokens,
		CacheReadTokens:     m.CacheReadTokens,
		OutputTokens:        m.OutputTokens,
		DurationMs:          dur,
		Speed:               m.Speed,
	}
}

// changedFiles discovers this turn's changes, preferring the git-baseline path
// (agent-agnostic, sees Bash writes, carries full-file context) and falling back
// to the agent's transcript parser when there is no usable baseline (not a git
// repo, no snapshot recorded, a git error). The fallback is exactly the legacy
// transcript-scoped behaviour, so a missing baseline never breaks review. The
// bool reports whether the git path was used (true) or the fallback (false) —
// the caller surfaces a degraded-review warning in the latter case — and the
// SkipReason says WHY it fell back.
//
// The fallback is logged at INFO, not Debug: a dev silently stuck on it gets a
// materially weaker review (no added-line positions, no
// Bash-write detection) while everything still looks normal, so the one line that
// would reveal it must survive the default log level. The reason rides along
// because the causes need opposite fixes (a baseline that was never recorded vs
// one git later lost).
func changedFiles(a agent.Agent, ev agent.Event, log *slog.Logger) ([]transcript.Change, bool, vcs.SkipReason, vcs.BaselineInfo, error) {
	mcpChanges := func() []transcript.Change {
		if ev.TranscriptPath == "" || len(ev.MCPTools) == 0 {
			return nil
		}
		var changes []transcript.Change
		var err error
		switch a.Name() {
		case "claude":
			changes, err = transcript.ParseMCPChanges(ev.TranscriptPath, ev.MCPTools)
		case "codex":
			changes, err = transcript.ParseCodexMCPChanges(ev.TranscriptPath, ev.MCPTools)
		default:
			return nil
		}
		if err != nil {
			log.Warn("MCP connector calls could not be read", "err", err.Error())
			return nil
		}
		return changes
	}
	changes, ok, skip, info, err := vcs.ChangedFilesWithInfo(ev.Cwd, ev.SessionID)
	if ok {
		changes = dropSecrets(changes, log)
		changes = append(changes, mcpChanges()...)
		log.Info("changed files via git baseline", "changed", len(changes))
		return changes, true, "", info, err
	}
	log.Info("DEGRADED review: no git baseline, using transcript fallback",
		"reason", string(skip), "cwd", ev.Cwd)
	changes, err = a.ChangedFiles(ev)
	// ⚠️ CARRY THE DECLINED REPOSITORIES THROUGH THE SKIP PATH. Everything else on
	// BaselineInfo describes a diff that did happen, so this branch discarded the whole
	// struct — but HeadDeclined is the reason there is no diff, and dropping it left the
	// developer with the generic "no git snapshot" notice on exactly the turn where we
	// knew which folders were in play and which one to open.
	// dropSecrets runs again after dropOutsideCwd, before any file is read: normalising a
	// path can reveal a different name than the agent used, and the secret check must see
	// the name that is read (LEO-637).
	changes = withFileContent(
		dropSecrets(
			dropOutsideCwd(
				dropSecrets(changes, log),
				ev.Cwd,
				log,
			),
			log,
		),
		ev.Cwd,
		log,
	)
	return append(changes, mcpChanges()...), false, skip, vcs.BaselineInfo{HeadDeclined: info.HeadDeclined}, err
}

// withFileContent attaches each fallback file's current content as FullContent, so the
// judge sees it numbered with its real line numbers. A transcript change is only the text
// the agent wrote, with no positions, and an unnumbered extract cannot say where a line
// sits: a guard appended BELOW the write it should guard reads as a fix (LEO-637, found in LEO-572: Opus
// 5.5 credited one 6 of 6 times unnumbered, 0 of 6 numbered).
//
// AddedLines stays nil ON PURPOSE. It is the positional authority for introduced vs
// pre-existing, and positions recovered by matching the agent's text against the file
// would be a content match, which cannot tell an added copy from its original. So
// classification is unchanged: only what the judge can see changes, to what the git path
// already sends for a file in a repository.
//
// Runs after dropSecrets and dropOutsideCwd, so it only reads files that already egress
// as their added text, and it reads them the way vcs does: through a root at cwd, from
// the descriptor it opened, rejecting a symlink, a non-regular file, binary content and
// anything over limits.MaxChangedFileBytes, within the turn's
// limits.MaxChangedTotalBytes. Any failure leaves the change as it was (fail-open).
func withFileContent(
	changes []transcript.Change,
	cwd string,
	log *slog.Logger,
) []transcript.Change {
	if cwd == "" {
		return changes
	}
	root, err := os.OpenRoot(resolvedPath(cwd))
	if err != nil {
		return changes
	}
	defer root.Close()
	total := 0
	for i, c := range changes {
		if c.Virtual || c.Deleted || c.FullContent != "" {
			continue
		}
		body, ok := fallbackContent(root, c.FilePath, cwd)
		if !ok || total+len(body) > limits.MaxChangedTotalBytes {
			log.Info("fallback file sent as its added text only", "path", c.FilePath)
			continue
		}
		total += len(body)
		changes[i].FullContent = body
	}
	return changes
}

// fallbackContent reads path from root without following a final symlink: only the
// directories are resolved (as dropOutsideCwd resolved them); the rest is readRegularFile.
func fallbackContent(
	root *os.Root,
	path string,
	cwd string,
) (string, bool) {
	if !filepath.IsAbs(path) {
		path = filepath.Join(cwd, path)
	}
	dir, err := filepath.EvalSymlinks(filepath.Dir(filepath.Clean(path)))
	if err != nil {
		return "", false
	}
	rel, err := filepath.Rel(root.Name(), filepath.Join(dir, filepath.Base(path)))
	if err != nil {
		return "", false
	}
	body, err := readRegularFile(root, rel)
	return body, err == nil
}

// readRegularFile is the one bounded read of a file the client sends whole outside the
// git diff: the fallback's changed files and an outcome's flagged files read back from disk
// (recoveryContent). It reads the way vcs does: the path must be a regular file reached
// without a final symlink, the open never blocks, the opened descriptor must be the same
// file Lstat sees, and the body is regular UTF-8 text within limits.MaxChangedFileBytes.
//
// Opening a FIFO blocks until a writer appears, which would hang the Stop hook before
// the checks below ever run. Two guards: a special file already at the path is refused
// without being opened at all, and the open itself is non-blocking (openNonblock), so a
// path swapped for a FIFO after this Lstat opens at once and the post-open checks
// refuse it. Those checks stay the authority: they prove the bytes came from a regular
// file reached without a symlink.
func readRegularFile(
	root *os.Root,
	rel string,
) (string, error) {
	if pre, err := root.Lstat(rel); err != nil {
		return "", err
	} else if !pre.Mode().IsRegular() {
		return "", fmt.Errorf("not a regular file: %s", rel)
	}
	f, err := root.OpenFile(rel, os.O_RDONLY|openNonblock, 0)
	if err != nil {
		return "", err
	}
	defer f.Close()
	opened, statErr := f.Stat()
	onDisk, lstatErr := root.Lstat(rel)
	if statErr != nil || lstatErr != nil || !opened.Mode().IsRegular() || !os.SameFile(opened, onDisk) {
		return "", fmt.Errorf("not a regular file: %s", rel)
	}
	body, err := io.ReadAll(io.LimitReader(f, limits.MaxChangedFileBytes+1))
	if err != nil {
		return "", err
	}
	if len(body) > limits.MaxChangedFileBytes || !utf8.Valid(body) || bytes.IndexByte(body, 0) >= 0 {
		return "", fmt.Errorf("unsupported content: %s", rel)
	}
	return string(body), nil
}

func dropOutsideCwd(
	changes []transcript.Change,
	cwd string,
	log *slog.Logger,
) []transcript.Change {
	if cwd == "" {
		return changes
	}
	root := resolvedPath(cwd)
	var out []transcript.Change
	for _, c := range changes {
		if c.Virtual {
			out = append(out, c)
			continue
		}
		if insideRoot(c.FilePath, cwd, root) {
			c.FilePath = relativeToRoot(c.FilePath, root)
			out = append(out, c)
			continue
		}
		log.Info("skipping file outside the project folder: never egressed for review",
			"path", c.FilePath,
			"cwd", cwd)
	}
	return out
}

func insideRoot(
	path string,
	cwd string,
	root string,
) bool {
	if !filepath.IsAbs(path) {
		path = filepath.Join(cwd, path)
	}
	rel, err := filepath.Rel(root, resolvedPath(path))
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func relativeToRoot(
	path string,
	root string,
) string {
	if !filepath.IsAbs(path) {
		return path
	}
	// Only the directories are resolved, never the final component: a symlink keeps its
	// own name, so a `config.py -> .env` alias is not renamed to the secret it points at,
	// and withFileContent still sees (and refuses) the link (LEO-637).
	rel, err := filepath.Rel(root, resolvedDir(path))
	if err != nil {
		return path
	}
	return filepath.ToSlash(rel)
}

// resolvedDir resolves symlinks in path's directories, keeping its last component as
// written.
func resolvedDir(path string) string {
	path = filepath.Clean(path)
	if dir, err := filepath.EvalSymlinks(filepath.Dir(path)); err == nil {
		return filepath.Join(dir, filepath.Base(path))
	}
	return path
}

func resolvedPath(path string) string {
	path = filepath.Clean(path)
	if r, err := filepath.EvalSymlinks(path); err == nil {
		return r
	}
	if dir, err := filepath.EvalSymlinks(filepath.Dir(path)); err == nil {
		return filepath.Join(dir, filepath.Base(path))
	}
	return path
}

// dropSecrets removes secret/credential files (private keys, .env, credential
// stores — see gate.IsSecretPath) from the change set so their content is NEVER
// egressed: not to the cloud /review, and not carried
// in an /outcome before/after. A dropped file is logged (the omission is never
// silent) and simply goes unreviewed. Runs on BOTH the git and fallback paths.
func dropSecrets(changes []transcript.Change, log *slog.Logger) []transcript.Change {
	var out []transcript.Change
	for _, c := range changes {
		if gate.IsSecretPath(c.FilePath) {
			log.Info("skipping secret file — never egressed for review", "path", c.FilePath)
			continue
		}
		out = append(out, c)
	}
	return out
}

// soleRepoOrigin names the repository a workspace turn changed, or "" when it changed
// several (or none, or the origin cannot be resolved).
//
// ⚠️ IT REFUSES TO GUESS WHEN A TURN SPANS REPOSITORIES. TurnMeta.Repo is the "app"
// dimension every dashboard groups by, and it holds ONE value; picking whichever
// project happened to be walked first would file a cross-project turn under an
// arbitrary one of them, which is worse than the blank these turns carried before —
// a wrong attribution reads as fact, a blank reads as unknown. Same discipline as
// BaselineHead, which is recorded only when there is one commit to name.
// changedRepoRoots returns the absolute roots of the repositories this turn changed,
// deduplicated and SORTED.
//
// Sorted rather than first-seen: `changes` arrives in whatever order git listed the diff,
// and an identity picked off that order would make a two-repo turn's attribution depend
// on it. The same reasoning the imports resolver records for `candidate.named`.
func changedRepoRoots(cwd string, changes []transcript.Change) []string {
	if cwd == "" {
		return nil
	}
	seen := map[string]bool{}
	var roots []string
	for _, c := range changes {
		if c.RepoDir == "" {
			continue // cwd IS the repo, which DeveloperFrom already read
		}
		dir := filepath.Join(cwd, filepath.FromSlash(c.RepoDir))
		if seen[dir] {
			continue
		}
		seen[dir] = true
		roots = append(roots, dir)
	}
	sort.Strings(roots)
	return roots
}

func soleRepoOrigin(cwd string, changes []transcript.Change) string {
	if cwd == "" || len(changes) == 0 {
		return ""
	}
	rel := changes[0].RepoDir
	for _, c := range changes[1:] {
		if c.RepoDir != rel {
			return ""
		}
	}
	if rel == "" {
		return "" // cwd IS the repo: turnMeta already resolved it (or it genuinely has none)
	}
	return vcs.RepoOrigin(filepath.Join(cwd, filepath.FromSlash(rel)))
}

// contextHintKey is the per-session throttle key for the repository-context reminder. It shares
// the skip notices' scratch file, and cannot collide with one: those key on a SkipReason.
const contextHintKey = "context_hint"

// firstCleanDeliverer is implemented by an adapter that can put the first-clean notice in the
// agent's reply on surfaces that hide a systemMessage (Claude's desktop app and web).
type firstCleanDeliverer interface {
	DeliverFirstClean(message string) ([]byte, error)
}

// editCallCounter is implemented by an adapter whose transcript can say how many edit
// tool calls the turn made, whether or not its ChangedFiles fallback could read them.
// The count turns "no git baseline and the fallback read nothing" into a reported
// failure when edits did happen (LEO-394), instead of a silent no_change.
type editCallCounter interface {
	EditCalls(ev agent.Event) (int, error)
}

// unreadEditsSkip is appended to the telemetry baseline_skip when the transcript shows
// edit calls the fallback could not read. A fixed string, so the field stays a closed set.
const unreadEditsSkip = "transcript shows edit tool calls the fallback could not read"

// unreadEdits reports how many edit calls the transcript shows on a turn where the git
// path was skipped and the fallback found nothing. 0 when the adapter cannot say.
func unreadEdits(a agent.Agent, ev agent.Event, usedGit bool, skip vcs.SkipReason, log *slog.Logger) int {
	c, ok := a.(editCallCounter)
	if !ok || usedGit || skip == vcs.SkipNoCwdOrSession {
		return 0
	}
	n, err := c.EditCalls(ev)
	if err != nil {
		log.Debug("edit-call count failed (continuing)", "err", err.Error())
		return 0
	}
	return n
}

type ephemeralHoster interface {
	EphemeralHost() bool
}

func onEphemeralHost(
	a agent.Agent,
) bool {
	h, ok := a.(ephemeralHoster)
	return ok && h.EphemeralHost()
}

// deliverFirstClean renders the one-time first-clean notice through the adapter's own channel
// when it has one, and as a plain non-blocking notice otherwise.
func deliverFirstClean(
	a agent.Agent,
) ([]byte, error) {
	if d, ok := a.(firstCleanDeliverer); ok {
		return d.DeliverFirstClean(review.FirstCleanNotice())
	}
	return a.DeliverNotice(review.FirstCleanNotice())
}

// codeReview is the code review's part of a Stop, unchanged from before the checks were routed
// (LEO-620): its own gate, the no-change and inert telemetry, /review, the wake or first-clean
// notice. It writes what it would print to stdout and returns the hook's exit code.
func codeReview(t stopTurn, stdout io.Writer) int {
	a, r, ev, log, now, recovered, failOpen := t.a, t.r, t.ev, t.log, t.now, t.recovered, t.failOpen
	changes, usedGit, baselineSkip, baseInfo := t.changes, t.usedGit, t.baselineSkip, t.baseInfo
	if len(changes) == 0 {
		// ⚠️ NOTHING READ IS NOT NOTHING WRITTEN. With the git path skipped, an empty
		// change set may only mean the fallback could not parse the agent's edit calls
		// (LEO-394: Codex code mode wrapped apply_patch in JavaScript and the turn was
		// recorded no_change). When the transcript shows edit calls, say so: an ERROR in
		// client.log, a distinct baseline_skip, and a once-per-session notice. Still
		// fail-open; the stop proceeds.
		if n := unreadEdits(a, ev, usedGit, baselineSkip, log); n > 0 {
			log.Error("the agent made edit tool calls but no change could be read (no git baseline, transcript fallback parsed none); this turn went unreviewed",
				"edit_calls", n, "reason", string(baselineSkip), "cwd", ev.Cwd)
			shipTelemetry(a, r, ev, wire.TelemetryNoChange, changes, usedGit, baselineSkip+"; "+unreadEditsSkip, log, now)
			notifyReviewSkipped(a, ev, &review.SkipError{Reason: review.SkipUnreadEdits}, log, stdout)
			return 0
		}
		log.Debug("no file edits this turn, allowing stop")
		shipTelemetry(a, r, ev, wire.TelemetryNoChange, changes, usedGit, baselineSkip, log, now)
		// A turn with no changes is normally just a question, and stays silent. But when
		// the git path was SKIPPED, "no changes" may instead mean we could not SEE them:
		// on an adapter with no transcript fallback (copilot) an empty change set is
		// Several repositories held work from this turn and nothing said which one it was
		// about, so none was reviewed. That is a MORE specific answer than the generic
		// no-baseline notice and it names the folder to open, so it wins — and it is not
		// throttled per session, because which repositories are in play changes turn to
		// turn and a stale suppression would leave the developer with no explanation at
		// all for the rest of the session.
		if len(baseInfo.HeadDeclined) > 0 {
			log.Warn("several repos hold this turn's work and none was named — nothing reviewed",
				"repos", strings.Join(baseInfo.HeadDeclined, ", "))
			if out, derr := a.DeliverNotice(review.HeadDeclinedNotice(baseInfo.HeadDeclined)); derr == nil {
				fmt.Fprint(stdout, string(out))
			}
			return 0
		}
		// ⚠️ NO GENERIC "no git snapshot" NOTICE ANY MORE — the reason it existed is now
		// covered, and it had become noise on every quiet turn.
		//
		// It was added because an unreviewed turn was indistinguishable from a quiet one:
		// a pilot on an agent with no transcript fallback spent a weekend at zero coverage
		// with no signal anywhere. What closed that: PreToolUse discovery resolves the
		// repo behind a named path or a shell command, and the Stop-time fallback covers
		// what nothing named — so a write we could not see now produces either a review or
		// the specific HeadDeclined notice above, both of which say more than this did.
		// What remained was a turn where nothing was written at all, where "nothing was
		// reviewed" is true, unactionable and printed on top of the developer's work.
		//
		// The WARN below stays: it is the operator's record in client.log, and it is how a
		// genuinely unseen write is still diagnosable after the fact. Only the terminal
		// message is gone. RESIDUAL GAP, deliberately accepted: a write into a repo more
		// than two levels below cwd, or outside it entirely, that nothing named — silent.
		if !usedGit && baselineSkip != vcs.SkipNoCwdOrSession {
			log.Warn("no git baseline and no changes discovered; this turn went unreviewed",
				"reason", string(baselineSkip), "cwd", ev.Cwd)
		}
		return 0 // nothing changed → telemetry still reports the turn's cost
	}

	// Inert gate: suppress only PROVABLY harmless changes (pure prose, or diffs
	// whose every non-blank added line is a comment) in BOTH tiers. This is a
	// denylist — it fails toward review, so an ambiguous diff is sent on rather
	// than silently dropped. A false negative here (vuln silently unreviewed) is
	// the dangerous failure; over-sending merely costs a little latency/egress.
	reviewable := gate.Run(changes)
	log.Info("changed files", "changed", len(changes), "reviewable", len(reviewable))
	if len(reviewable) == 0 {
		log.Debug("all changes inert, allowing stop")
		shipTelemetry(a, r, ev, wire.TelemetryInert, changes, usedGit, baselineSkip, log, now)
		return 0
	}

	// Coding-agent turn metadata for analytics (cloud tier forwards it).
	// Built only now that a review is actually happening. Best-effort:
	// any failure logs and proceeds with whatever was gathered — analytics must
	// never break the fail-open review.
	meta := turnMeta(a, ev, log, now)
	meta = withDiscovery(meta, ev, changes, usedGit, baselineSkip, baseInfo, log)

	// Cross-turn pre-existing resolution: if a PRIOR block surfaced pre-existing vulns
	// the dev hadn't fixed, and this turn touches those files, re-judge just those rules
	// against the new code and credit any now resolved (server records a kind:"resolution"
	// event). Independent of this turn's own review; off the critical path, fail-open.
	// The origin review_ids it resolved
	// ride this turn's /review meta so the (usually clean) review is recorded as a
	// RE-REVIEW, linkable back to the triggered review that first flagged them.
	if !recovered {
		meta.ResolvedReviewIDs = resolveLedger(r, ev.SessionID, changes, meta, log)
	}

	// Record that we are ABOUT to ask, before we ask. outcome.Remember below runs only
	// once /review returns, so a turn killed mid-call leaves nothing on disk while the
	// server has already judged the code and kept its findings: indistinguishable, on
	// the next Stop, from a turn that never asked. The marker makes the difference
	// visible. Best-effort: losing the write costs the detection, never the review.
	proposedID := outcome.NewReviewID()
	if err := outcome.MarkInFlight(ev.SessionID, outcome.InFlight{
		ReviewID:     proposedID,
		Repo:         meta.Repo,
		Developer:    meta.Developer,
		AgentModel:   meta.AgentModel,
		ChangedFiles: len(reviewable),
	}); err != nil {
		log.Debug("mark review in-flight failed (continuing)", "err", err.Error())
	}

	res, err := r.Review(ev.Cwd, reviewable, meta, proposedID)
	// The call came back: success, clean, or error. Either way its fate is known and
	// failOpen accounts for it, so the marker has done its job. Only a reply that never
	// arrives is left behind for the next Stop to find.
	outcome.ClearInFlight(ev.SessionID)
	if err != nil {
		notifyReviewSkipped(a, ev, err, log, stdout)
		return failOpen(err)
	}
	if res.Prompt == "" {
		log.Info("reviewer raised nothing, allowing stop")
		if !onEphemeralHost(a) && config.ClaimFirstClean(licenseKey()) {
			if out, derr := deliverFirstClean(a); derr == nil {
				fmt.Fprint(stdout, string(out))
			}
		}
		return 0 // reviewer found nothing to raise → silent after the first time
	}
	log.Info("review fired, re-waking agent", "reviewable", len(reviewable))

	// We are about to BLOCK + re-wake. Remember what we flagged so the NEXT Stop
	// (after the agent fixes) can score the outcome. Best-effort: a persist failure
	// just means no outcome is reported, never a failed re-wake.
	if res.Pending != nil {
		// How long this first Stop hook has been blocking the agent (from hook entry
		// `now` until here — changedFiles + gate + resolveLedger + the /review wait).
		// The agent is idle this whole window; the final Stop subtracts it so the
		// recorded latency excludes the wait-on-LeoPrevent (deliver+print after this is
		// sub-ms). See the stop_hook_active branch.
		res.Pending.ReviewBlockMs = time.Since(now).Milliseconds()
		if len(baseInfo.HeadAnchored) == 0 {
			prepareRecovery(res.Pending, ev.Cwd, reviewable, meta)
		}
		if err := outcome.Remember(ev.SessionID, *res.Pending); err != nil {
			log.Debug("remember outcome pending failed (continuing)", "err", err.Error())
		}
	}

	// Deliver with a short, neutral console banner (selection is not detection).
	// Without a git baseline the review ran on the transcript fallback (partial
	// view) — tell the developer it's degraded so a "clean-ish" result isn't
	// over-trusted.
	banner := review.Banner(len(reviewable))
	if !usedGit {
		banner += " " + review.GitlessWarning
	}
	findings := res.Findings
	if findings == nil && res.Pending != nil {
		findings = res.Pending.Findings
	}
	// ⚠️ A HEAD-ANCHORED REVIEW NEVER BLOCKS. It exists because nothing named a path, so
	// its diff is a superset of the turn and its findings may be describing work the
	// developer left uncommitted earlier. Re-waking the agent over that spends the
	// forcing function on somebody else's work in progress: measured live 2026-08-25, a
	// turn that wrote NOTHING was blocked for 71s over ten findings from four unrelated
	// checkouts. A false block is the one cost this product cannot pay, so these are
	// surfaced as a NON-BLOCKING notice and the stop proceeds.
	//
	// The two cases are mutually exclusive by construction: the fallback only runs when
	// the turn produced no changes at all, so a turn is either wholly baselined or wholly
	// HEAD-anchored, and this can never suppress a block a baselined finding earned.
	if len(baseInfo.HeadAnchored) > 0 {
		log.Info("HEAD-anchored review: surfacing without a block",
			"repos", strings.Join(baseInfo.HeadAnchored, ", "), "findings", len(findings))
		if out, derr := a.DeliverNotice(review.HeadAnchoredNotice(baseInfo.HeadAnchored, len(findings))); derr == nil {
			fmt.Fprint(stdout, string(out))
		}
		return 0
	}
	// The repository-context reminder rides this block, once per session (LEO-161). Checked
	// only here, after every early return, so the throttle is spent only on a re-wake that is
	// actually delivered.
	if res.ContextHint != "" && notify.FirstThisSession(ev.SessionID, contextHintKey) {
		res.Prompt = review.AppendContextHint(res.Prompt, res.ContextHint)
	}
	out, err := a.DeliverReview(res.Prompt, banner, len(reviewable), findings, res.Summary)
	if err != nil {
		return failOpen(err)
	}
	fmt.Fprint(stdout, string(out))
	return 0
}
