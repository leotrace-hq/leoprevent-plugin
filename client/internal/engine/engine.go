// Package engine is leoprevent's agent-agnostic Stop-hook run loop:
// per-turn guard → changed files → inert gate → review → deliver re-wake. The
// agent-specific I/O (stdin shape, changed-file discovery, re-wake format) is
// supplied by an agent.Agent; HOW the review prompt is produced (local-tier
// on-device selection + /rules, or cloud-tier server /review) is supplied by a
// Reviewer, so the loop is identical across tiers.
//
// Contract: FAIL OPEN. Any error → log to stderr, exit 0, never block the stop.
// The hook must never trap the developer. The one thing it may print on the
// fail-open path is a NON-BLOCKING notice (systemMessage, no decision) when a
// review couldn't run — so an outage isn't silently mistaken for "all clear" —
// throttled to once per session per reason (see notifyReviewSkipped).
package engine

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"runtime"
	"strings"
	"time"

	"github.com/leotrace-hq/leoprevent-plugin/buildinfo"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/agent"
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

// Result is what a Reviewer produces for a turn: the re-wake Prompt (empty =
// nothing to raise → allow the stop) and, on a cloud-tier BLOCK, the Pending
// outcome to track (review_id + findings + the "before" code) so the agent's later
// fix can be scored. Pending is nil for the local tier and for clean reviews.
type Result struct {
	Prompt  string
	Pending *outcome.Pending
}

// Reviewer turns the changed code this turn into a Result. The implementation owns
// the tier (local: select on-device + fetch /rules; cloud: call /review). meta is
// the coding agent's own turn activity (analytics); the cloud tier forwards it to
// the server, the local tier ignores it.
type Reviewer interface {
	// Review judges this turn's changes. cwd is the agent's working directory —
	// the cloud tier uses it to resolve cross-file imported context on-device (the
	// local tier ignores it, sending no code). meta is the coding agent's own turn
	// activity (analytics), forwarded by cloud, ignored by local.
	Review(cwd string, changes []transcript.Change, meta wire.TurnMeta) (Result, error)
	// ShipOutcome reports the agent's fix after a prior block and SYNCHRONOUSLY
	// re-verifies it (cloud: POST /outcome, server re-judges, bounded + fail-open;
	// local: no-op). It returns (1) the INTRODUCED findings the re-judge still flags —
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
	// /outcome with Resolution=true; local: no-op. Same scored contract as ShipOutcome:
	// an unscored response is an error (outcome.ErrUnscored), so an empty stillFiring
	// with a nil error genuinely means everything resolved.
	ShipResolution(p outcome.Pending, after []transcript.Change, meta wire.TurnMeta) (stillFiring []wire.Finding, err error)
	// ShipTelemetry reports the coding agent's turn metadata for a turn that did NOT
	// trigger a review (no changed files, or every change inert), so per-prompt
	// cost/latency analytics covers EVERY turn — not only reviewed ones. Cloud POSTs
	// /telemetry (fail-open, off the dev's path); local is a no-op. Never blocks the
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
	if ev.StopHookActive {
		if p, ok := outcome.Take(ev.SessionID); ok {
			after, _, _, _, _ := changedFiles(a, ev, log) // agent's state now (incl. the fix)
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
			stillFiring, preStillFiring, err := r.ShipOutcome(p, after, agentReply(a, ev, log), fullMeta)
			switch {
			case errors.Is(err, outcome.ErrUnscored):
				// The server ACCEPTED the outcome but produced NO verdict (capacity
				// skip / re-judge failure). There is nothing to warn the dev about —
				// a "still vulnerable" notice needs a verdict — and the empty
				// still-firing sets mean "not judged", not "all clear", so nothing is
				// seeded either (the err != nil guard below skips seedLedger).
				log.Info("outcome accepted but not scored — no verdict, no notice, ledger untouched", "review_id", p.ReviewID)
			case err != nil:
				log.Debug("ship outcome failed (best-effort, ignoring)", "err", err.Error())
			case len(stillFiring) > 0:
				// The re-verify says the agent's introduced fix is STILL vulnerable. Warn
				// the dev in-turn (non-blocking) — before they close the agent thinking
				// it's done. Fail-open: the stop still proceeds.
				log.Info("fix still vulnerable after re-wake", "review_id", p.ReviewID, "still_firing", len(stillFiring))
				notifyFixStillVulnerable(a, ev, stillFiring, log, stdout)
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
		}
		log.Debug("stop_hook_active guard: already reviewed this turn, allowing stop")
		return 0
	}

	changes, usedGit, baselineSkip, baseInfo, err := changedFiles(a, ev, log)
	if err != nil {
		return failOpen(fmt.Errorf("changed files: %w", err))
	}
	if len(changes) == 0 {
		log.Debug("no file edits this turn, allowing stop")
		shipTelemetry(a, r, ev, wire.TelemetryNoChange, 0, log, now)
		return 0 // nothing changed → silent (telemetry still reports the turn's cost)
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
		shipTelemetry(a, r, ev, wire.TelemetryInert, len(changes), log, now)
		return 0
	}

	// Coding-agent turn metadata for analytics (cloud tier forwards it; local
	// ignores it). Built only now that a review is actually happening. Best-effort:
	// any failure logs and proceeds with whatever was gathered — analytics must
	// never break the fail-open review.
	meta := turnMeta(a, ev, log, now)
	// Record HOW this turn's changes were discovered. A fallback turn is a materially
	// weaker review (no full-file context, no real line numbers, no Bash-write
	// detection) that is otherwise indistinguishable server-side, so without this a
	// developer silently stuck on it looks exactly like one who is fine.
	meta.GitBaseline, meta.BaselineSkip = usedGit, string(baselineSkip)
	// Where the tree started, and how many files were excluded as already-published
	// (a mid-turn checkout/pull/merge imports somebody else's merged commits). The
	// second is the one worth watching: it is the only step that removes code from
	// review, so an over-subtraction would otherwise just look like a quiet turn.
	meta.BaselineHead, meta.ImportedDropped = baseInfo.Head, baseInfo.ImportedDropped

	// Cross-turn pre-existing resolution: if a PRIOR block surfaced pre-existing vulns
	// the dev hadn't fixed, and this turn touches those files, re-judge just those rules
	// against the new code and credit any now resolved (server records a kind:"resolution"
	// event). Independent of this turn's own review; off the critical path, fail-open.
	// (cloud only — local ShipResolution is a no-op.) The origin review_ids it resolved
	// ride this turn's /review meta so the (usually clean) review is recorded as a
	// RE-REVIEW, linkable back to the triggered review that first flagged them.
	meta.ResolvedReviewIDs = resolveLedger(r, ev.SessionID, changes, meta, log)

	res, err := r.Review(ev.Cwd, reviewable, meta)
	if err != nil {
		notifyReviewSkipped(a, ev, err, log, stdout)
		return failOpen(err)
	}
	if res.Prompt == "" {
		log.Info("reviewer raised nothing, allowing stop")
		return 0 // reviewer found nothing to raise → silent
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
	// Pass the judged findings so an adapter that states the notice can say whether
	// anything was actually FIXED: only introduced findings are force-fixed; the rest
	// are surfaced. res.Pending is nil on the local tier (the agent's own model judges,
	// so the client never sees a finding list) — the notice then falls back to the
	// generic wording.
	var findings []wire.Finding
	if res.Pending != nil {
		findings = res.Pending.Findings
	}
	out, err := a.DeliverReview(res.Prompt, banner, len(reviewable), findings)
	if err != nil {
		return failOpen(err)
	}
	fmt.Fprint(stdout, string(out))
	return 0
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
	if se.Reason == review.SkipUnauthorized {
		enroll.MarkStaleKey()
	}
	if !notify.FirstThisSession(ev.SessionID, se.Reason.String()) {
		log.Debug("skip notice already shown this session, suppressing", "reason", se.Reason.String())
		return
	}
	out, derr := a.DeliverNotice(review.SkipNotice(se.Reason))
	if derr != nil {
		log.Debug("deliver skip notice failed (continuing)", "err", derr.Error())
		return
	}
	fmt.Fprint(stdout, string(out))
}

// notifyFixStillVulnerable surfaces a NON-BLOCKING developer notice when the
// synchronous /outcome re-verify finds the agent's introduced fix is STILL vulnerable —
// so the dev learns it in-turn (before closing the agent) instead of shipping a
// silently-bad fix. It never blocks or re-wakes (the stop proceeds); fail-open — any
// delivery problem just means no notice. This is the PLUGIN client log (client.log).
func notifyFixStillVulnerable(a agent.Agent, ev agent.Event, stillFiring []wire.Finding, log *slog.Logger, stdout io.Writer) {
	out, derr := a.DeliverNotice(review.FixStillVulnerableNotice(stillFiring))
	if derr != nil {
		log.Debug("deliver fix-still-vulnerable notice failed (continuing)", "err", derr.Error())
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
// reviewer's ShipTelemetry (cloud → /telemetry fire-and-forget; local → no-op).
// Best-effort and off the dev's critical path: any failure is logged and ignored,
// so analytics never delays or breaks the fail-open stop. Fires ONLY on a
// no-review exit — reviewed turns already carry their meta on /review, so this
// never double-counts.
func shipTelemetry(a agent.Agent, r Reviewer, ev agent.Event, reason string, changedFiles int, log *slog.Logger, now time.Time) {
	meta := turnMeta(a, ev, log, now)
	if err := r.ShipTelemetry(meta, reason, changedFiles); err != nil {
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
	return wire.TurnMeta{
		Agent:               a.Name(),
		AgentModel:          m.AgentModel,
		Repo:                vcs.RepoOrigin(ev.Cwd),
		Developer:           vcs.Developer(ev.Cwd),
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
// materially weaker review (no full-file context, no real line numbers, no
// Bash-write detection) while everything still looks normal, so the one line that
// would reveal it must survive the default log level. The reason rides along
// because the causes need opposite fixes (a baseline that was never recorded vs
// one git later lost).
func changedFiles(a agent.Agent, ev agent.Event, log *slog.Logger) ([]transcript.Change, bool, vcs.SkipReason, vcs.BaselineInfo, error) {
	changes, ok, skip, info, err := vcs.ChangedFilesWithInfo(ev.Cwd, ev.SessionID)
	if ok {
		changes = dropSecrets(changes, log)
		log.Info("changed files via git baseline", "changed", len(changes))
		return changes, true, "", info, err
	}
	log.Info("DEGRADED review: no git baseline, using transcript fallback",
		"reason", string(skip), "cwd", ev.Cwd)
	changes, err = a.ChangedFiles(ev)
	return dropSecrets(changes, log), false, skip, vcs.BaselineInfo{}, err
}

// dropSecrets removes secret/credential files (private keys, .env, credential
// stores — see gate.IsSecretPath) from the change set so their content is NEVER
// egressed: not to the cloud /review, not read for local selection, and not carried
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
