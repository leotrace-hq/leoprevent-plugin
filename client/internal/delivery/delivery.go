// Package delivery implements the two tiers behind the engine.Reviewer seam
// :
//
//   - Local: select rule IDs ON-DEVICE (the decision tree), fetch their content
//     via /rules, and let the agent's own model judge locally. No code egress.
//   - Cloud: send the changed code to /review; the server selects + judges and
//     returns confirmed findings. The rules never leave the server.
package delivery

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/apiclient"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/config"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/engine"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/imports"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/outcome"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/review"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/selector"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/vcs"
	"github.com/leotrace-hq/leoprevent-plugin/limits"
	"github.com/leotrace-hq/leoprevent-plugin/logx"
	"github.com/leotrace-hq/leoprevent-plugin/rulespec"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

// changedPaths is the file paths of a change set (for language filtering).
func changedPaths(changes []transcript.Change) []string {
	paths := make([]string, len(changes))
	for i, c := range changes {
		paths[i] = c.FilePath
	}
	return paths
}

// New builds the Reviewer for the configured tier.
func New(cfg *config.Config) (engine.Reviewer, error) {
	client := apiclient.New(cfg.ServerURL, cfg.LicenseKey)
	switch cfg.Tier {
	case config.TierLocal:
		return Local{client: client}, nil
	case config.TierCloud:
		return Cloud{client: client, resolveImports: cfg.ResolveImportsEnabled()}, nil
	default:
		return nil, fmt.Errorf("delivery: unknown tier %q", cfg.Tier)
	}
}

// Local is the no-code-egress tier: on-device selection + /rules + local judge.
type Local struct{ client *apiclient.Client }

func (d Local) Review(_ string, changes []transcript.Change, _ wire.TurnMeta) (engine.Result, error) {
	ids := selector.SelectIDs(changes)
	slog.Debug("local: selected rule IDs", "ids", ids)
	if len(ids) == 0 {
		return engine.Result{}, nil
	}
	resp, err := d.client.Rules(ids)
	if err != nil {
		return engine.Result{}, classifyServerErr(err)
	}
	// Drop rules whose applies_to doesn't match the changed files' languages
	// (the selector is content-free, so this happens once content is in hand).
	rules := rulespec.FilterByLanguages(resp.Rules, changedPaths(changes))
	// NOTE: rich per-review event logging is built for the CLOUD tier only for now
	// (see Cloud.Review). The local tier's equivalent is deliberately deferred —
	// here selection/judging happen on-device, so there's no server-side record to
	// pair with.
	slog.Info("local: rules to review", "fetched", len(resp.Rules), "after_language_filter", len(rules))
	if len(rules) == 0 {
		return engine.Result{}, nil
	}
	return engine.Result{Prompt: review.BuildPrompt(changes, rules, resp.MetaPolicy)}, nil
}

// ShipOutcome is a no-op for the local tier: the server never saw the code (only
// rule IDs), so there is no /outcome to report to. Satisfies engine.Reviewer.
// ShipReasons is a no-op for the local tier, for ShipOutcome's reason: the server saw no
// code and holds no outcome to label.
func (d Local) ShipReasons(_ outcome.Pending, _, _ string, _ wire.TurnMeta) error { return nil }

func (d Local) ShipOutcome(_ outcome.Pending, _ []transcript.Change, _ string, _ wire.TurnMeta) ([]wire.Finding, []wire.Finding, error) {
	return nil, nil, nil
}

// ShipResolution is a no-op for the local tier: no code ever reached the server, so
// there is no cross-turn re-judge to run. Satisfies engine.Reviewer.
func (d Local) ShipResolution(_ outcome.Pending, _ []transcript.Change, _ wire.TurnMeta) ([]wire.Finding, error) {
	return nil, nil
}

// ShipTelemetry is a no-op for the local tier: the local tier sends only rule IDs
// and NEVER metadata (the egress non-negotiable), so there is no /telemetry to
// report to. Per-prompt analytics is a cloud-tier concern. Satisfies engine.Reviewer.
func (d Local) ShipTelemetry(_ wire.TurnMeta, _ string, _ int) error { return nil }

// Cloud is the IP-protected tier: server selects + judges, returns findings only.
// resolveImports gates the cross-file context feature (off → today's behavior:
// only changed files are sent).
type Cloud struct {
	client         *apiclient.Client
	resolveImports bool
}

// Request-size budgets live in the limits package (limits.MaxReviewBytes —
// per /review POST; limits.MaxSingleFileBytes — single-file ceiling). The batch
// budget sits UNDER the server's ~1.5 MiB render cap (with margin for server-side
// numbering/headers) so every changed file in a batch renders in full for the model —
// no "sent but not judged" window. A change set larger than one batch spans several;
// a single file larger than the ceiling (a generated blob, never source) has its
// FullContent dropped then AddedText truncated. See the limits package.

// fileBytes estimates a file's contribution to the JSON request body.
func fileBytes(f wire.ChangedFile) int {
	return len(f.Path) + len(f.AddedText) + len(f.FullContent) + 64 // +64 ≈ JSON field overhead
}

// fitFile guarantees a single file's payload is ≤ limits.MaxSingleFileBytes so it can always
// be sent in some request. It first drops FullContent (only context), then — only if
// still too large — truncates AddedText as a last resort. This is the ONLY place
// reviewable text is reduced; it triggers solely for a single file past the 1 MiB
// ceiling (not hand-written source), and it is logged at WARN so it is never silent.
func fitFile(f wire.ChangedFile) wire.ChangedFile {
	if fileBytes(f) <= limits.MaxSingleFileBytes {
		return f
	}
	if f.FullContent != "" {
		f.FullContent = ""
		if fileBytes(f) <= limits.MaxSingleFileBytes {
			slog.Warn("cloud: dropped full-file context for oversized file (added lines still reviewed)", "path", f.Path)
			return f
		}
	}
	const marker = "\n… [truncated: file exceeds review size limit]\n"
	keep := limits.MaxSingleFileBytes - len(f.Path) - 64 - len(marker)
	if keep < 0 {
		keep = 0
	}
	if keep < len(f.AddedText) {
		f.AddedText = f.AddedText[:keep] + marker
		slog.Warn("cloud: truncated oversized file to fit review size limit (not normal source)", "path", f.Path)
	}
	return f
}

// packReviewBatches groups files into batches whose total payload stays under budget,
// so each /review POST is under the server's body cap. Every file rides in exactly one
// batch (no file is dropped); an empty input yields a single empty batch so the
// "no changes → clean" path still issues one request.
func packReviewBatches(files []wire.ChangedFile, budget int) [][]wire.ChangedFile {
	if len(files) == 0 {
		return [][]wire.ChangedFile{nil}
	}
	var batches [][]wire.ChangedFile
	var cur []wire.ChangedFile
	curSize := 0
	for _, f := range files {
		f = fitFile(f)
		sz := fileBytes(f)
		if len(cur) > 0 && curSize+sz > budget {
			batches = append(batches, cur)
			cur, curSize = nil, 0
		}
		cur = append(cur, f)
		curSize += sz
	}
	return append(batches, cur)
}

func (h Cloud) Review(cwd string, changes []transcript.Change, meta wire.TurnMeta) (engine.Result, error) {
	files := make([]wire.ChangedFile, len(changes))
	for i, c := range changes {
		files[i] = wire.ChangedFile{Path: c.FilePath, AddedText: c.AddedText, FullContent: c.FullContent, AddedLines: c.AddedLines}
	}
	// Cross-file context: resolve the in-repo helpers the changed code imports and
	// calls into (one hop, local symbols, gated) so the server can judge a sink that
	// lives one import away. Best-effort and off the critical contract — any failure
	// (no git root, unreadable file) just yields less context, never a broken review.
	var ctx []wire.ContextFile
	if h.resolveImports {
		ctx = resolveContext(cwd, changes)
		if len(ctx) > 0 {
			slog.Info("cloud: resolved cross-file context", "files", len(ctx))
		}
	}
	// Split the changed files into request-sized batches so NO single POST exceeds the
	// server's body cap (api.maxRequestBytes). An over-cap body is rejected with 400,
	// which the client treats as a server error and FAILS OPEN — the turn goes
	// unreviewed. Batching guarantees every file is SENT in some request (each then
	// rendered up to the server's payload cap), so a normal turn — well under one
	// request — is judged in full; only a pathologically large change set is split.
	// Binaries are dropped at capture in vcs and FullContent is already per-file/
	// total-capped there; the only reduction here is a last-resort truncation of a
	// single file larger than a whole request (a generated blob) — logged below.
	batches := packReviewBatches(files, limits.MaxReviewBytes)
	resp := wire.ReviewResponse{Verdict: wire.VerdictClean}
	for bi, batch := range batches {
		var bctx []wire.ContextFile
		bmeta := meta
		if bi == 0 {
			bctx = ctx // cross-file context rides the first batch only (keeps it bounded)
		} else {
			// Continuation batch: identity dimensions only. The turn's tokens, duration
			// and prompt were recorded on the FIRST batch's event — re-sending them
			// would double-count the agent's cost per batch (and persist the dev's
			// prompt N times). ContinuesReviewID points at the event that has them.
			bmeta.Prompt = ""
			bmeta.InputTokens, bmeta.CacheCreationTokens, bmeta.CacheReadTokens, bmeta.OutputTokens = 0, 0, 0, 0
			bmeta.DurationMs = 0
			bmeta.ResolvedReviewIDs = nil // the re-review link rides the FIRST batch only
			bmeta.ContinuesReviewID = resp.ReviewID
		}
		br, err := h.client.Review(batch, bctx, bmeta)
		if err != nil {
			return engine.Result{}, classifyServerErr(err)
		}
		if br.Verdict != wire.VerdictClean {
			resp.Verdict = br.Verdict
		}
		resp.Findings = append(resp.Findings, br.Findings...)
		if resp.ReviewID == "" {
			resp.ReviewID = br.ReviewID
		}
		// The pre-existing remediation directive is the SERVER's wording, and every batch
		// of one turn carries the same account policy — so take the FIRST non-empty one
		// rather than appending. Concatenating would print the instruction paragraph once
		// per batch above a single merged group.
		if resp.PreexistingDirective == "" {
			resp.PreexistingDirective = br.PreexistingDirective
		}
	}
	if len(batches) > 1 {
		slog.Info("cloud: review split into batches (change set exceeded request budget)",
			"batches", len(batches), "files", len(files))
	}

	var prompt string
	if resp.Verdict != wire.VerdictClean && len(resp.Findings) > 0 {
		prompt = review.BuildFindingsPrompt(resp.Findings, resp.PreexistingDirective)
	}

	// Cloud-tier client logging (PLUGIN-side client.log; the server keeps its own
	// review-event log). Metadata always — now including the coding-agent turn
	// metadata we send (model, repo, developer, token totals, duration); code
	// bodies — the diff we sent, the per-finding issue/fix, and the dev's prompt —
	// only when $LEOPREVENT_AUDIT opts in (logx.AuditBodies, shared with the server
	// so the two agree). The dev's own machine + own code.
	fields := []any{
		"tier", "cloud",
		"files", len(files),
		"verdict", resp.Verdict,
		"findings", len(resp.Findings),
		"rules", findingRuleIDs(resp.Findings),
		"fired", prompt != "",
		"agent_model", meta.AgentModel,
		"repo", meta.Repo,
		"developer", meta.Developer,
		"agent_tokens", meta.InputTokens + meta.CacheCreationTokens + meta.CacheReadTokens + meta.OutputTokens,
		"agent_duration_ms", meta.DurationMs,
	}
	if logx.AuditBodies() {
		fields = append(fields, "diff", changesText(changes), "findings_detail", resp.Findings, "prompt", meta.Prompt)
	}
	slog.Info("cloud: server review", fields...)

	res := engine.Result{Prompt: prompt}
	// On a BLOCK, remember what we flagged so the agent's later fix can be scored
	// (the engine persists this and ships it at the next Stop via ShipOutcome).
	if prompt != "" {
		res.Pending = &outcome.Pending{
			ReviewID:   resp.ReviewID,
			Repo:       meta.Repo,
			Developer:  meta.Developer,
			AgentModel: meta.AgentModel,
			Findings:   resp.Findings,
			Before:     files,
		}
	}
	return res, nil
}

// ShipOutcome POSTs the agent's reaction to a prior block to /outcome for a SYNCHRONOUS
// server-side re-judge, and returns the still-firing introduced + pre-existing findings.
// Bounded + fail-open: the client waits only up to OutcomeVerifyDeadline (then the engine
// treats it as no verdict), and at server capacity the re-judge is skipped (202, empty
// verdict); any error is returned for the engine to log and ignore.
func (h Cloud) ShipOutcome(p outcome.Pending, after []transcript.Change, agentResponse string, meta wire.TurnMeta) ([]wire.Finding, []wire.Finding, error) {
	afterFiles := make([]wire.ChangedFile, len(after))
	for i, c := range after {
		afterFiles[i] = wire.ChangedFile{Path: c.FilePath, AddedText: c.AddedText, FullContent: c.FullContent, AddedLines: c.AddedLines}
	}
	// Prefer the final-Stop meta's model (the model that ended the turn); fall back to
	// the Pending record's if the re-parse came up empty.
	agentModel := meta.AgentModel
	if agentModel == "" {
		agentModel = p.AgentModel
	}
	// If the reply carries an assumptions block, lift it into its own field. Nothing
	// ASKS for one since LEO-113 (review.AssumptionsAsk is no longer appended to the
	// re-wake, because the ask and the answer both render in the developer's session),
	// so in practice this yields reported=false on every turn. The call stays because it
	// is what makes re-enabling the ask a one-line change, and because an agent that
	// volunteers the block should still be read rather than ignored. Parsed here rather
	// than in the engine so BOTH callers get it — the Stop hook and the headless `exec`
	// loop (clirun), which share this method and nothing above it. agentResponse itself
	// is shipped VERBATIM: it is the record of what the agent said, and editing a block
	// out of it to avoid a duplicate would make that record less faithful.
	assumptions, reported := review.ParseAssumptions(agentResponse)
	resp, err := h.client.Outcome(wire.OutcomeRequest{
		ReviewID:      p.ReviewID,
		Repo:          p.Repo,
		Developer:     p.Developer,
		Agent:         meta.Agent,
		AgentModel:    agentModel,
		Before:        p.Before,
		After:         afterFiles,
		Findings:      p.Findings,
		AgentResponse: agentResponse,
		// The turn's own instruction, so the server's reason classifier can tell a
		// deliberate test of LeoPrevent from ordinary work — see wire.OutcomeRequest.Prompt.
		// Already sent on /review this same turn, so no new egress.
		Prompt:              meta.Prompt,
		Assumptions:         assumptions,
		AssumptionsReported: reported,
		// FULL-TURN agent token usage + wall-clock (final-Stop capture, spans the re-wake).
		InputTokens:         meta.InputTokens,
		CacheCreationTokens: meta.CacheCreationTokens,
		CacheReadTokens:     meta.CacheReadTokens,
		OutputTokens:        meta.OutputTokens,
		DurationMs:          meta.DurationMs,
		Speed:               meta.Speed,
	})
	if err != nil {
		return nil, nil, err
	}
	// IntroducedStillFiring → the in-turn "still vulnerable" notice; PreexistingStillFiring
	// → seeds the cross-turn ledger (surfaced pre-existing the dev hasn't fixed yet).
	return resp.IntroducedStillFiring, resp.PreexistingStillFiring, nil
}

// ShipResolution re-judges carried-over findings (from a prior block — pre-existing
// surfaced AND introduced declined/failed) against this turn's code, via POST /outcome
// with Resolution=true so the server records a kind:"resolution" event crediting any now
// resolved (pre-existing → PreexistingFixed, introduced → IntroducedResolved). NO agent
// token/latency meta is sent — this turn's cost is already captured by its OWN /review or
// /telemetry, and re-sending it here would double-count the agent's spend. Bounded +
// fail-open like ShipOutcome: the client waits only up to OutcomeVerifyDeadline (then no
// verdict). Returns ALL findings still firing (both classes) so the ledger keeps the
// correct open set.
func (h Cloud) ShipResolution(p outcome.Pending, after []transcript.Change, meta wire.TurnMeta) ([]wire.Finding, error) {
	afterFiles := make([]wire.ChangedFile, len(after))
	for i, c := range after {
		afterFiles[i] = wire.ChangedFile{Path: c.FilePath, AddedText: c.AddedText, FullContent: c.FullContent, AddedLines: c.AddedLines}
	}
	agentModel := meta.AgentModel
	if agentModel == "" {
		agentModel = p.AgentModel
	}
	resp, err := h.client.Outcome(wire.OutcomeRequest{
		ReviewID:   p.ReviewID, // the ORIGIN review that surfaced these pre-existing findings
		Resolution: true,
		Repo:       p.Repo,
		Developer:  p.Developer,
		Agent:      meta.Agent,
		AgentModel: agentModel,
		Before:     p.Before,
		After:      afterFiles,
		Findings:   p.Findings,
		// Deliberately no token/duration meta — see doc comment (avoids double-counting).
	})
	if err != nil {
		return nil, err
	}
	// Both classes still open stay in the ledger; each keeps its Preexisting flag so a
	// future resolution credits it to the right bucket. Introduced first (stable order).
	stillOpen := make([]wire.Finding, 0, len(resp.IntroducedStillFiring)+len(resp.PreexistingStillFiring))
	stillOpen = append(stillOpen, resp.IntroducedStillFiring...)
	stillOpen = append(stillOpen, resp.PreexistingStillFiring...)
	return stillOpen, nil
}

// ShipReasons POSTs a REASONS-ONLY resolution: the carried findings plus this turn's own
// words, so the server can record why they are still open without re-judging anything.
//
// ⚠️ THE TURN THAT DECIDES IS RARELY THE TURN THAT BLOCKED. /outcome fires at the second
// Stop of the blocked turn, so its reply predates the developer answering — the ticket is
// usually created on the NEXT turn, which changes no flagged file and so never triggers an
// ordinary resolution. Without this the commonest shape of "ticketed" was invisible.
//
// Deliberately carries NO after-files and no token/duration meta: nothing is re-judged, and
// this turn's own cost is already recorded by its /review or /telemetry.
func (h Cloud) ShipReasons(p outcome.Pending, prompt, reply string, meta wire.TurnMeta) error {
	agentModel := meta.AgentModel
	if agentModel == "" {
		agentModel = p.AgentModel
	}
	_, err := h.client.Outcome(wire.OutcomeRequest{
		ReviewID:      p.ReviewID, // the ORIGIN review whose findings are still open
		Resolution:    true,
		ReasonsOnly:   true,
		Repo:          p.Repo,
		Developer:     p.Developer,
		Agent:         meta.Agent,
		AgentModel:    agentModel,
		Findings:      p.Findings,
		Prompt:        prompt,
		AgentResponse: reply,
	})
	// An unscored ACK is the EXPECTED answer here — nothing was judged, by design — so it is
	// not an error worth reporting to a caller that changes no state either way.
	if errors.Is(err, outcome.ErrUnscored) {
		return nil
	}
	return err
}

// ShipTelemetry reports a NO-REVIEW turn's metadata to /telemetry so per-prompt
// cost/latency analytics covers every cloud turn, not just reviewed ones. The
// BODIES are dropped before sending — the dev's prompt AND the agent's reply
// (AgentNote) — so telemetry carries only the dimensions: model, repo, developer,
// tokens, duration (minimal egress; the server records no body fields for
// telemetry anyway). Fail-open: the server 202s
// and the apiclient uses a short timeout, so this never delays the developer; any
// error is returned for the engine to log and ignore.
func (h Cloud) ShipTelemetry(meta wire.TurnMeta, reason string, changedFiles int) error {
	meta.Prompt = ""    // never egress the dev's prompt on a no-review turn (opt-in only, future)
	meta.AgentNote = "" // ditto the agent's reply — a body, not a dimension (the metadata-only contract)
	req := wire.TelemetryRequest{Meta: meta, Reason: reason, ChangedFiles: changedFiles}

	// Cloud-tier client logging (PLUGIN-side client.log). All metadata — there is no
	// body to gate here (the prompt is dropped above; no code is sent on a no-review
	// turn), so this logs unconditionally.
	slog.Info("cloud: telemetry",
		"reason", reason,
		"changed_files", changedFiles,
		"agent_model", meta.AgentModel,
		"repo", meta.Repo,
		"developer", meta.Developer,
		"agent_tokens", meta.InputTokens+meta.CacheCreationTokens+meta.CacheReadTokens+meta.OutputTokens,
		"agent_duration_ms", meta.DurationMs,
	)
	return h.client.Telemetry(req)
}

// classifyServerErr maps an apiclient error into a review.SkipError carrying the
// developer-facing reason, so the engine can surface a non-blocking skip notice
// (and still fail open) without importing apiclient. A reached-but-non-200 reply
// is a StatusError: 401/403 → the license is bad/unentitled; any other status →
// the server faulted. A deadline/timeout → the server was likely reachable but too
// slow (timed_out, distinct so the dev knows the review timed out, not that the
// server is down). Everything else (transport / decode) → unreachable.
func classifyServerErr(err error) error {
	var se *apiclient.StatusError
	if errors.As(err, &se) {
		switch se.Status {
		case http.StatusUnauthorized, http.StatusForbidden:
			return &review.SkipError{Reason: review.SkipUnauthorized, Err: err}
		default:
			return &review.SkipError{Reason: review.SkipServerError, Err: err}
		}
	}
	if errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
		return &review.SkipError{Reason: review.SkipTimedOut, Err: err}
	}
	return &review.SkipError{Reason: review.SkipUnreachable, Err: err}
}

// isTimeout reports whether err is (or wraps) a network timeout (e.g. an i/o
// timeout from the HTTP transport), so a slow server surfaces as timed_out.
func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// findingRuleIDs lists the rule IDs in a finding set (metadata for client logs).
func findingRuleIDs(fs []wire.Finding) []string {
	ids := make([]string, len(fs))
	for i, f := range fs {
		ids[i] = f.Rule
	}
	return ids
}

// changesText joins the changed files into a single body blob (client-log audit
// only; gated by logx.AuditBodies).
func changesText(changes []transcript.Change) string {
	var b strings.Builder
	for _, c := range changes {
		fmt.Fprintf(&b, "### %s\n%s\n\n", c.FilePath, c.AddedText)
	}
	return b.String()
}

// resolveContext resolves the one-hop imported helpers the changed code calls into,
// for EVERY repository the turn touched, each against ITS OWN root.
//
// ⚠️ THE PER-REPOSITORY ROOT IS WHAT MAKES CONTEXT WORK AT ALL IN A WORKSPACE. An
// import resolves relative to the project it was written in, so anchoring on the
// workspace folder reads paths against the wrong base and builds the index over the
// wrong tree.
//
// MEASURED, because an earlier version of this comment claimed more than was true: the
// workspace-anchored variant returns NO context rather than a SIBLING project's file,
// for both a path-based language (Python) and an index-based one (Go) — see
// context_test.go. So this is a quality property, not the cross-project egress bug it
// was first described as. The sibling tests stay anyway: they cost nothing and they
// are what would catch a future resolver that does reach across.
//
// ⚠️ AND THE BYTE BUDGET IS SHARED ACROSS REPOSITORIES. imports.Resolve enforces
// limits.MaxContextTotalBytes per CALL, so resolving per repo would otherwise permit
// N times the cap — the same multiplication the changed-file budget already avoids.
// Trimming here keeps one turn's context bounded however many projects it spans.
//
// Paths come back relative to the repository they were resolved in, so they are
// re-qualified with its directory to match the changed files the judge sees them
// beside. Best-effort throughout: a repo whose root cannot be resolved contributes
// nothing rather than failing the review.
func resolveContext(cwd string, changes []transcript.Change) []wire.ContextFile {
	if len(changes) == 0 {
		return nil
	}
	// Group by repository label, preserving first-seen order so the result is stable,
	// and strip the label prefix: Resolve reads paths relative to the root it is given.
	//
	// ⚠️ THE ROOT COMES OFF THE CHANGE (Change.RepoRoot), NOT FROM cwd/label. A label is
	// a BASENAME — a repository discovered at PreToolUse can live anywhere on the
	// filesystem — so joining it onto cwd resolves nothing for a repo outside cwd and,
	// where cwd holds a same-named project, resolves the WRONG one and egresses that
	// project's code as context. See the note on Change.RepoRoot.
	var order []string
	byRepo := map[string][]transcript.Change{}
	rootOf := map[string]string{}
	for _, c := range changes {
		if _, seen := byRepo[c.RepoDir]; !seen {
			order = append(order, c.RepoDir)
			rootOf[c.RepoDir] = c.RepoRoot
		}
		local := c
		if c.RepoDir != "" {
			local.FilePath = strings.TrimPrefix(c.FilePath, c.RepoDir+"/")
		}
		byRepo[c.RepoDir] = append(byRepo[c.RepoDir], local)
	}

	var out []wire.ContextFile
	total := 0
	for _, rel := range order {
		// No recorded root means the transcript fallback (no git), where cwd is the
		// only directory there is — the behaviour that path always had.
		dir := rootOf[rel]
		if dir == "" {
			if rel != "" {
				continue // labelled but rootless: nothing honest to resolve against
			}
			dir = cwd
		}
		root := vcs.RepoRoot(dir)
		if root == "" {
			continue // not a repository (or git errored) → no context from it
		}
		for _, cf := range imports.Resolve(root, byRepo[rel]) {
			if total+len(cf.Content) > limits.MaxContextTotalBytes {
				slog.Info("cloud: cross-file context budget reached — later repos contribute less",
					"repo", rel, "files_so_far", len(out))
				return out
			}
			total += len(cf.Content)
			if rel != "" {
				cf.Path = rel + "/" + cf.Path
			}
			out = append(out, cf)
		}
	}
	return out
}
