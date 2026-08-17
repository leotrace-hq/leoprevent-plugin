// Package wire is the shared HTTP request/response contract for the leoprevent
// API, used by both the client (apiclient) and the server (api). It lives once
// so the two sides cannot drift.
//
//   - /review  (cloud tier):   code in → findings out. Rules never leave the server.
//   - /rules   (local tier):  rule IDs in → rule content out. No code ever in.
package wire

import "github.com/leotrace-hq/leoprevent-plugin/rulespec"

// ChangedFile is one file changed this turn.
//
//   - AddedText is the code the agent added this turn — what the server selects
//     on (scoped to what changed).
//   - FullContent is OPTIONAL whole-file context (capped) the cloud client sends
//     when it captured changes via the git baseline; the server's judge reasons
//     over it so off-screen guards/sinks are visible. Empty → judge falls back
//     to AddedText (legacy snippet-only behaviour).
type ChangedFile struct {
	Path        string `json:"path"`
	AddedText   string `json:"added_text"`
	FullContent string `json:"full_content,omitempty"`
	// AddedLines are the 1-based line numbers (in FullContent's numbering) the agent
	// ADDED this turn, taken from the git diff hunk headers — POSITIONAL, not content.
	// This is the authority for introduced-vs-pre-existing: it distinguishes two
	// identical lines (a pre-existing line and an added copy of it), which a content
	// match cannot — the copy-paste case where an agent mirrors an existing handler.
	// Absent (nil) when there's no git diff (the transcript fallback) or from an older
	// client → the server then can't positionally anchor and defaults to pre-existing.
	AddedLines []int `json:"added_lines,omitempty"`
}

// ContextFile is an UNCHANGED in-repo file pulled in for cross-file context — a
// local helper the changed code imports and calls, whose body holds the actual
// sink (the indirect-sink blind spot: a reviewer seeing only the changed file
// can't judge a guard/sink that lives one import away). The cloud client resolves
// these on-device (one hop, local symbols only — never stdlib/third-party) and
// sends them alongside Changes. The server shows them to BOTH the selector (so a
// non-telegraphing sink like os.system still shortlists its rule) and the judge,
// LABELED as imported context — so any finding landing here is marked preexisting
// (surfaced to the dev, never force-fixed: the dev didn't change this file).
type ContextFile struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

// ReviewRequest is the POST /review body (cloud tier). It carries only the
// turn-scoped changed code (git diff vs the turn-start baseline; transcript-scoped
// only in the non-git fallback) — never the whole repo — plus optional Context
// (imported local files the change calls into; see ContextFile) and optional
// TurnMeta describing the CODING AGENT's own turn (model, repo, developer, prompt,
// token usage, wall-clock), for the server's analytics. Meta is best-effort: a
// client that can't compute it sends the zero value and review proceeds unchanged.
type ReviewRequest struct {
	Changes []ChangedFile `json:"changes"`
	Context []ContextFile `json:"context,omitempty"`
	Meta    TurnMeta      `json:"meta,omitempty"`
}

// TurnMeta is the coding agent's OWN activity for the turn under review — NOT
// leoprevent's. On `/review` it is captured at the first Stop (pre-re-wake); the
// SAME struct is re-captured at the FINAL Stop and shipped on the OutcomeRequest
// (full-turn token + duration fields) so a blocked turn's cost spans the re-wake.
// The server stamps these onto the audit event so reviews can be sliced
// by developer / repo / agent model — e.g. "which engineer trips the most rules,
// in which app." Prompt is the only BODY field (the developer's text); the server
// drops it (and the diff) on a CLEAN verdict and whenever body logging is off. All
// other fields are metadata, always retained.
type TurnMeta struct {
	Agent      string `json:"agent,omitempty"`       // the coding agent itself: "claude" | "codex" | "copilot" (from --agent; always known)
	AgentModel string `json:"agent_model,omitempty"` // the model, e.g. "claude-opus-4-8" (from the transcript; blank for Copilot — no transcript model)
	Repo       string `json:"repo,omitempty"`        // normalized git origin "host/org/repo" (the "app")
	Developer  string `json:"developer,omitempty"`   // git user "Name <email>" (PII; attribution)
	Prompt     string `json:"prompt,omitempty"`      // BODY: the dev's turn-start prompt; dropped on clean / bodies-off
	// OS/Arch are the DEVELOPER MACHINE's platform, from the client binary's own
	// runtime.GOOS/GOARCH — so they are always known and never parsed (unlike
	// AgentModel, which depends on a transcript). Metadata, not PII: the answer to
	// "which platforms is the plugin actually running on" (and, since we ship ONE
	// windows/amd64 exe that also runs emulated on ARM, "amd64 on ARM Windows" is a
	// real combination worth seeing). They ride /review AND /telemetry, so the
	// platform mix is complete per-turn; deliberately NOT on OutcomeRequest — an
	// outcome is the same machine as its review, so it would add egress and no
	// information.
	OS   string `json:"os,omitempty"`   // "darwin" | "windows" | "linux" (runtime.GOOS)
	Arch string `json:"arch,omitempty"` // "arm64" | "amd64" (runtime.GOARCH)
	// ClientVersion is the plugin build the turn ran on (buildinfo.Version, stamped
	// from plugin/VERSION; "dev" for an unstamped local build). Same character as
	// OS/Arch — compiled in, always known, no transcript needed — and it rides the
	// same routes (/review AND /telemetry, not /outcome: same machine as its review).
	// Without it a support question as basic as "which version was this dev on?" is
	// unanswerable from the event log, which is exactly how a client-side regression
	// stays invisible: every turn looks the same server-side no matter what shipped.
	ClientVersion string `json:"client_version,omitempty"`
	// Environment is the PRODUCT SURFACE this turn ran in — the terminal, the desktop
	// app, a web session — normalized to the closed Env* vocabulary below. Agent alone
	// stops at the VENDOR ("claude"), which cannot answer "did this turn come from the
	// terminal or from claude.ai", so the two are separate dimensions and must stay
	// separable in analysis: Agent x Environment x AgentModel, never one fused string.
	//
	// Same character as OS/Arch/ClientVersion — resolved from the client's own process
	// environment or its hook dialect, never from a transcript, so it needs no parse to
	// succeed — and it rides the same routes (/review AND /telemetry, not /outcome:
	// same machine as its review, so it would be egress with no information).
	//
	// EMPTY means the client is too old to send one. EnvUnknown means a current client
	// looked and could not classify what it found. Those are different facts and the
	// dashboards must not merge them: the first is a rollout gap that fixes itself as
	// clients update, the second is a surface we have not taught the client about.
	Environment string `json:"environment,omitempty"`
	// EnvironmentRaw is the underlying signal VERBATIM and unmapped (for Claude Code,
	// $CLAUDE_CODE_ENTRYPOINT). It exists because the normalized vocabulary is compiled
	// into the client, and the client is the slowest thing in the system to update: when
	// a new surface appears, Environment buckets it as EnvUnknown until a release ships,
	// while this field shows what it actually was from the very first turn. It also makes
	// a misclassification diagnosable from the event log alone, with no repro.
	//
	// Metadata, not PII — a product-surface identifier from a fixed vendor vocabulary.
	// Never a path, a hostname or anything user-authored; see the Env* mapping.
	EnvironmentRaw string `json:"environment_raw,omitempty"`
	// GitBaseline reports whether this turn's changed files came from the git-baseline
	// diff (true) or the DEGRADED transcript fallback (false), and BaselineSkip says
	// WHY when it didn't. The fallback loses full-file context, real line numbers and
	// Bash-write detection, but is otherwise indistinguishable server-side — so a dev
	// silently stuck on it looks identical to one who is fine. The reason matters
	// because the causes have opposite fixes: no baseline recorded (the UserPromptSubmit
	// hook never ran) vs a baseline that existed and git then lost (the dangling stash
	// commit was garbage-collected).
	GitBaseline  bool   `json:"git_baseline,omitempty"`
	BaselineSkip string `json:"baseline_skip,omitempty"`
	// AgentNote is the coding agent's OWN end-of-turn message (last_assistant_message at
	// the FIRST Stop, before any re-wake) — what the agent itself said about the code it
	// wrote, including issues it flagged but chose not to fix. BODY (the agent's text).
	// Used server-side to classify each finding as already-acknowledged by the agent
	// (forcing-lift) vs missed (detection-lift) — the moving-baseline signal. Transient:
	// used for classification, NOT persisted on the review event (only the per-finding
	// bool is). Like Prompt it egresses only on a reviewed turn.
	AgentNote string `json:"agent_note,omitempty"`

	// Token usage summed over the agent's assistant messages this turn. Kept as the
	// four raw counts (not a dollar figure) — pricing varies per model and over
	// time, so cost is computed downstream from these + AgentModel.
	InputTokens         int `json:"input_tokens,omitempty"`
	CacheCreationTokens int `json:"cache_creation_input_tokens,omitempty"`
	CacheReadTokens     int `json:"cache_read_input_tokens,omitempty"`
	OutputTokens        int `json:"output_tokens,omitempty"`

	DurationMs int64  `json:"duration_ms,omitempty"` // agent wall-clock: Stop-hook end − prompt ts (the "crunched for X" interval)
	Speed      string `json:"speed,omitempty"`       // "fast" when Claude Code Fast mode was on → Opus ~2× price tier

	// ContinuesReviewID marks a CONTINUATION batch of a multi-request turn (a change
	// set over the per-request budget spans several /review POSTs). Batches ≥2 carry
	// only the identity dimensions (model/repo/developer) plus this pointer to the
	// FIRST batch's review_id — the event that holds the turn's tokens, duration and
	// prompt — so per-turn cost lands in the audit log exactly once, traceably.
	ContinuesReviewID string `json:"continues_review_id,omitempty"`

	// ResolvedReviewIDs are the origin review_ids whose surfaced pre-existing findings
	// this SAME turn just resolved cross-turn (see OutcomeRequest.Resolution). Set when
	// the dev fixes a previously-surfaced pre-existing vuln a later turn: that turn's
	// /review records these so the (usually clean) review event is identifiable as a
	// RE-REVIEW and linkable back to the triggered review that first flagged them.
	ResolvedReviewIDs []string `json:"resolved_review_ids,omitempty"`
}

// Finding is one confirmed violation from the server's judge.
type Finding struct {
	Rule     string `json:"rule"`           // rule ID that fired
	Name     string `json:"name,omitempty"` // human rule name (e.g. "Server-Side Request Forgery"); server-filled
	Location string `json:"location"`       // file:line
	Issue    string `json:"issue"`          // what's wrong
	Fix      string `json:"fix"`            // the concrete fix to apply
	// Preexisting is true when the judge determined the violation is in code that
	// ALREADY existed (not in the lines added this turn). These are SURFACED to the
	// developer to fix-or-not, never force-fixed in-turn. Absent/false ⇒ introduced
	// this turn ⇒ force-fixed (the safe default if the judge omits it).
	Preexisting bool `json:"preexisting,omitempty"`
	// SuggestOnly is true when the finding's rule is marked `auto_fix: false` in the
	// corpus. Like Preexisting, these are SURFACED to the developer to fix-or-not and
	// never force-fixed in-turn — but for a different reason: the fix itself carries
	// high regression risk (e.g. an nginx / reverse-proxy config rewrite that could
	// break routing), so it is unsafe to auto-apply even for code introduced this
	// turn. Server-filled from the rule's auto_fix flag (the server is the authority).
	// Absent/false ⇒ auto-fix allowed.
	SuggestOnly bool `json:"suggest_only,omitempty"`
	// AgentAcknowledged is true when the coding agent's own end-of-turn message
	// (TurnMeta.AgentNote) already called out THIS issue — server-classified after the
	// judge. true ⇒ forcing-lift (the agent knew and shipped it anyway; leoprevent
	// forced the fix); false ⇒ detection-lift (the agent missed it). Metadata.
	AgentAcknowledged bool `json:"agent_acknowledged,omitempty"`
	// NewlyReached is a BEST-EFFORT label on a PRE-EXISTING finding: the agent's code
	// added this turn appears to newly route into this old sink (new call site → old
	// vulnerable helper). It ONLY enriches the surfaced message ("your new code routes
	// into this existing helper") so the agent can make its OWN new code safe — it
	// NEVER changes Preexisting and NEVER causes a force-fix of the old line. Detection
	// is heuristic (it can miss, and a miss is harmless: the finding still surfaces as a
	// normal pre-existing item). Set only on pre-existing findings; absent otherwise.
	NewlyReached bool `json:"newly_reached,omitempty"`
}

// ClientVersionHeader carries the plugin build that made the request. It lives here,
// in the shared wire package, because both sides now depend on the exact string: the
// client stamps it on every POST, and the server reads it when the BODY could not be
// decoded — the one case where meta.ClientVersion is unavailable and the version is
// the first thing anyone debugging a rejected payload wants to know.
const ClientVersionHeader = "X-LeoPrevent-Client-Version"

// TurnMeta.Environment values — the CLOSED vocabulary the dashboards group on. It
// lives here, in the shared wire package, for the same reason ClientVersionHeader
// does: the client writes these strings and the server + both dashboards read them,
// so a vendor-side spelling change must break the build in one place rather than
// silently split one surface into two rows.
//
// Each value is one PRODUCT SURFACE, agent-prefixed so it reads correctly standing
// alone in a table cell (Agent is a separate column, but a bare "vscode" would be
// ambiguous between Claude Code and Copilot — both have one).
//
// DELIBERATELY SMALL. The mapping's inputs are much larger than this set (Claude
// Code alone ships ~25 entrypoint values), and the temptation is to mint a constant
// per input. Resist it: every value here becomes a row in someone's UI, and the
// surfaces that cannot realistically run a Stop hook — an ephemeral GitHub Actions
// or Slack sandbox, where nobody has installed the plugin — would be rows that are
// always zero. A recognized-but-unmapped input lands on EnvUnknown with
// TurnMeta.EnvironmentRaw carrying what it actually was, which is the honest record
// and costs no UI. Add a constant when the log shows the raw value arriving, not in
// anticipation of it.
const (
	EnvClaudeTerminal = "claude-code-terminal" // the CLI in a terminal
	EnvClaudeDesktop  = "claude-code-desktop"  // the Claude desktop app
	EnvClaudeWeb      = "claude-code-web"      // a remote session driven from claude.ai
	EnvClaudeMobile   = "claude-code-mobile"   // a remote session driven from the mobile app
	EnvClaudeVSCode   = "claude-code-vscode"   // the Claude Code VS Code extension
	EnvClaudeCowork   = "claude-code-cowork"   // Cowork (local-agent / coworker sessions)
	EnvClaudeSDK      = "claude-code-sdk"      // driven programmatically via the Agent SDK or MCP

	EnvCodexCLI  = "codex-cli"  // the Codex CLI's own TUI, via its Stop hook
	EnvCodexExec = "codex-exec" // headless, driven by our own `leoprevent exec` loop

	EnvCopilotVSCode = "copilot-vscode" // GitHub Copilot agent mode inside VS Code
	EnvCopilotCLI    = "copilot-cli"    // the GitHub Copilot CLI

	// EnvUnknown is a CURRENT client that looked and could not classify what it found.
	// It is NOT the same as an absent Environment (a client too old to send one) — see
	// the field doc. Pair it with EnvironmentRaw to tell a brand-new vendor surface
	// apart from no signal at all.
	EnvUnknown = "unknown"
)

// Verdict values for ReviewResponse.
const (
	VerdictClean     = "clean"
	VerdictTriggered = "triggered"
)

// ReviewResponse is the POST /review result: code in, findings out. The rules
// the judge consulted are NOT included — that is the whole point of the tier.
type ReviewResponse struct {
	Verdict string `json:"verdict"` // "clean" | "triggered"
	// Confidence is the judge's self-reported 0-100 confidence in the verdict
	// (50 = coin-flip). Telemetry-only flap-calibration instrumentation — recorded on
	// the audit event, nothing gates on it (it is poorly calibrated).
	Confidence int       `json:"confidence,omitempty"`
	Findings   []Finding `json:"findings,omitempty"`
	// ReviewID correlates a later OutcomeRequest back to this review (server-minted
	// on a triggered review). The client stashes it with the findings + the "before"
	// code and echoes it on /outcome once the agent has (maybe) fixed the diff.
	ReviewID string `json:"review_id,omitempty"`
}

// OutcomeRequest is the POST /outcome body: AFTER leoprevent blocked and re-woke
// the agent, the client reports back what the agent did, so the server can re-judge
// the fix. This is a SYNCHRONOUS, BOUNDED re-verify on the developer's path — the
// client waits up to OutcomeVerifyDeadline for the still-firing findings (then fails
// open), so it can warn the dev in-turn when a fix is still vulnerable. This is how
// "vulns blocked" becomes "vulns actually remediated" + a NO-leoprevent (before) ↔
// WITH-leoprevent (after) diff.
type OutcomeRequest struct {
	ReviewID string `json:"review_id"` // correlates to the ReviewResponse that blocked

	// Resolution marks a CROSS-TURN re-judge of pre-existing findings a PRIOR block
	// surfaced but the dev hadn't fixed yet — fired on a LATER turn that touches those
	// files (not the block→re-wake→stop cycle that produces a normal outcome). The
	// server re-judges exactly the carried-over rules against After and records a
	// dedicated `kind:"resolution"` event crediting only the newly-resolved pre-existing
	// findings (no preexisting_total — that was counted by the original outcome). Keeps
	// the cross-turn fix from double-counting the total or being mistaken for a failed
	// introduced fix. False ⇒ a normal block-outcome re-judge.
	Resolution bool `json:"resolution,omitempty"`

	// Attribution, re-sent so the outcome event is self-contained (the audit log is
	// append-only — the server doesn't look the original up).
	Repo       string `json:"repo,omitempty"`
	Developer  string `json:"developer,omitempty"`
	Agent      string `json:"agent,omitempty"` // "claude" | "codex" | "copilot"
	AgentModel string `json:"agent_model,omitempty"`

	// Before is the vulnerable code the judge flagged (what the client sent to
	// /review); After is the same files now (post-fix). Their diff is the
	// NO_LeoPrevent ↔ With_LeoPrevent delta; After is what the server re-judges.
	Before []ChangedFile `json:"before,omitempty"`
	After  []ChangedFile `json:"after,omitempty"`

	// Findings are the violations the original review fired (rule IDs + preexisting
	// flags). The server re-judges these rules against After to see which cleared.
	Findings []Finding `json:"findings,omitempty"`

	// AgentResponse is the coding agent's final message after the re-wake — its
	// reaction to leoprevent (last_assistant_message from the Stop stdin). When the
	// agent PUSHES BACK, this is the false-positive tuning signal ("this URL is a
	// hardcoded constant…"). A body.
	AgentResponse string `json:"agent_response,omitempty"`

	// Assumptions are the things the agent says it treated as true WITHOUT verifying
	// this turn ("the caller is already authenticated", "this input is validated
	// upstream") — the re-wake prompt asks for them (review.AssumptionsAsk) and the
	// client parses them back out of AgentResponse deterministically, with no model
	// call (review.ParseAssumptions).
	//
	// COLLECTION ONLY. Nothing gates on these and no surface renders them; they exist
	// so the history is there when we want to analyse it, rather than starting cold.
	// Bodies (model-authored prose), so they are logged only when body logging is on.
	//
	// They ride /outcome rather than /review because that is where the ANSWER lands:
	// the ask goes out on the block, and the agent replies during the re-wake, which
	// the client reads at the FINAL Stop. So they are captured only on a turn that
	// blocked, which is the whole population that gets asked.
	Assumptions []string `json:"assumptions,omitempty"`
	// AssumptionsReported distinguishes "the agent answered and had none" (true, empty
	// Assumptions) from "the agent never answered" (false) — a slice with omitempty
	// cannot tell those apart, and they are different facts: the first is a clean empty
	// result, the second is an agent that ignored the ask, was truncated, or ran on a
	// surface with no transcript to read the reply back from (copilot). Same shape and
	// reason as ReviewEvent.AckClassified.
	AssumptionsReported bool `json:"assumptions_reported,omitempty"`

	// Full-turn agent token usage + wall-clock, captured at the FINAL Stop so it
	// SPANS the re-wake fix leoprevent induced. The /review Meta was captured at the
	// FIRST Stop (pre-re-wake) and therefore UNDER-counts a blocked turn; the
	// dashboard uses THESE as the authoritative per-turn cost + latency for a blocked
	// turn (the fix the agent makes after a block IS part of what that agent did).
	// Metadata only — the prompt is NOT re-sent (it already egressed on /review).
	InputTokens         int    `json:"input_tokens,omitempty"`
	CacheCreationTokens int    `json:"cache_creation_input_tokens,omitempty"`
	CacheReadTokens     int    `json:"cache_read_input_tokens,omitempty"`
	OutputTokens        int    `json:"output_tokens,omitempty"`
	DurationMs          int64  `json:"duration_ms,omitempty"`
	Speed               string `json:"speed,omitempty"` // full-turn speed (Fast mode price tier)
}

// OutcomeResponse is the /outcome result. The re-verify now runs SYNCHRONOUSLY (the
// client waits, bounded by OutcomeVerifyDeadline, fail-open) so it can warn the
// developer IN-TURN — before they close the agent — when the agent's fix is still
// vulnerable. IntroducedStillFiring carries the introduced findings the re-judge STILL
// flags (rule + location + issue + fix); empty when the fix is good, or pre-existing-
// only, or the re-verify was skipped (server at capacity). Accepted=true always means
// the outcome was recorded.
type OutcomeResponse struct {
	Accepted bool `json:"accepted"`
	// Scored reports whether the re-judge actually RAN and produced per-finding
	// verdicts. It is false on every no-verdict path — the 202 capacity skip, a
	// server without a model, original rules missing from the corpus, a re-judge
	// failure — all of which return EMPTY still-firing lists that are otherwise
	// indistinguishable from a genuinely clean re-judge. The client must treat an
	// unscored response as "no verdict" (no still-vulnerable notice, cross-turn
	// ledger untouched), never as "everything resolved". Additive: an old server
	// never sets it, so a new client reads its responses as unscored and
	// conservatively under-credits (fail-safe); old clients ignore the field.
	Scored                bool      `json:"scored,omitempty"`
	IntroducedStillFiring []Finding `json:"introduced_still_firing,omitempty"`
	// PreexistingStillFiring carries the PRE-EXISTING findings the re-judge STILL flags
	// against the after-code. The client uses it to seed/update its cross-turn ledger:
	// after the first outcome these are the surfaced pre-existing vulns the dev hasn't
	// fixed yet (so a later turn touching those files can re-judge them); on a resolution
	// call it is the remaining-open set (empty ⇒ all resolved, drop the ledger entry).
	// Excludes any the agent already fixed in-turn, so they are never double-credited.
	PreexistingStillFiring []Finding `json:"preexisting_still_firing,omitempty"`
}

// TelemetryRequest is the POST /telemetry body (cloud tier): the coding agent's
// turn metadata for a turn that did NOT trigger a review, so per-prompt cost /
// latency analytics is complete instead of covering only reviewed turns. The
// client fires it fire-and-forget on the no-review Stop exits (no changed files,
// or an all-inert change the gate dropped). NEVER on the developer's critical path
// — short timeout, fail-open; the server 202s and only appends one audit record
// (no model work).
//
// Reason distinguishes WHY no review ran (analytics: how many turns were no-op vs
// inert), and ChangedFiles is the inert-dropped count (0 for no_change). The
// client DROPS Meta.Prompt before sending — telemetry carries only the dimensions
// (model, repo, developer, tokens, duration), never the dev's text (minimal
// egress; the prompt would be dropped server-side anyway, as on a clean verdict).
type TelemetryRequest struct {
	Meta         TurnMeta `json:"meta"`
	Reason       string   `json:"reason"`                  // "no_change" | "inert"
	ChangedFiles int      `json:"changed_files,omitempty"` // inert-dropped file count (0 for no_change)
}

// Reason values for TelemetryRequest.
const (
	TelemetryNoChange = "no_change" // the turn produced no changed files at all
	TelemetryInert    = "inert"     // changed files existed but were all provably inert (gate-dropped)
)

// TelemetryResponse is the /telemetry ack — the record is appended synchronously
// before this returns, so it only confirms acceptance.
type TelemetryResponse struct {
	Accepted bool `json:"accepted"`
}

// RulesRequest is the POST /rules body (local tier): rule IDs only, never code.
type RulesRequest struct {
	IDs []string `json:"ids"`
}

// RulesResponse returns the requested rule content plus the meta-policy the
// on-device reviewer must apply. Unknown IDs are silently omitted.
type RulesResponse struct {
	Rules      []rulespec.Rule `json:"rules"`
	MetaPolicy string          `json:"meta_policy"`
}
