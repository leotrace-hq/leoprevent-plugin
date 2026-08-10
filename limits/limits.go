// Package limits holds the size caps and deadlines the CLIENT enforces, plus the
// one deadline the client and server must agree on (OutcomeVerifyDeadline).
//
// It lives in the plugin module — the open-sourceable half — because the shipped
// binary is built from this module alone. The server-only values (model IDs, the
// corpus source, SelectTimeout/JudgeTimeout, and the server-side render caps
// MaxPayloadBytes/MaxFileAddedBytes/MaxFileFullBytes/MaxRequestBytes) stay in the
// private root `leoprevent` package; the server imports THIS package for the
// values it shares with the client.
//
// Like the root package, these are git-tracked CONSTANTS, not env knobs: changing
// one is a reviewed PR and a rebuild, which is the right ceremony for a
// correctness choice that must hold identically on both sides of the wire.
//
// The cross-module invariants (a batch must fit the server's render cap, a single
// file must fit a batch, the rendered max must fit the model's token window) are
// enforced by TestPayloadCapFitsTokenWindow in the root module's config_test.go,
// which imports this package precisely so the split cannot silently break them.
package limits

import "time"

// Deadlines. The Stop-hook timeout is 600s (plugin/hooks/*.json): it must exceed
// the worst legitimate turn — a cross-turn resolution pass (≤ OutcomeVerifyDeadline
// total, engine.resolveLedger) followed by the /review (≤ ClientReviewDeadline)
// ≈ 525s — so the client's fail-open deadlines always fire before the agent kills
// the hook (a killed hook can't print the skip notice → silently unreviewed turn).
// Changing these means re-checking that ordering against the server's SelectTimeout
// / JudgeTimeout / HTTPClientCeiling in the root package.
const (
	// ClientReviewDeadline is when the client cancels /review (apiclient).
	ClientReviewDeadline = 345 * time.Second

	// OutcomeVerifyDeadline bounds the SYNCHRONOUS /outcome re-verify at the second
	// Stop: the client waits this long for the server to re-judge the agent's fix and
	// fails OPEN past it (allow the stop, no notice). It's on the dev's path (only on a
	// blocked-and-fixed turn) — but deliberately GENEROUS so a legitimate-but-slow
	// re-review is NOT cut short, which would silently drop the "your fix is still
	// vulnerable" warning: the re-judge is a single OutcomeJudgeModel (Opus) pass
	// (adjudicateSamples=1 since fa8a37e; was a 3× concurrent majority vote), up to
	// 16384 output tokens — 90s demonstrably cut off large-after-file cases. The
	// timeout exists to fail-open on an UNREACHABLE/dead server, not to cap a
	// slow-but-valid re-review. It also caps the WHOLE cross-turn resolution pass
	// (engine.resolveLedger's total budget), which the 600s Stop-hook timeout is sized
	// for (resolution + ClientReviewDeadline + margin). Sits under the server's
	// JudgeTimeout (so the client, not the judge, is the bound). Worst case the dev
	// waits this on a hang.
	//
	// SHARED: the server bounds its in-handler re-verify by the same value, so this
	// is the one constant here that both deployables read.
	OutcomeVerifyDeadline = 180 * time.Second
)

// Client-side size caps. A GARBAGE/DoS guard sized so a legitimate large change plus
// its imported context fits the MODEL CONTEXT WINDOW, NOT a throttle on real code.
// Over budget a turn degrades gracefully: per file the added lines are always kept,
// then full-file context, then imported context trims FIRST — the change under
// review is never dropped. The server re-bounds whatever the client sends.
const (
	// Client (vcs) — bound the whole-file context GATHERED per turn (added text is
	// never capped here). Kept ≈ the server render cap so we don't egress bytes the
	// server then trims.
	MaxChangedFileBytes  = 112 * 1024 // per changed file's full-file context (~2.7k lines)
	MaxChangedTotalBytes = 256 * 1024 // full-file context across the turn (≈ the render cap)

	// Client (imports) — bound the cross-file imported context (lowest priority; trims first).
	MaxContextFileBytes  = 112 * 1024 // per imported helper
	MaxContextTotalBytes = 128 * 1024 // total imported context (changed + this batched under the cap)

	// Client (delivery) — request-size budgets. The per-batch budget sits UNDER the
	// server's render cap (MaxPayloadBytes) with margin for the server-side line
	// numbering + section headers, so the CHANGED FILES of a batch the client sends
	// always render in full for the model — a budget above the render cap opened a
	// "sent but not judged" window where trailing files were silently omitted
	// server-side. A turn larger than one batch splits across several /review POSTs
	// (each its own model call, within the window); imported context still trims first
	// when batch+context exceed the render cap, and the server logs any omission.
	MaxReviewBytes     = 192 * 1024 // per /review request batch (< render cap, margin for line numbers)
	MaxSingleFileBytes = 192 * 1024 // single-file ceiling before last-resort truncation (fits one batch)

	// Client (transcript) — bound the agent's post-re-wake reply shipped as
	// /outcome's agent_response. It is a BODY that egresses and is persisted, and
	// since it became the whole post-re-wake segment rather than one message its
	// length is the agent's to choose, not ours — so it needs a ceiling of its own.
	// 32 KiB is ~8k tokens: generous for any real reply (the recorded ones run 1–4 KB),
	// small enough that a runaway agent cannot dominate an /outcome request.
	MaxAgentReplyBytes = 32 * 1024
)
