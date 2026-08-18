// Package clirun drives a HEADLESS agent (codex exec / claude -p) through the
// SAME review loop the Stop hook runs in an interactive session. It is a faithful
// reproduction of "a developer using the agent with the leoprevent plugin",
// driven from the CLI instead of by a hook — for testing, CI, and the eval
// harness, where Stop hooks don't fire (codex exec is TUI-hook-less).
//
// Faithfulness is by REUSE, not re-implementation: it calls the exact same
// vcs.CaptureBaseline / vcs.ChangedFiles, gate.Run, and engine.Reviewer the hook
// path uses. The only difference is the loop is driven here (run the agent, then
// re-run it with the re-wake) rather than the agent re-waking itself in-turn.
package clirun

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/leotrace-hq/leoprevent-plugin/buildinfo"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/engine"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/gate"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/outcome"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/vcs"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

// AgentRunner runs the agent ONCE with prompt in cwd, streaming its output to out.
// Injectable so tests drive a fake agent instead of a real binary.
type AgentRunner func(cwd, prompt string, out io.Writer) error

// ExecRunner returns an AgentRunner that shells out to argv with the prompt
// appended as the final argument (e.g. argv ["codex","exec"] → `codex exec <prompt>`),
// run in cwd with output streamed to out.
func ExecRunner(argv []string) AgentRunner {
	return func(cwd, prompt string, out io.Writer) error {
		args := append(append([]string{}, argv[1:]...), prompt)
		cmd := exec.Command(argv[0], args...)
		cmd.Dir = cwd
		cmd.Stdout = out
		cmd.Stderr = out
		return cmd.Run()
	}
}

// Options configures one headless review loop.
type Options struct {
	Cwd    string // working dir (must be a git repo)
	Prompt string // the developer's task
	Agent  string // the coding agent being driven ("codex" | "claude" | "copilot"), for attribution
	// Environment is the wire.Env* surface to attribute these turns to. This loop is
	// NOT the agent's own hook path — it drives the agent headlessly — so it is a
	// distinct surface from the TUI even for the same vendor (wire.EnvCodexExec vs
	// wire.EnvCodexCLI), and the caller names it rather than the loop inferring it
	// from Agent. Empty is left as-is: an unattributed turn, never a guess.
	Environment string
	MaxRounds   int         // safety cap on agent invocations (>=1)
	Run         AgentRunner // how to invoke the agent
	Out         io.Writer   // human-facing progress

	// RolloutMeta, if set, recovers the agent's own turn metadata (model, tokens,
	// duration, prompt) AFTER a round's run — for codex exec, by parsing the rollout
	// the run just wrote (which has no transcript_path the loop could know up front).
	// `since` is the round's start time, so the enricher can pick the rollout written
	// by THIS round. Returns zero meta if it can't find/parse one (best-effort).
	RolloutMeta func(since time.Time) wire.TurnMeta
}

// Result reports the loop outcome.
type Result struct {
	Clean  bool // the final state passed review (no findings)
	Rounds int  // agent invocations made
}

// Loop reproduces the plugin's per-turn review cycle headlessly. ONE baseline is
// captured up front — the equivalent of the Stop hook's UserPromptSubmit snapshot
// — then each round runs the agent and reviews the CUMULATIVE diff vs that baseline
// (what the hook sees at each Stop), re-feeding the re-wake to the agent exactly as
// the hook re-wakes it in-turn, until the diff is clean or MaxRounds is hit.
func Loop(r engine.Reviewer, opts Options) (Result, error) {
	if opts.MaxRounds < 1 {
		opts.MaxRounds = 1
	}
	session := fmt.Sprintf("cli-%d", os.Getpid())
	if err := vcs.CaptureBaseline(opts.Cwd, session); err != nil {
		return Result{}, fmt.Errorf("baseline capture (need a git repo): %w", err)
	}
	defer vcs.ClearBaseline(session)

	// Outcome state, carried across rounds so we can ship ONE /outcome after the loop —
	// exactly as engine.Run does at the final Stop. firstPending is the ORIGINAL block
	// (the first round that fired): its findings + before-code are what the server
	// re-judges against the agent's final fix. lastChanges/lastMeta/lastResp are the
	// FINAL round's cumulative diff, turn meta, and agent reply (the after-state).
	var firstPending *outcome.Pending
	var lastChanges []transcript.Change
	var lastMeta wire.TurnMeta
	var lastResp string

	// shipOutcome fires the /outcome re-verify ONCE (take-once, mirroring engine), if a
	// block ever fired. Fail-open: any error just means no outcome, never a failed run.
	shipOutcome := func() {
		if firstPending == nil {
			return
		}
		introStillFiring, _, err := r.ShipOutcome(*firstPending, lastChanges, lastResp, lastMeta)
		firstPending = nil // ship at most once
		switch {
		case err != nil:
			fmt.Fprintf(opts.Out, "outcome ship failed (ignored): %v\n", err)
		case len(introStillFiring) > 0:
			fmt.Fprintf(opts.Out, "⚠️  re-verify: %d introduced finding(s) still firing after the fix\n", len(introStillFiring))
		default:
			fmt.Fprintln(opts.Out, "✅ outcome shipped: fix re-verified clean")
		}
	}

	prompt := opts.Prompt
	for round := 1; round <= opts.MaxRounds; round++ {
		fmt.Fprintf(opts.Out, "\n── round %d ─ running agent ──\n", round)
		roundStart := time.Now()
		// Tee the agent's output: stream to the human-facing Out AND capture this round's
		// text so the LAST round's reply rides /outcome as agent_response (the FP-tuning
		// signal — the hook path uses ev.LastAssistantMessage here).
		var roundOut bytes.Buffer
		if err := opts.Run(opts.Cwd, prompt, io.MultiWriter(opts.Out, &roundOut)); err != nil {
			return Result{Rounds: round}, fmt.Errorf("agent run failed: %w", err)
		}

		changes, ok, skip, err := vcs.ChangedFiles(opts.Cwd, session)
		if err != nil || !ok {
			fmt.Fprintf(opts.Out, "⚠️  no git baseline, cannot review (need a git repo); stopping (%s)\n", skip)
			return Result{Rounds: round}, nil
		}
		reviewable := gate.Run(changes)
		// Git-derived attribution (repo, developer) + this round's prompt always; the
		// agent's OWN model/tokens/duration come from RolloutMeta when wired (codex
		// exec parses the rollout it just wrote), else stay zero.
		meta := wire.TurnMeta{
			Agent:     opts.Agent,
			Repo:      vcs.RepoOrigin(opts.Cwd),
			Developer: vcs.Developer(opts.Cwd),
			OS:        runtime.GOOS,   // this machine's platform (parity with the hook path)
			Arch:      runtime.GOARCH, // NB amd64 on ARM Windows: one x64 exe, emulated
			Prompt:    prompt,

			ClientVersion: buildinfo.Version, // parity with the hook path
			Environment:   opts.Environment,  // the headless loop, not the agent's own TUI
			GitBaseline:   true,              // this loop bails above unless the git path worked
		}
		if opts.RolloutMeta != nil {
			rm := opts.RolloutMeta(roundStart)
			meta.AgentModel = rm.AgentModel
			meta.InputTokens = rm.InputTokens
			meta.CacheCreationTokens = rm.CacheCreationTokens
			meta.CacheReadTokens = rm.CacheReadTokens
			meta.OutputTokens = rm.OutputTokens
			meta.DurationMs = rm.DurationMs
			meta.Speed = rm.Speed
			if rm.Prompt != "" {
				meta.Prompt = rm.Prompt // the agent's actual recorded prompt, if captured
			}
		}
		// Remember this round's after-state for the post-loop /outcome re-verify.
		lastChanges, lastMeta, lastResp = changes, meta, roundOut.String()

		res, err := r.Review(opts.Cwd, reviewable, meta)
		rewake := res.Prompt
		if err != nil {
			// Fail-open, exactly like the hook: a review error never traps the loop. Ship
			// any pending outcome first (best-effort) so a block earlier in the loop still
			// records its remediation.
			fmt.Fprintf(opts.Out, "review error (failing open): %v\n", err)
			shipOutcome()
			return Result{Clean: true, Rounds: round}, nil
		}
		// Capture the FIRST block's pending (the original findings + before-code) so the
		// post-loop /outcome re-judges the agent's final fix against it. r.Review already
		// builds it; the hook path stashes it across Stops, the loop just holds it.
		if rewake != "" && firstPending == nil && res.Pending != nil {
			firstPending = res.Pending
		}
		if rewake == "" {
			fmt.Fprintf(opts.Out, "✅ clean after %d round(s)\n", round)
			shipOutcome() // ship the verified-fix outcome (no-op if nothing ever blocked)
			return Result{Clean: true, Rounds: round}, nil
		}
		fmt.Fprintf(opts.Out, "🔒 leoprevent findings (round %d):\n%s\n", round, rewake)
		prompt = rewake // re-wake the agent with the findings (what the hook injects)
	}
	fmt.Fprintf(opts.Out, "⚠️  findings remain after %d round(s); stopping\n", opts.MaxRounds)
	shipOutcome() // even unresolved: record the (still-firing) outcome for analytics
	return Result{Clean: false, Rounds: opts.MaxRounds}, nil
}
