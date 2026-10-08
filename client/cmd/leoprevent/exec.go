package main

import (
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/clirun"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/config"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/delivery"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

// runExec is the `leoprevent exec` subcommand: run a HEADLESS agent (codex exec /
// claude -p) through the real leoprevent review loop, from the CLI. It faithfully
// reproduces a developer using the agent WITH the plugin — same baseline → diff →
// review → re-wake → fix cycle — but driven here, because headless agents fire no
// Stop hooks. For testing / CI / the eval harness.
//
//	leoprevent exec --agent codex -- "add a /fetch route"
//	leoprevent exec --agent claude --max-rounds 4 -- "implement password reset"
//	leoprevent exec --agent-cmd "codex exec --model gpt-5" -- "..."   # override the invocation
func runExec(args []string) int {
	fs := flag.NewFlagSet("exec", flag.ContinueOnError)
	agentName := fs.String("agent", "codex", "agent to drive: codex | claude | copilot")
	maxRounds := fs.Int("max-rounds", 3, "max agent invocations before giving up")
	cwdFlag := fs.String("cwd", "", "working dir (default: current dir); must be a git repo")
	agentCmd := fs.String("agent-cmd", "", "override the agent invocation (space-separated); the prompt is appended as the final arg")
	strict := fs.Bool("strict", false, "exit non-zero if findings remain after --max-rounds")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	prompt := strings.TrimSpace(strings.Join(fs.Args(), " "))
	if prompt == "" {
		fmt.Fprintln(os.Stderr, "usage: leoprevent exec [flags] <prompt>\n  reproduces a dev using the agent with the plugin, headlessly (see --help)")
		fs.SetOutput(os.Stderr)
		fs.PrintDefaults()
		return 2
	}

	cwd := *cwdFlag
	if cwd == "" {
		wd, err := os.Getwd()
		if err != nil {
			fmt.Fprintf(os.Stderr, "leoprevent exec: cwd: %v\n", err)
			return 2
		}
		cwd = wd
	}

	argv, err := agentArgv(*agentName, *agentCmd)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	// Same config + reviewer the hook uses (server_url + tier from leoprevent.json).
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "leoprevent exec: config: %v\n", err)
		return 2
	}
	reviewer, err := delivery.New(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "leoprevent exec: reviewer: %v\n", err)
		return 2
	}

	fmt.Fprintf(os.Stderr, "leoprevent exec: driving %q through the plugin loop (tier=%s, server=%s, max-rounds=%d)\n",
		strings.Join(argv, " "), cfg.Tier, cfg.ServerURL, *maxRounds)

	opts := clirun.Options{
		Cwd:         cwd,
		Prompt:      prompt,
		Agent:       *agentName,
		Environment: execEnvironment(*agentName),
		MaxRounds:   *maxRounds,
		Run:         clirun.ExecRunner(argv),
		Out:         os.Stderr,
	}
	// For Codex, recover the agent's own model/tokens/duration from the rollout it
	// writes (the headless loop has no transcript path to hand the reviewer).
	if isCodexArgv(argv) {
		opts.RolloutMeta = codexRolloutMeta
	}
	res, err := clirun.Loop(reviewer, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "leoprevent exec: %v\n", err)
		return 2
	}
	if !res.Clean && *strict {
		return 1
	}
	return 0
}

// execEnvironment names the product surface these turns are attributed to. This
// subcommand drives the agent HEADLESSLY, so the surface is the exec loop, not the
// agent's own interactive runtime — the two must not merge, or a CI/eval run's turns
// would be indistinguishable from a developer's in the analytics they exist to feed.
//
// Only Codex has a distinct exec surface today. `claude -p` and the Copilot CLI both
// export or infer their own surface on the hook path; here there is no hook and no
// signal, so they stay unattributed (empty) rather than being assigned a plausible
// one — an absent value reads as "we don't know", which is true, while a guess would
// read as a measurement.
func execEnvironment(agentName string) string {
	if agentName == "codex" {
		return wire.EnvCodexExec
	}
	return ""
}

// agentArgv resolves the agent command: an explicit --agent-cmd override, else a
// per-agent default. The task / re-wake prompt is appended as the final argument.
func agentArgv(agent, override string) ([]string, error) {
	if o := strings.Fields(override); len(o) > 0 {
		return o, nil
	}
	switch agent {
	case "codex":
		// Headless Codex must be able to apply edits. `codex exec` defaults to a
		// read-only sandbox, so without this it produces an empty diff (no feature
		// written) and the review loop sees nothing to fix. workspace-write lets it
		// edit the repo non-interactively (exec's approval policy is already "never").
		return []string{"codex", "exec", "--sandbox", "workspace-write"}, nil
	case "claude":
		// Headless Claude needs to apply edits without an interactive prompt.
		return []string{"claude", "-p", "--permission-mode", "acceptEdits"}, nil
	case "copilot":
		// Headless Copilot CLI: --allow-all-tools approves edits non-interactively,
		// -p takes the prompt (appended as the final arg by ExecRunner). NB flags
		// taken from Copilot's own docs but not yet live-verified.
		return []string{"copilot", "--allow-all-tools", "-p"}, nil
	default:
		return nil, fmt.Errorf("leoprevent exec: --agent must be codex|claude|copilot (got %q); or pass --agent-cmd", agent)
	}
}

// isCodexArgv reports whether the resolved agent command is Codex (so we should
// recover its turn meta from the rollout). Covers the default and an --agent-cmd
// override that still drives codex.
func isCodexArgv(argv []string) bool {
	for _, a := range argv {
		if strings.Contains(a, "codex") {
			return true
		}
	}
	return false
}

// codexRolloutMeta parses the turn meta from the rollout codex exec wrote this round
// (the newest under $CODEX_HOME/sessions, modified at/after the round start). Returns
// zero meta if it can't find or parse one — best-effort, never fails the loop.
func codexRolloutMeta(since time.Time) wire.TurnMeta {
	p := newestCodexRollout(since)
	if p == "" {
		return wire.TurnMeta{}
	}
	m, err := transcript.ParseCodexTurnMeta(p)
	if err != nil {
		return wire.TurnMeta{}
	}
	return wire.TurnMeta{
		AgentModel:          m.AgentModel,
		Prompt:              m.Prompt,
		InputTokens:         m.InputTokens,
		CacheCreationTokens: m.CacheCreationTokens,
		CacheReadTokens:     m.CacheReadTokens,
		OutputTokens:        m.OutputTokens,
		DurationMs:          m.DurationMs,
		Speed:               m.Speed,
	}
}

// codexHome resolves Codex's home dir ($CODEX_HOME, else ~/.codex).
func codexHome() string {
	if h := os.Getenv("CODEX_HOME"); h != "" {
		return h
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".codex")
}

// newestCodexRollout returns the most-recently-modified rollout-*.jsonl under
// <codexHome>/sessions, provided it was touched at/after `since` (so we pick THIS
// round's run, not a stale session). "" if none qualifies. Single-exec invocation,
// so no concurrent-session race in practice.
func newestCodexRollout(since time.Time) string {
	root := filepath.Join(codexHome(), "sessions")
	var best string
	var bestT time.Time
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil //nolint:nilerr // skip unreadable subtrees, keep walking
		}
		name := d.Name()
		if !strings.HasPrefix(name, "rollout-") || !strings.HasSuffix(name, ".jsonl") {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		if info.ModTime().After(bestT) {
			bestT, best = info.ModTime(), p
		}
		return nil
	})
	// Reject a stale rollout (a previous session) — this round must have written it.
	if best != "" && bestT.Before(since.Add(-2*time.Second)) {
		return ""
	}
	return best
}
