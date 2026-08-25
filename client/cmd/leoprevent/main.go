// Command leoprevent is the Stop-hook binary for AI coding agents.
//
// One static binary serves every supported agent; the active one MUST be named
// explicitly with --agent (set in each agent's hooks file). There is no implicit
// default — a hook registration that doesn't say which agent it serves is a
// misconfiguration. It reads the hook event from stdin and routes on
// hook_event_name: UserPromptSubmit → snapshot the git baseline (silent); Stop →
// review and (maybe) write a re-wake decision to stdout.
//
//	leoprevent --agent=claude
//	leoprevent --agent=codex
//
// Three explicit CLI actions sit in front of the hook path: `set-license` (store the
// customer key), `exec` (drive a headless agent through the review loop) and `mcp` (serve
// the read tools over the Model Context Protocol on stdio — LEO-88).
//
// The client ships NO rules: leoprevent.json at the plugin root (one dir above the
// binary) sets the server URL and tier (cloud → /review, local → /rules), env-
// overridable via $LEOPREVENT_SERVER_URL/$LEOPREVENT_TIER. Reviewing therefore
// requires a reachable server.
//
// Contract: FAIL OPEN. Any error (missing/unknown --agent, missing/invalid
// config, server unreachable) → log to stderr, exit 0, never block the stop. The
// only thing it may write to stdout on a fail-open path is a NON-BLOCKING skip
// notice ({"systemMessage":…}, no decision) so the developer learns a Stop went
// unreviewed; that still yields. It never emits a blocking re-wake on an error.
package main

import (
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/leotrace-hq/leoprevent-plugin/buildinfo"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/agent"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/agent/claude"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/agent/codex"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/agent/copilot"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/config"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/delivery"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/engine"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/enroll"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/notify"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/review"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/update"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/vcs"
	"github.com/leotrace-hq/leoprevent-plugin/logx"
)

func main() {
	// Fail open against ANY panic: the contract is "a hook error must never trap
	// the developer". This is the backstop so the guarantee doesn't
	// rest on "no code path panics" — recover, note it, exit 0 with no stdout.
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "leoprevent: panic recovered, failing open: %v\n", r)
			os.Exit(0)
		}
	}()

	// NB there is deliberately NO `install`/`uninstall` subcommand: the ONLY install
	// path is the marketplace (`/plugin marketplace add` / `codex plugin marketplace
	// add`), whose hook manifests + bin/ launcher register everything. The binary-side
	// installer was removed so a second, drifting install path can't exist.

	// `set-license` stores the customer key in the per-user config file (survives
	// plugin auto-updates; read by config.Load). Explicit CLI action with human-facing
	// stdout — dispatch before run().
	if len(os.Args) > 1 && os.Args[1] == "set-license" {
		os.Exit(runSetLicense(os.Args[2:]))
	}

	// `exec` is an explicit CLI action too: drive a HEADLESS agent (codex exec /
	// claude -p) through the plugin's review loop, for testing / CI / the eval
	// harness (headless agents fire no Stop hooks). Human-facing output, not the
	// re-wake JSON — so dispatch before run().
	if len(os.Args) > 1 && os.Args[1] == "exec" {
		os.Exit(runExec(os.Args[2:]))
	}

	// `mcp` serves the READ tools over the Model Context Protocol on stdio (LEO-88). It is
	// the one LONG-LIVED path in this binary — the agent starts it from the plugin's
	// .mcp.json and keeps it for the session — and stdout is the JSON-RPC transport, not the
	// re-wake channel, so it must never reach run() below.
	if len(os.Args) > 1 && os.Args[1] == "mcp" {
		os.Exit(runMCP(os.Args[2:]))
	}

	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// run is the hook path, factored out of main so the routing glue is unit-testable
// (main only adds the panic backstop + the install dispatch). ALWAYS returns 0 —
// every error path fails open (logs to stderr, returns 0; the only stdout it may
// emit is a NON-BLOCKING skip notice, never a blocking re-wake). It reads the hook
// event from stdin and routes on hook_event_name:
// UserPromptSubmit → snapshot the git baseline (silent); Stop → review.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	closeLog := logx.Setup("client", false) // file only; stdout is the re-wake channel
	defer closeLog()

	failOpen := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "leoprevent: "+format+" (failing open)\n", a...)
		return 0
	}

	// ContinueOnError (not the global flag.CommandLine, which is ExitOnError): an
	// unexpected flag must fail OPEN, never exit non-zero past main's recover.
	fs := flag.NewFlagSet("leoprevent", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	agentName := fs.String("agent", "", "target agent (required): claude | codex | copilot")
	if err := fs.Parse(args); err != nil {
		slog.Error("flag parse failed; failing open", "err", err.Error())
		return failOpen("%v", err)
	}

	a := newAgent(*agentName)
	if a == nil {
		slog.Error("invalid --agent; failing open", "agent", *agentName)
		return failOpen("--agent must be one of claude|codex|copilot, got %q", *agentName)
	}

	// Read + parse the hook stdin once, then route by event. The same binary is
	// registered for two events: UserPromptSubmit (snapshot the git baseline) and
	// Stop (review). Capture needs no config/server, so route it before that.
	data, err := io.ReadAll(stdin)
	if err != nil {
		slog.Error("read stdin failed; failing open", "err", err.Error())
		return failOpen("read stdin: %v", err)
	}
	ev, err := a.ParseEvent(data)
	if err != nil {
		slog.Error("parse stdin failed; failing open", "err", err.Error())
		return failOpen("parse stdin: %v", err)
	}
	// ⚠️ ROUTED BEFORE THE STOP BRANCH, AND THE ORDER IS THE WHOLE SAFETY PROPERTY.
	// Everything that is not UserPromptSubmit falls through to the review path, so an
	// unhandled PreToolUse would run a selector, a judge and a possible BLOCK on EVERY
	// tool call the agent makes, mid-turn. The manifests register the event, so this
	// branch must exist for as long as they do.
	//
	// It decides nothing and prints nothing: this is repo DISCOVERY, not the PreToolUse
	// hard gate the non-negotiables forbid. Exit 0, no decision, no stdout.
	if ev.IsPreToolUse() {
		// Recording is best-effort by design; a failure costs one repo's baseline and
		// the Stop path still reviews everything it did capture.
		// Every candidate, not the first: a Bash command names its target inside a
		// string, so the paths are a best-effort scavenge in which most entries name
		// nothing (see agent.BashPathCandidates). Recording is idempotent per repo
		// root and returns early for a path outside any repository, so the loop costs
		// one RepoRoot walk per candidate and records at most one section each.
		for _, p := range ev.EditPaths {
			if err := vcs.RecordEditedRepo(p, ev.Cwd, ev.SessionID); err != nil {
				// INFO, not Debug: the client logs at INFO, so a Debug line here made
				// a failed capture indistinguishable from a hook that never ran — the
				// ambiguity that made this event's first live failure unreadable.
				slog.Info("pre-tool-use repo capture failed (continuing)", "err", err.Error(), "path", p)
			}
		}
		return 0
	}
	if ev.IsUserPromptSubmit() {
		if err := vcs.CaptureBaseline(ev.Cwd, ev.SessionID); err != nil {
			slog.Warn("baseline capture failed (review will fall back to transcript)", "err", err.Error())
		} else {
			slog.Debug("git baseline captured", "session", ev.SessionID)
		}
		// UserPromptSubmit is the single-writer, no-decision channel (the Stop path is
		// reserved for the re-wake/notice), so it's where we surface the once-per-day
		// update nag: a prior Stop learned from the server that a newer client is out
		// (see internal/update). Best-effort — a delivery failure just means no nag.
		//
		// Delivered on BOTH channels (DeliverPromptNotice): the systemMessage half is
		// verbatim but terminal-only — it is not forwarded over stream-json, so the
		// desktop app and web UI never see it — while the injected-context half gets
		// the agent to restate the nag in its reply, which every surface renders.
		if latest, ok := update.PendingNag(*agentName, buildinfo.Version); ok {
			slog.Info("newer leoprevent available", "current", buildinfo.Version, "latest", latest)
			environment := a.Environment(ev).Name
			msg := update.Message(*agentName, environment, buildinfo.Version, latest)
			ctx := update.ContextMessage(*agentName, environment, buildinfo.Version, latest)
			if out, derr := a.DeliverPromptNotice(msg, ctx); derr == nil {
				fmt.Fprint(stdout, string(out))
			}
			return 0 // one notice per prompt: don't stack the license nag on top
		}
		// No license key ⇒ every /review 401s ⇒ the client fails open and NOTHING is
		// ever reviewed — silently. That is the same false-assurance the Stop-path skip
		// notice exists to prevent, but it never fires on the desktop app (systemMessage
		// is not forwarded over stream-json), and an unlicensed install has no Stop
		// notice to render anyway. Surface it here, on the same two-channel prompt
		// path as the update nag, throttled once per day per install.
		//
		// Deliberately NOT fatal and NOT a block: a missing license must never trap the
		// developer (the fail-open non-negotiable). Config-load failure is also ignored
		// here — the Stop path already classifies that as SkipMisconfigured.
		if cfg, cerr := config.Load(); cerr == nil && cfg.LicenseKey == "" {
			if update.PendingLicenseNag(*agentName) {
				slog.Info("no license key configured — turns are NOT being reviewed")
				msg := update.LicenseMessage(*agentName)
				ctx := update.LicenseContextMessage(*agentName)
				if out, derr := a.DeliverPromptNotice(msg, ctx); derr == nil {
					fmt.Fprint(stdout, string(out))
				}
			}
		}
		return 0 // capture is silent apart from the (rare) nags: never a re-wake
	}

	// A misconfigured client (unreadable/invalid leoprevent.json, reviewer init
	// failure) silently disables review for EVERY turn — the developer sees a normal
	// "done" and never learns the gate didn't run. Surface a NON-BLOCKING notice on
	// these Stop-path fail-opens (we're past the UserPromptSubmit return, so this is
	// a Stop), so the miss is detectable. Still fail-open, throttled once per session
	// per reason; a notice failure is itself ignored.
	notifyMisconfigured := func() {
		if !notify.FirstThisSession(ev.SessionID, review.SkipMisconfigured.String()) {
			return
		}
		if out, derr := a.DeliverNotice(review.SkipNotice(review.SkipMisconfigured)); derr == nil {
			fmt.Fprint(stdout, string(out))
		}
	}

	cfg, err := config.Load()
	if err != nil {
		slog.Error("config load failed; failing open", "err", err.Error())
		notifyMisconfigured()
		return failOpen("%v", err)
	}
	// ENROLMENT, before the reviewer is built so the very first turn is reviewed rather than the
	// second. A no-op unless an admin pushed an enrolment token and this machine has no key yet;
	// fail-open and at most one attempt per session (see internal/enroll).
	enroll.Ensure(cfg, ev.Cwd, ev.SessionID)

	reviewer, err := delivery.New(cfg)
	if err != nil {
		slog.Error("reviewer init failed; failing open", "err", err.Error())
		notifyMisconfigured()
		return failOpen("%v", err)
	}
	slog.Info("hook invoked", "agent", *agentName, "tier", cfg.Tier, "server_url", cfg.ServerURL)
	return engine.Run(a, reviewer, ev, stdout, stderr)
}

// newAgent maps an --agent value to its adapter, or nil if missing/unknown.
func newAgent(name string) agent.Agent {
	switch name {
	case "claude":
		return claude.New()
	case "codex":
		return codex.New()
	case "copilot":
		return copilot.New()
	default:
		return nil
	}
}
