package main

import (
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/leotrace-hq/leoprevent-plugin/buildinfo"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/config"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/delivery"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/depcheck"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/engine"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/vcs"
	"github.com/leotrace-hq/leoprevent-plugin/logx"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

// `sca` is the session scan on demand (/leoprevent:sca, LEO-819): the first Stop's dependency scan
// is said to no one now, so typing the command is how a developer sees it, in its current form,
// offer included. It sends what the first Stop's scan sends (docs/egress.md). With a session it
// saves the report for that turn's Stop, which shows it and asks the offer's question as the shown
// session scan's are, and prints only the line the agent ends its turn with (engine.AwaitStopLine);
// without one (Copilot, Cursor) it prints the report for the agent to relay. Like every explicit
// action it never reaches run(), and it fails like a command, not like a hook: a reason on stderr
// and exit 1.

func runSca(args []string) int {
	return runScaTo(args, os.Stdout, os.Stderr, scanWith)
}

// scanner runs the scan; a var in tests.
type scanner func(cfg *config.Config, meta *wire.TurnMeta, cwd, session string, log *slog.Logger) (engine.ScanReport, error)

func scanWith(cfg *config.Config, meta *wire.TurnMeta, cwd, session string, log *slog.Logger) (engine.ScanReport, error) {
	r, err := delivery.New(cfg)
	if err != nil {
		return engine.ScanReport{}, err
	}
	c, ok := r.(depcheck.Checker)
	if !ok {
		return engine.ScanReport{}, fmt.Errorf("the dependency scan needs the cloud tier")
	}
	return engine.RunScanReport(c, meta, cwd, session, log, time.Now()), nil
}

func runScaTo(args []string, stdout, stderr io.Writer, scan scanner) int {
	fs := flag.NewFlagSet("sca", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	session := fs.String("session", "", "the session the command was typed in, so an answer to the offer starts the 24-hour quiet")
	agentName := fs.String("agent", defaultScaAgent(), "the agent the command runs in: claude | copilot | cursor")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(stderr, "leoprevent sca: %v\nusage: leoprevent-plugin sca [--session=ID] [--agent=NAME]\n", err)
		return 1
	}
	// An agent that doesn't substitute ${CLAUDE_SESSION_ID} passes it literally (or, through a
	// shell, as nothing): either way there's no session.
	sid := scaSession(*session)

	closeLog := logx.Setup("client", false)
	defer closeLog()

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(stderr, "leoprevent sca: %v\n", err)
		return 1
	}
	if cfg.Tier != config.TierCloud {
		fmt.Fprintln(stderr, "leoprevent sca: the dependency scan needs the cloud tier")
		return 1
	}
	if cfg.LicenseKey == "" {
		fmt.Fprintln(stderr, "leoprevent sca: no license key. Generate one in the dashboard under Plugin setup, then run: leoprevent set-license <key>")
		return 1
	}
	cwd, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(stderr, "leoprevent sca: %v\n", err)
		return 1
	}
	dev, devSource := vcs.DeveloperFrom(cwd)
	meta := &wire.TurnMeta{Agent: *agentName, Repo: vcs.RepoOrigin(cwd), Developer: dev, DeveloperSource: devSource,
		OS: runtime.GOOS, Arch: runtime.GOARCH, ClientVersion: buildinfo.Version}
	rep, err := scan(cfg, meta, cwd, sid, slog.Default())
	if err != nil {
		fmt.Fprintf(stderr, "leoprevent sca: %v\n", err)
		return 1
	}
	if sid != "" && rep.SaveForStop(sid, time.Now()) {
		// The report follows from this turn's Stop hook, which prints it and asks the offer's
		// question as the shown session scan's are (engine.SaveForStop).
		fmt.Fprintln(stdout, engine.AwaitStopLine)
		return 0
	}
	fmt.Fprint(stdout, rep.CommandOutput(newAgent(*agentName)))
	return 0
}

// scaSession is the --session value, or "" when the agent didn't fill it in (the literal
// placeholder) or it couldn't be a session id: it names a file in the plugin's scratch folder.
func scaSession(s string) string {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "$") || strings.ContainsAny(s, "/\\ .") {
		return ""
	}
	return s
}

// defaultScaAgent is the agent the command runs in when --agent isn't given: the command file is
// copied verbatim to every agent, so it can't say. Claude Code sets CLAUDECODE in its Bash tool's
// environment; anything else is recorded as unknown rather than as Claude.
func defaultScaAgent() string {
	if os.Getenv("CLAUDECODE") != "" {
		return "claude"
	}
	return "unknown"
}
