package main

import (
	"fmt"
	"os"

	"github.com/leotrace-hq/leoprevent-plugin/buildinfo"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/config"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/mcp"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/stats"
	"github.com/leotrace-hq/leoprevent-plugin/logx"
)

// runMCP is the `leoprevent mcp` subcommand: serve the READ tools to a coding agent over
// the Model Context Protocol on stdio (LEO-88).
//
// The agent starts this itself — the plugin's `.mcp.json` names it, so a developer who
// installed LeoPrevent from the marketplace gets the tools with no extra configuration and
// no second credential. That is deliberate and it is most of the answer to the ticket's
// other half (how anyone finds out this exists): a setup step nobody has to take is one
// nobody has to be taught.
//
// ⚠️ IT IS A LONG-LIVED PROCESS, WHICH NOTHING ELSE IN THIS BINARY IS. Every other path
// here is a hook invocation that reads stdin once and exits; this one runs for the length
// of the agent session. Two consequences worth stating: stdout is the TRANSPORT (so, as on
// the hook path, nothing but protocol messages may be written to it — diagnostics go to
// client.log), and the config is resolved ONCE at start, so a license key set with
// `set-license` mid-session is picked up on the next session rather than immediately. The
// same is true of the hook, which re-reads per invocation; here it is worth knowing because
// the window is longer.
//
// It does NOT fail open in the hook's sense, because there is nothing to fail open INTO: no
// turn is blocked and no developer is trapped. A configuration error is reported to stderr
// and exits non-zero, which is what makes an agent show "server failed to start" rather
// than a set of tools that answer nothing.
func runMCP(args []string) int {
	if len(args) > 0 {
		fmt.Fprintln(os.Stderr, "usage: leoprevent mcp   (reads MCP JSON-RPC on stdin)")
		return 2
	}

	// File only, like the hook — stdout carries JSON-RPC here, so a stray log line would
	// corrupt the transport rather than merely being noisy.
	closeLog := logx.Setup("client", false)
	defer closeLog()

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "leoprevent mcp: %v\n", err)
		return 1
	}
	if cfg.DashboardURL == "" {
		// Named rather than defaulted, for the reason on Config.DashboardURL: a compiled-in
		// origin would point one deployment's developers at another's dashboard and answer
		// plausibly. An install predating this feature lands here, which is correct — it also
		// has no `.mcp.json`, so nothing starts this in the first place.
		fmt.Fprintf(os.Stderr,
			"leoprevent mcp: dashboard_url is not set (add it to %s or set $%s)\n",
			config.FileName, config.EnvDashboardURL)
		return 1
	}
	if cfg.LicenseKey == "" {
		// Worth refusing rather than serving tools that will 401 on every call: the developer
		// gets one clear message at startup instead of the same refusal repeated inside every
		// answer the agent gives them.
		fmt.Fprintln(os.Stderr,
			"leoprevent mcp: no license key. Generate one in the dashboard under Plugin setup, "+
				"then run: leoprevent set-license <key>")
		return 1
	}

	srv := &mcp.Server{
		Tools:   mcp.Tools(),
		Call:    mcp.Dispatch(stats.New(cfg.DashboardURL, cfg.LicenseKey)),
		Version: buildinfo.Version,
	}
	if err := srv.Serve(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "leoprevent mcp: %v\n", err)
		return 1
	}
	return 0
}
