package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/config"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/stats"
	"github.com/leotrace-hq/leoprevent-plugin/logx"
)

// runStats is the `leoprevent stats` subcommand: print the developer's own LeoPrevent
// figures, and the flaws behind them, as the dashboard's own JSON (LEO-248).
//
// ⚠️ THIS IS THE SHIPPED ROUTE TO THE READ API, AND IT EXISTS BECAUSE THE MCP ONE IS NOT.
// `leoprevent mcp` serves the same data as tools (LEO-88) and is withheld from every
// release: a plugin carrying a local MCP server makes Claude Code show "Installing will
// grant access to everything on your computer" to EVERY developer installing LeoPrevent,
// per plugin rather than per feature, with *Disable plugin* as one of its two buttons. A
// slash command declares no server, so it costs that prompt nothing — it reaches this
// binary through Bash exactly as `set-license` and `login` already do. So the reporting
// those tools were built for reaches a marketplace install after all, and the reason the
// tools stay withdrawn is unchanged rather than worked around: see docs/plugins.md.
//
// ⚠️ IT MAY REPORT, NEVER REVIEW. LEO-88's bound holds here word for word: the request
// carries a view name and a few bounded filters, no code and no prompt, so this adds a READ
// and not a disclosure. Nothing here judges anything, and nothing here may ever decide
// whether code is safe — the Stop hook is the forcing function and a command the developer
// has to remember to type could never substitute for it.
//
// ⚠️ THE BODIES ARE PRINTED VERBATIM, labelled by the view they came from and nothing more.
// Rendering prose here would put a second description of every figure inside the shipped,
// open-source client — the one place a change to the dashboard's shape cannot reach — so
// the agent reads the JSON the dashboard computed and writes the summary itself, with the
// vocabulary it needs carried by commands/stats.md. See the note on package `stats`.
//
// It does NOT fail open in the hook's sense, because there is nothing to fail open into: no
// turn is blocked and no developer is trapped. A configuration error is named on stderr and
// exits non-zero, so the agent reports the real reason rather than an empty week.
func runStats(args []string) int {
	fs := flag.NewFlagSet("stats", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	// `days` defaults to 0, which `stats.Query` omits from the request and the API reads as
	// its own default — so the window's default lives in ONE place, beside the clamp that
	// bounds it, rather than in a Go constant that would drift from it silently.
	days := fs.Int("days", 0, "days back to read (API default 30, capped at 365)")
	limit := fs.Int("limit", defaultStatsFindings, "recent findings to list (capped at 100)")
	scope := fs.String("scope", "me", "whose activity to report: me | team")
	repo := fs.String("repo", "", "restrict the findings list to one repository")
	if err := fs.Parse(args); err != nil {
		return statsUsage(err.Error())
	}
	if fs.NArg() > 0 {
		return statsUsage(fmt.Sprintf("unexpected argument %q", fs.Arg(0)))
	}
	// Refused rather than passed through, unlike the API, which reads an unrecognised scope
	// as `me` — the narrow answer being the safe one for a value that arrives over the wire.
	// Here the value is something a person typed, so the same fallback would answer a
	// question about the team with one about the developer and say nothing about having done
	// so. Narrowing a typo into a wrong answer is worse than refusing it.
	if *scope != "me" && *scope != "team" {
		return statsUsage(fmt.Sprintf("--scope must be me or team, got %q", *scope))
	}

	// File only, like every other path here: stdout carries the JSON document, so a stray
	// log line would corrupt what the agent parses rather than merely being noisy.
	closeLog := logx.Setup("client", false)
	defer closeLog()

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "leoprevent stats: %v\n", err)
		return 1
	}
	if cfg.DashboardURL == "" {
		// Named rather than defaulted, for the reason on Config.DashboardURL: a compiled-in
		// origin would point one deployment's developers at another's dashboard and answer
		// plausibly. An install predating the field lands here, which is correct.
		fmt.Fprintf(os.Stderr,
			"leoprevent stats: dashboard_url is not set (add it to %s or set $%s)\n",
			config.FileName, config.EnvDashboardURL)
		return 1
	}
	if cfg.LicenseKey == "" {
		fmt.Fprintln(os.Stderr,
			"leoprevent stats: no license key. Generate one in the dashboard under Plugin setup, "+
				"then run: leoprevent set-license <key>")
		return 1
	}

	client := stats.New(cfg.DashboardURL, cfg.LicenseKey)

	// Concurrently, because these are two round trips to the same function and a developer is
	// watching a spinner for the sum of them otherwise.
	var overview, findings statsRead
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		overview = readView(client, stats.Query{View: "stats", Scope: *scope, Days: *days})
	}()
	go func() {
		defer wg.Done()
		findings = readView(client, stats.Query{
			View: "findings", Scope: *scope, Days: *days, Limit: *limit, Repo: *repo,
		})
	}()
	wg.Wait()

	// ⚠️ A HALF ANSWER IS NOT PRINTED. Both reads share a credential and an endpoint, so one
	// failing usually means both did — but a document carrying figures and an empty findings
	// list would read as a clean period, which is the false all-clear this product exists to
	// avoid. Either the whole summary is true or the developer is told why there isn't one.
	for _, r := range []statsRead{overview, findings} {
		if r.err != nil {
			fmt.Fprintf(os.Stderr, "leoprevent stats: %v\n", r.err)
			return 1
		}
		// A 200 carrying something that is not JSON is an edge proxy or a captive portal, not
		// the API. Saying so beats the opaque marshal failure the encoder would raise.
		if !json.Valid(r.body) {
			fmt.Fprintln(os.Stderr,
				"leoprevent stats: the dashboard returned a body that is not JSON")
			return 1
		}
	}

	out, err := json.MarshalIndent(statsReport{
		Stats:    overview.body,
		Findings: findings.body,
	}, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "leoprevent stats: %v\n", err)
		return 1
	}
	fmt.Println(string(out))
	return 0
}

// defaultStatsFindings is how many recent flaws the command lists.
//
// Lower than the API's own default of 20, deliberately: this command is billed as a quick
// summary and every row costs context the developer pays for. It is a choice about
// verbosity and defines no figure — `matched` and `truncated` in the body state what was
// left out, so a short list can never read as a quiet period. `--limit` raises it, and the
// API clamps at 100.
const defaultStatsFindings = 10

// statsReport is the document printed to stdout: the two bodies, labelled, unaltered.
//
// `json.RawMessage` rather than decoded structs — the shapes are defined once, in the
// TypeScript that computes them, and a Go mirror would drop a new field out of the answer
// with nothing failing.
type statsReport struct {
	Stats    json.RawMessage `json:"stats"`
	Findings json.RawMessage `json:"findings"`
}

type statsRead struct {
	body json.RawMessage
	err  error
}

func readView(c *stats.Client, q stats.Query) statsRead {
	body, err := c.Read(q)
	return statsRead{body: json.RawMessage(body), err: err}
}

// statsUsageLine names every flag, so a refusal is a complete answer rather than one
// correction and a guess at what else the command takes.
const statsUsageLine = "usage: leoprevent stats [--days N] [--limit N] [--scope me|team] [--repo NAME]"

func statsUsage(msg string) int {
	fmt.Fprintf(os.Stderr, "leoprevent stats: %s\n", msg)
	fmt.Fprintln(os.Stderr, statsUsageLine)
	return 2
}
