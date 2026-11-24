package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/config"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/stats"
	"github.com/leotrace-hq/leoprevent-plugin/logx"
)

const defaultOpenFindings = 20

const findingsUsageLine = "usage: leoprevent findings [--all] [--days N] [--limit N] [--scope me|team] [--repo NAME] [--rule ID]\n" +
	"       leoprevent findings ignore|resolve <id> --reason TEXT [--scope me|team]\n" +
	"       leoprevent findings reopen <id> [--scope me|team]"

var triageVerbs = map[string]string{
	"ignore":  "ignored",
	"resolve": "resolved",
	"reopen":  "open",
}

func runFindings(args []string) int {
	closeLog := logx.Setup("client", false)
	defer closeLog()
	if len(args) > 0 {
		if state, ok := triageVerbs[args[0]]; ok {
			return runFindingsTriage(args[0], state, args[1:])
		}
	}
	return runFindingsList(args)
}

func runFindingsList(args []string) int {
	fs := flag.NewFlagSet("findings", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	all := fs.Bool("all", false, "list every finding, not only the open undecided ones")
	days := fs.Int("days", 0, "days back to read (default: all time for open findings, 30 with --all)")
	limit := fs.Int("limit", defaultOpenFindings, "findings to list (capped at 100)")
	scope := fs.String("scope", "me", "whose findings: me | team")
	repo := fs.String("repo", "", "restrict to one repository")
	rule := fs.String("rule", "", "restrict to one rule id")
	if err := fs.Parse(args); err != nil {
		return findingsUsage(err.Error())
	}
	if fs.NArg() > 0 {
		return findingsUsage(fmt.Sprintf("unexpected argument %q", fs.Arg(0)))
	}
	if *scope != "me" && *scope != "team" {
		return findingsUsage(fmt.Sprintf("--scope must be me or team, got %q", *scope))
	}

	client, code := findingsClient()
	if client == nil {
		return code
	}
	body, err := client.Read(stats.Query{
		View:    "findings",
		Scope:   *scope,
		Days:    *days,
		AllTime: !*all && *days == 0,
		Repo:    *repo,
		Rule:    *rule,
		Limit:   *limit,
		Open:    !*all,
	})
	return printFindingsBody(body, err)
}

func runFindingsTriage(verb, state string, args []string) int {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return findingsUsage(fmt.Sprintf("%s needs a finding id first", verb))
	}
	id := strings.TrimSpace(args[0])
	fs := flag.NewFlagSet("findings "+verb, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	reason := fs.String("reason", "", "why: required to ignore or resolve")
	scope := fs.String("scope", "me", "whose findings: me | team")
	if err := fs.Parse(args[1:]); err != nil {
		return findingsUsage(err.Error())
	}
	if fs.NArg() > 0 {
		return findingsUsage(fmt.Sprintf("unexpected argument %q", fs.Arg(0)))
	}
	if *scope != "me" && *scope != "team" {
		return findingsUsage(fmt.Sprintf("--scope must be me or team, got %q", *scope))
	}
	note := strings.TrimSpace(*reason)
	if state != "open" && note == "" {
		return findingsUsage(fmt.Sprintf("%s needs --reason: say why, so the team can see it later", verb))
	}

	client, code := findingsClient()
	if client == nil {
		return code
	}
	req := stats.TriageRequest{ID: id, State: state, Note: note}
	if *scope == "team" {
		req.Scope = "team"
	}
	body, err := client.Triage(req)
	return printFindingsBody(body, err)
}

func findingsClient() (*stats.Client, int) {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "leoprevent findings: %v\n", err)
		return nil, 1
	}
	if cfg.DashboardURL == "" {
		fmt.Fprintf(os.Stderr,
			"leoprevent findings: dashboard_url is not set (add it to %s or set $%s)\n",
			config.FileName, config.EnvDashboardURL)
		return nil, 1
	}
	if cfg.LicenseKey == "" {
		fmt.Fprintln(os.Stderr,
			"leoprevent findings: no license key. Generate one in the dashboard under Plugin setup, "+
				"then run: leoprevent set-license <key>")
		return nil, 1
	}
	return stats.New(cfg.DashboardURL, cfg.LicenseKey), 0
}

func printFindingsBody(body []byte, err error) int {
	if err != nil {
		fmt.Fprintf(os.Stderr, "leoprevent findings: %v\n", err)
		return 1
	}
	if !json.Valid(body) {
		fmt.Fprintln(os.Stderr, "leoprevent findings: the dashboard returned a body that is not JSON")
		return 1
	}
	fmt.Println(string(body))
	return 0
}

func findingsUsage(msg string) int {
	fmt.Fprintf(os.Stderr, "leoprevent findings: %s\n", msg)
	fmt.Fprintln(os.Stderr, findingsUsageLine)
	return 2
}
