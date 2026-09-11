package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/config"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/delivery"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/prreview"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/vcs"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

// runReviewPR is the `leoprevent review-pr` subcommand: run the real review loop over
// a PULL REQUEST's diff and post the findings as review comments (LEO-231).
//
// It exists because review otherwise only happens where the plugin runs, and the gaps
// are not edge cases: a checkout that is not a git repository, a write whose path is
// computed at runtime, a developer who never installed the plugin, and code a person
// wrote by hand. This lane covers all four at the point every change passes through.
//
//	leoprevent review-pr                       # inside a GitHub Actions pull_request job
//	leoprevent review-pr --base main --pr 42    # explicit, e.g. locally against a checkout
//	leoprevent review-pr --base main --pr 42 --dry-run
//
// ⚠️ IT ALWAYS EXITS 0 UNLESS --fail-on-findings IS PASSED. That is the no-blocking-gate
// non-negotiable, and it is stronger here than on the Stop hook: a false positive that
// blocks one turn costs one developer a minute, while a false positive in a merge queue
// blocks a whole team — and the team's answer is to delete the workflow. --fail-on-findings
// is a customer's own opt-in, and the flag name says what it does rather than implying
// the findings are an error.
func runReviewPR(args []string) int {
	fs := flag.NewFlagSet("review-pr", flag.ContinueOnError)
	base := fs.String("base", "", "base branch, ref or SHA to compare against (default: $GITHUB_BASE_REF, else the event payload)")
	prNum := fs.Int("pr", 0, "pull request number (default: from $GITHUB_EVENT_PATH)")
	cwdFlag := fs.String("cwd", "", "the checkout to review (default: current dir); must be a git repository")
	dryRun := fs.Bool("dry-run", false, "review and print what would be posted, without calling GitHub")
	failOn := fs.Bool("fail-on-findings", false, "exit 1 when findings remain. OFF by default, and off is the supported posture")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	cwd := *cwdFlag
	if cwd == "" {
		wd, err := os.Getwd()
		if err != nil {
			fmt.Fprintf(os.Stderr, "leoprevent review-pr: cwd: %v\n", err)
			return 2
		}
		cwd = wd
	}

	ev := readActionsEvent()
	pr := *prNum
	if pr == 0 {
		pr = ev.PullRequest.Number
	}
	if pr == 0 {
		fmt.Fprintln(os.Stderr, "leoprevent review-pr: no pull request number (pass --pr, or run this on a pull_request event)")
		fs.SetOutput(os.Stderr)
		fs.PrintDefaults()
		return 2
	}
	target := strings.TrimSpace(*base)
	if target == "" {
		target = strings.TrimSpace(os.Getenv("GITHUB_BASE_REF"))
	}
	if target == "" {
		target = strings.TrimSpace(ev.PullRequest.Base.Ref)
	}
	if target == "" {
		fmt.Fprintln(os.Stderr, "leoprevent review-pr: no base branch (pass --base)")
		return 2
	}
	// A pull_request checkout has the base branch as a REMOTE ref only, so a bare
	// branch name resolves to nothing. Qualifying it is what makes the zero-config
	// case work; an explicit --base is taken verbatim, since a caller naming a SHA or
	// a ref must not have origin/ prepended to it.
	if *base == "" {
		target = qualifyBase(cwd, target)
	}

	// Same config and reviewer the hook uses.
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "leoprevent review-pr: config: %v\n", err)
		return 2
	}
	// ⚠️ CLOUD ONLY, AND THIS IS A CAPABILITY LIMIT RATHER THAN A POLICY ONE. The local
	// tier ships rule CONTENT to the device and the developer's own model does the
	// judging, so there are no server-side findings to turn into comments — a local-tier
	// run would review nothing and post an empty summary, which reads as a clean pull
	// request. Refuse it here and say why.
	if cfg.Tier != config.TierCloud {
		fmt.Fprintf(os.Stderr, "leoprevent review-pr: this lane needs the cloud tier (configured tier is %q).\n"+
			"  The local tier judges on the developer's own model, so a CI job has nothing to judge with.\n", cfg.Tier)
		return 2
	}
	reviewer, err := delivery.New(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "leoprevent review-pr: reviewer: %v\n", err)
		return 2
	}

	envName, envRaw := ciEnvironment()
	opts := prreview.Options{
		Cwd:            cwd,
		Base:           target,
		PR:             pr,
		URL:            ev.PullRequest.HTMLURL,
		Environment:    envName,
		EnvironmentRaw: envRaw,
		Out:            os.Stderr,
	}
	if !*dryRun {
		client, cerr := githubClient()
		if cerr != nil {
			// No token means no comments, and that must not mean no review: the step log
			// still carries every finding, which is the whole point of printing them
			// there as well. Say so rather than exiting, so a misconfigured `permissions`
			// block reads as a missing comment and not as a clean pull request.
			fmt.Fprintf(os.Stderr, "leoprevent review-pr: not posting to GitHub: %v\n", cerr)
			fmt.Fprintln(os.Stderr, "  the review still runs and its findings are printed below")
		} else {
			opts.Post = client
		}
	}

	fmt.Fprintf(os.Stderr, "leoprevent review-pr: PR #%d, base %s (tier=%s, server=%s)\n", pr, target, cfg.Tier, cfg.ServerURL)
	res, rerr := prreview.Run(reviewer, opts)
	if rerr != nil {
		fmt.Fprintf(os.Stderr, "leoprevent review-pr: %v\n", rerr)
		return 2
	}
	writeStepSummary(res)
	if *failOn && res.Findings > 0 {
		return 1
	}
	return 0
}

// actionsEvent is the slice of GitHub's pull_request webhook payload this lane reads.
// Deliberately partial: the payload is large, third-party and versioned by GitHub, so
// a decoder that named every field would break on a shape change that does not
// concern us.
type actionsEvent struct {
	PullRequest struct {
		Number  int    `json:"number"`
		HTMLURL string `json:"html_url"`
		Base    struct {
			Ref string `json:"ref"`
		} `json:"base"`
	} `json:"pull_request"`
}

// readActionsEvent parses $GITHUB_EVENT_PATH. A missing, unreadable or unparseable
// payload yields the zero value rather than an error: every field it supplies has a
// flag or an environment variable behind it, so the caller degrades to those instead
// of failing.
func readActionsEvent() actionsEvent {
	var ev actionsEvent
	p := strings.TrimSpace(os.Getenv("GITHUB_EVENT_PATH"))
	if p == "" {
		return ev
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return ev
	}
	_ = json.Unmarshal(data, &ev)
	return ev
}

// githubClient builds the comment poster from the runner's own environment.
//
// The token is read from $GITHUB_TOKEN, which the action passes through from the
// workflow's `permissions` block. It is never a flag: a token on a command line lands
// in the process list and in the step's own echoed command.
func githubClient() (*prreview.Client, error) {
	token := strings.TrimSpace(os.Getenv("GITHUB_TOKEN"))
	if token == "" {
		return nil, fmt.Errorf("GITHUB_TOKEN is not set (the workflow needs `permissions: pull-requests: write`)")
	}
	slug := strings.TrimSpace(os.Getenv("GITHUB_REPOSITORY"))
	owner, repo, ok := strings.Cut(slug, "/")
	if !ok || owner == "" || repo == "" {
		return nil, fmt.Errorf("GITHUB_REPOSITORY is not owner/repo (got %q)", slug)
	}
	return &prreview.Client{
		Token: token,
		Owner: owner,
		Repo:  repo,
		API:   strings.TrimSpace(os.Getenv("GITHUB_API_URL")),
	}, nil
}

// ciEnvironment names the runtime this ran in, and the raw signal behind it.
//
// ⚠️ AN UNRECOGNISED CI PROVIDER IS wire.EnvUnknown WITH ITS OWN NAME IN THE RAW
// FIELD, never a plausible guess. That is the same call execEnvironment makes and the
// same one the agent adapters make: a wrong bucket is invisible and silently inflates
// a real surface, while an honest unknown announces itself and names its own fix. A
// provider earns a constant when the log shows its raw value arriving.
func ciEnvironment() (name, raw string) {
	switch {
	case os.Getenv("GITHUB_ACTIONS") == "true":
		return wire.EnvGitHubActions, "github_actions"
	case os.Getenv("GITLAB_CI") == "true":
		return wire.EnvUnknown, "gitlab_ci"
	case os.Getenv("CI") != "":
		return wire.EnvUnknown, "ci"
	default:
		// Not a CI runner at all — a maintainer running this against a local checkout.
		// Left empty rather than marked unknown: absent means "no signal", which is
		// true, and EnvUnknown means "a current client looked at a surface it could not
		// classify", which would be a claim about a runtime that is not there.
		return "", ""
	}
}

// qualifyBase turns a bare base BRANCH name into a ref this checkout actually holds.
// On a pull_request event the base branch is fetched as a remote-tracking ref, so
// `main` resolves to nothing while `origin/main` resolves; a value that already
// resolves is returned untouched, so a SHA or a fully-qualified ref is never rewritten.
func qualifyBase(cwd, base string) string {
	if base == "" || vcs.RevResolves(cwd, base) {
		return base
	}
	if remote := "origin/" + base; vcs.RevResolves(cwd, remote) {
		return remote
	}
	return base
}

// writeStepSummary appends a one-line result to the job summary GitHub renders on the
// run page, so the outcome is visible without opening the step log. Best-effort: a
// missing or unwritable path costs a line of presentation and nothing else.
func writeStepSummary(res prreview.Result) {
	p := strings.TrimSpace(os.Getenv("GITHUB_STEP_SUMMARY"))
	if p == "" {
		return
	}
	f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	switch {
	case !res.Reviewed:
		fmt.Fprintf(f, "### LeoPrevent\n\nNot reviewed: %s\n", res.Skip)
	case res.Findings == 0:
		fmt.Fprintf(f, "### LeoPrevent\n\nNo findings across %d reviewed file(s).\n", res.FilesSeen)
	default:
		fmt.Fprintf(f, "### LeoPrevent\n\n%d finding(s) across %d reviewed file(s); %d attached to the diff. Advisory only.\n",
			res.Findings, res.FilesSeen, res.Inline)
	}
}
