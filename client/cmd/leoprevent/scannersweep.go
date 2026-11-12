package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/leotrace-hq/leoprevent-plugin/buildinfo"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/apiclient"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/config"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/outcome"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/policycheck"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/sweep"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/vcs"
	"github.com/leotrace-hq/leoprevent-plugin/limits"
	"github.com/leotrace-hq/leoprevent-plugin/logx"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

// sweepTool is one scanner the backlog sweep runs against (LEO-685 Aikido, Snyk since), named
// as `leoprevent sweep <route>`. Each has its own server routes, review lane and saved state;
// the flow is the same.
type sweepTool struct {
	cmd   string // the command as the developer types it, "sweep aikido"
	name  string // the scanner as the developer knows it, "Aikido"
	route string // its argument, server routes' prefix and state key, "aikido"
	lane  string
}

var (
	aikidoSweep = sweepTool{cmd: "sweep aikido", name: "Aikido", route: "aikido", lane: wire.LaneAikidoSweep}
	snykSweep   = sweepTool{cmd: "sweep snyk", name: "Snyk", route: "snyk", lane: wire.LaneSnykSweep}
	githubSweep = sweepTool{cmd: "sweep github", name: "GitHub code scanning", route: "github", lane: wire.LaneGithubSweep}
	sweepTools  = []sweepTool{aikidoSweep, snykSweep, githubSweep}
)

const sweepPickUsage = "usage: leoprevent sweep aikido|snyk|github [--plan | --next] [--all] [--agent NAME]"

// runSweep is `leoprevent sweep <scanner> ...`. The scanner comes first; the slash command asks
// the developer for one when they did not name it, so a missing one here is a usage error.
func runSweep(args []string) int {
	if len(args) > 0 {
		for _, t := range sweepTools {
			if strings.EqualFold(args[0], t.route) {
				return runScannerSweep(t, args[1:])
			}
		}
	}
	fmt.Fprintln(os.Stderr, "leoprevent sweep: name the scanner to sweep, aikido, snyk or github")
	fmt.Fprintln(os.Stderr, sweepPickUsage)
	return 2
}

func (t sweepTool) usageLine() string {
	return "usage: leoprevent " + t.cmd + " [--plan | --next] [--all] [--agent NAME]\n" +
		"       leoprevent " + t.cmd + " answer --review ID < reply.txt\n" +
		"       leoprevent " + t.cmd + " resolve [--agent NAME]"
}

// fail prints one line to stderr, prefixed with the subcommand.
func (t sweepTool) fail(format string,
	args ...any) {
	fmt.Fprintf(os.Stderr, "leoprevent "+t.cmd+": "+format+"\n", args...)
}

type sweepFinding struct {
	Rule     string `json:"rule"`
	Name     string `json:"name"`
	Location string `json:"location"`
	Severity string `json:"severity,omitempty"`
	Issue    string `json:"issue"`
	Fix      string `json:"fix,omitempty"`
}

type sweepBatch struct {
	ReviewID string         `json:"review_id"`
	Findings []sweepFinding `json:"findings"`
}

type sweepReport struct {
	Notice    string           `json:"notice,omitempty"`
	Repo      string           `json:"repo"`
	Complete  bool             `json:"complete"`
	Files     int              `json:"files"`
	Issues    int              `json:"issues"`
	Planned   bool             `json:"plan_only,omitempty"`
	Settled   int              `json:"already_answered"`
	Withheld  int              `json:"withheld"`
	Checked   int              `json:"checked"`
	Disputed  int              `json:"disputed"`
	Real      int              `json:"real"`
	Absent    int              `json:"absent"`
	Unjudged  int              `json:"unjudged"`
	Failed    int              `json:"failed_batches"`
	Untracked int              `json:"real_not_tracked"`
	Skipped   []sweep.Skipped  `json:"skipped"`
	Batches   []sweepBatch     `json:"batches"`
	RealList  []sweepFinding   `json:"real_findings"`
	Plan      []wire.SweepFile `json:"plan,omitempty"`
	MoreFiles int              `json:"remaining_files"`
	More      int              `json:"remaining_findings"`
}

// runAikidoSweep keeps the old `aikido-sweep` subcommand working for an agent session that
// loaded the old /leoprevent:aikido-sweep command before the plugin updated under it.
func runAikidoSweep(args []string) int { return runScannerSweep(aikidoSweep, args) }

func runScannerSweep(t sweepTool,
	args []string) int {
	if len(args) > 0 && args[0] == "answer" {
		return runSweepAnswer(t, args[1:], os.Stdin)
	}
	if len(args) > 0 && args[0] == "resolve" {
		return runSweepResolve(t, args[1:])
	}
	fs := flag.NewFlagSet(t.cmd, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	planOnly := fs.Bool("plan", false, "list the files holding open scanner issues and send no code")
	next := fs.Bool("next", false, "sweep the next findings the last run left")
	all := fs.Bool("all", false, "sweep every open finding in one run instead of one batch")
	agent := fs.String("agent", "", "the coding agent running the sweep")
	if err := fs.Parse(args); err != nil {
		return sweepUsage(t, err.Error())
	}
	if fs.NArg() > 0 {
		return sweepUsage(t, fmt.Sprintf("unexpected argument %q", fs.Arg(0)))
	}
	if *planOnly && *next {
		return sweepUsage(t, "--plan and --next do not go together")
	}
	if *planOnly && *all {
		return sweepUsage(t, "--plan and --all do not go together")
	}

	closeLog := logx.Setup("client", false)
	defer closeLog()

	client, ok := sweepClient(t)
	if !ok {
		return 1
	}
	cwd, _ := os.Getwd()
	root, repo := vcs.RepoRoot(cwd), vcs.RepoOrigin(cwd)
	if root == "" || repo == "" {
		t.fail("run this inside a git repository with an origin remote, which is how %s's repository is matched", t.name)
		return 1
	}

	if sweepExcluded(t, client, repo) {
		return 1
	}
	plan, err := client.SweepPlan(t.route, wire.SweepPlanRequest{Repo: repo, Masking: true})
	if err != nil {
		t.fail("%v", err)
		return 1
	}
	if !plan.Connected {
		t.fail("%s is not connected for this account, or could not be read. An admin connects it in the dashboard under Integrations.", t.name)
		return 1
	}
	report := sweepReport{Repo: repo, Complete: plan.Complete, Files: len(plan.Files), Settled: plan.Settled, Withheld: plan.Withheld, Skipped: []sweep.Skipped{}, Batches: []sweepBatch{}, RealList: []sweepFinding{}}
	for _, f := range plan.Files {
		report.Issues += f.Issues
	}
	if *planOnly {
		report.Planned, report.Plan = true, plan.Files
		report.Notice = sweepNotice(t, client, wire.SweepNoticeRequest{Kind: wire.SweepNoticePlan, Complete: report.Complete, Files: report.Files, Issues: report.Issues, Settled: report.Settled, Withheld: report.Withheld})
		return printSweep(t, report)
	}

	state := sweep.State{Tool: t.route, Repo: repo}
	if *next {
		if state, err = sweep.Load(t.route, repo); err != nil {
			t.fail("could not read the last sweep: %v", err)
			return 1
		}
		state.DropExpired(time.Now())
	}
	limit := sweep.PageFindings
	if *all {
		limit = math.MaxInt
	}
	page, rest := sweep.Page(plan.Files, state.Swept, limit)
	report.Files, report.Issues, report.MoreFiles = len(page), 0, len(rest)
	for _, f := range page {
		report.Issues += f.Issues
		state.Swept = append(state.Swept, f.Path)
	}
	for _, f := range rest {
		report.More += f.Issues
	}

	var files []sweep.File
	for _, f := range page {
		if f.Issues > wire.MaxSweepIssues {
			report.Skipped = append(report.Skipped, sweep.Skipped{Path: f.Path, Reason: sweep.SkipTooMany})
			continue
		}
		content, skip := sweep.Read(root, f.Path)
		if skip != "" {
			report.Skipped = append(report.Skipped, sweep.Skipped{Path: f.Path, Reason: skip})
			continue
		}
		if len(f.Secrets) == 0 {
			files = append(files, sweep.File{Path: f.Path, Issues: f.Issues, Content: content})
			continue
		}
		excerpt, start := sweep.Excerpt(content, f.Secrets)
		if excerpt == "" {
			report.Skipped = append(report.Skipped, sweep.Skipped{Path: f.Path, Reason: sweep.SkipNoLines})
			continue
		}
		files = append(files, sweep.File{Path: f.Path, Issues: f.Issues, Content: excerpt, Start: start, Masked: true})
	}

	dev, devSource := vcs.DeveloperFrom(cwd)
	meta := wire.TurnMeta{
		Agent: *agent, Repo: repo, Developer: dev, DeveloperSource: devSource,
		OS: runtime.GOOS, Arch: runtime.GOARCH, ClientVersion: buildinfo.Version,
		ReviewLane: t.lane,
	}
	head := vcs.Head(root)
	for _, batch := range sweep.Batches(files, limits.MaxReviewBytes, wire.MaxSweepFiles, wire.MaxSweepIssues) {
		changes := make([]wire.ChangedFile, len(batch))
		var masked []string
		for i, f := range batch {
			changes[i] = wire.ChangedFile{Path: f.Path, FullContent: f.Content, BodyStartLine: f.Start}
			if f.Masked {
				masked = append(masked, f.Path)
			}
		}
		resp, err := client.Sweep(t.route, wire.SweepRequest{Files: changes, Masked: masked, Meta: meta})
		if err != nil {
			report.Failed++
			t.fail("a batch of %d files failed: %v", len(batch), err)
			continue
		}
		report.Checked += resp.Checked
		report.Disputed += resp.Disputed
		report.Real += resp.Real
		report.Absent += resp.Absent
		report.Unjudged += resp.Unjudged
		sent := map[string]string{}
		excerpts := map[string]bool{}
		for _, f := range batch {
			sent[f.Path] = f.Content
			excerpts[f.Path] = f.Masked
		}
		open := sweep.Open{ReviewID: resp.ReviewID, Commit: head, At: time.Now()}
		for _, f := range resp.RealFindings {
			report.RealList = append(report.RealList, sweepFinding{Rule: f.Rule, Name: f.Name, Location: f.Location, Severity: f.Severity, Issue: f.Issue, Fix: f.Fix})
			path := wire.ParseLocation(f.Location).Path
			if excerpts[path] {
				continue
			}
			if committed, ok := vcs.FileAt(root, head, path); ok && committed == sent[path] {
				open.Findings = append(open.Findings, f)
			} else {
				report.Untracked++
			}
		}
		if len(open.Findings) > 0 {
			state.Open = append(state.Open, open)
		}
		if len(resp.Findings) == 0 {
			continue
		}
		b := sweepBatch{ReviewID: resp.ReviewID}
		for _, f := range resp.Findings {
			b.Findings = append(b.Findings, sweepFinding{Rule: f.Rule, Name: f.Name, Location: f.Location, Severity: f.Severity, Issue: f.Issue})
		}
		report.Batches = append(report.Batches, b)
		state.Pending = append(state.Pending, sweep.Pending{ReviewID: resp.ReviewID, Findings: resp.Findings})
	}
	if err := sweep.Save(state); err != nil {
		t.fail("could not save the sweep to answer later: %v", err)
		return 1
	}
	report.Notice = sweepNotice(t, client, wire.SweepNoticeRequest{
		Kind: wire.SweepNoticeSweep, Complete: report.Complete, Files: report.Files, Issues: report.Issues,
		Checked: report.Checked, Disputed: report.Disputed, Real: report.Real, Absent: report.Absent,
		Skipped: len(report.Skipped), Unjudged: report.Unjudged, Failed: report.Failed,
		Continued: *next, RemainingFiles: report.MoreFiles, RemainingFindings: report.More,
		Settled: report.Settled, Withheld: report.Withheld,
	})
	return printSweep(t, report)
}

func runSweepAnswer(t sweepTool,
	args []string,
	stdin io.Reader) int {
	fs := flag.NewFlagSet(t.cmd+" answer", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	reviewID := fs.String("review", "", "the review_id of the batch being answered")
	agent := fs.String("agent", "", "the coding agent running the sweep")
	if err := fs.Parse(args); err != nil {
		return sweepUsage(t, err.Error())
	}
	if *reviewID == "" || fs.NArg() > 0 {
		return sweepUsage(t, "answer needs --review ID and the reply on stdin")
	}

	closeLog := logx.Setup("client", false)
	defer closeLog()

	reply, err := io.ReadAll(io.LimitReader(stdin, limits.MaxAgentReplyBytes+1))
	if err != nil || strings.TrimSpace(string(reply)) == "" {
		t.fail("the answer is read from stdin and was empty")
		return 1
	}
	if len(reply) > limits.MaxAgentReplyBytes {
		t.fail("the answer is over %d bytes; keep it to one short line per finding", limits.MaxAgentReplyBytes)
		return 1
	}
	cwd, _ := os.Getwd()
	state, err := sweep.Load(t.route, vcs.RepoOrigin(cwd))
	if err != nil {
		t.fail("could not read the saved sweep: %v", err)
		return 1
	}
	pending, ok := state.Take(*reviewID)
	if !ok {
		t.fail("no unanswered batch %q; run the sweep again", *reviewID)
		return 1
	}
	client, ok := sweepClient(t)
	if !ok {
		return 1
	}
	_, err = client.Outcome(wire.OutcomeRequest{
		ReviewID:      pending.ReviewID,
		Repo:          state.Repo,
		Developer:     vcs.Developer(cwd),
		Agent:         *agent,
		Findings:      pending.Findings,
		AgentResponse: string(reply),
	})
	if err != nil && (!errors.Is(err, outcome.ErrUnscored) || errors.Is(err, outcome.ErrTransient)) {
		t.fail("the answer was not recorded, try again: %v", err)
		return 1
	}
	if err := sweep.Save(state); err != nil {
		t.fail("the answer was recorded but the saved sweep was not updated: %v", err)
	}
	return printSweep(t, map[string]any{"review_id": pending.ReviewID, "recorded": true, "remaining_batches": len(state.Pending)})
}

type resolveReport struct {
	Notice     string   `json:"notice,omitempty"`
	Checked    int      `json:"checked"`
	Fixed      []string `json:"fixed"`
	StillOpen  []string `json:"still_open"`
	Unchanged  int      `json:"unchanged"`
	NotChecked int      `json:"not_checked"`
}

func runSweepResolve(t sweepTool,
	args []string) int {
	fs := flag.NewFlagSet(t.cmd+" resolve", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	agent := fs.String("agent", "", "the coding agent running the fixes")
	if err := fs.Parse(args); err != nil {
		return sweepUsage(t, err.Error())
	}
	if fs.NArg() > 0 {
		return sweepUsage(t, fmt.Sprintf("unexpected argument %q", fs.Arg(0)))
	}

	closeLog := logx.Setup("client", false)
	defer closeLog()

	cwd, _ := os.Getwd()
	root, repo := vcs.RepoRoot(cwd), vcs.RepoOrigin(cwd)
	if root == "" || repo == "" {
		t.fail("run this inside the repository that was swept")
		return 1
	}
	state, err := sweep.Load(t.route, repo)
	if err != nil {
		t.fail("could not read the saved sweep: %v", err)
		return 1
	}
	state.DropExpired(time.Now())
	report := resolveReport{Fixed: []string{}, StillOpen: []string{}}
	client, ok := sweepClient(t)
	if !ok {
		return 1
	}
	if len(state.Open) == 0 {
		report.Notice = resolveNotice(t, client, report)
		return printSweep(t, report)
	}
	if sweepExcluded(t, client, repo) {
		return 1
	}
	dev := vcs.Developer(cwd)
	var kept []sweep.Open
	for _, o := range state.Open {
		touched, untouched, before, after := sweep.Changed(root, o, vcs.FileAt, sweep.Read)
		if len(touched) == 0 {
			report.Unchanged += len(o.Findings)
			kept = append(kept, o)
			continue
		}
		resp, err := client.Outcome(wire.OutcomeRequest{
			ReviewID: o.ReviewID, Resolution: true, Findings: touched, Before: before, After: after,
			Repo: repo, Developer: dev, Agent: *agent,
		})
		if err != nil || !resp.Scored {
			report.NotChecked += len(touched)
			kept = append(kept, o)
			continue
		}
		report.Checked += len(touched)
		still := map[string]bool{}
		for _, f := range resp.PreexistingStillFiring {
			still[f.Rule+"\x00"+f.Location] = true
		}
		o.Findings = untouched
		for _, f := range touched {
			if still[f.Rule+"\x00"+f.Location] {
				o.Findings = append(o.Findings, f)
				report.StillOpen = append(report.StillOpen, f.Location)
			} else {
				report.Fixed = append(report.Fixed, f.Location)
			}
		}
		kept = append(kept, o)
	}
	state.Open = kept
	state.DropExpired(time.Now())
	if err := sweep.Save(state); err != nil {
		t.fail("the fixes were recorded but the saved sweep was not updated: %v", err)
	}
	report.Notice = resolveNotice(t, client, report)
	return printSweep(t, report)
}

func sweepNotice(t sweepTool,
	client *apiclient.Client,
	req wire.SweepNoticeRequest) string {
	resp, err := client.SweepNotice(t.route, req)
	if err != nil {
		return ""
	}
	return resp.Notice
}

func resolveNotice(t sweepTool,
	client *apiclient.Client,
	r resolveReport) string {
	return sweepNotice(t, client, wire.SweepNoticeRequest{
		Kind: wire.SweepNoticeResolve, Fixed: len(r.Fixed), StillOpen: len(r.StillOpen),
		Unchanged: r.Unchanged, NotChecked: r.NotChecked,
	})
}

// sweepExcluded runs the organisation's exclusion check before the sweep sends anything
// (docs/enterprise.md § Policies on reviews): an excluded repository, or one the check couldn't
// answer for when the license is known to exclude something, is not swept. It says why on stderr.
func sweepExcluded(t sweepTool,
	client *apiclient.Client,
	repo string) bool {
	key := ""
	if cfg, err := config.Load(); err == nil {
		key = cfg.LicenseKey
	}
	res := policycheck.Check(policycheck.API{Client: client}, key, []string{repo}, time.Now())
	if !res.Skip {
		return false
	}
	slog.Warn("scanner sweep not sent: organisation review policy", "scanner", t.route, "notice", res.NoticeID, "repo", res.Repo, "reason", res.Reason)
	t.fail("%s", res.Notice)
	return true
}

func sweepClient(t sweepTool) (*apiclient.Client, bool) {
	cfg, err := config.Load()
	if err != nil {
		t.fail("%v", err)
		return nil, false
	}
	if cfg.Tier != config.TierCloud {
		t.fail("the sweep needs the cloud tier")
		return nil, false
	}
	if cfg.LicenseKey == "" {
		t.fail("no license key. Generate one in the dashboard under Plugin setup, then run: leoprevent set-license <key>")
		return nil, false
	}
	return apiclient.New(cfg.ServerURL, cfg.LicenseKey), true
}

const sweepRelay = "[For the agent: the user cannot see this output. Print the LeoPrevent block above to the user now, in your next message, exactly as it is, every \"> \" line as markdown. Never summarise or reword it.]"

func writeNotice(out io.Writer,
	notice string) {
	if notice == "" {
		return
	}
	fmt.Fprintf(out, "%s\n\n%s\n\n", strings.TrimRight(notice, "\n"), sweepRelay)
}

func printSweep(t sweepTool,
	v any) int {
	switch r := v.(type) {
	case sweepReport:
		writeNotice(os.Stdout, r.Notice)
	case resolveReport:
		writeNotice(os.Stdout, r.Notice)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		t.fail("%v", err)
		return 1
	}
	return 0
}

func sweepUsage(t sweepTool,
	msg string) int {
	t.fail("%s", msg)
	fmt.Fprintln(os.Stderr, t.usageLine())
	return 2
}
