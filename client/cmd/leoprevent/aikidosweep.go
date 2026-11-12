package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/leotrace-hq/leoprevent-plugin/buildinfo"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/apiclient"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/config"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/outcome"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/sweep"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/vcs"
	"github.com/leotrace-hq/leoprevent-plugin/limits"
	"github.com/leotrace-hq/leoprevent-plugin/logx"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

const sweepUsageLine = "usage: leoprevent aikido-sweep [--plan] [--agent NAME]\n       leoprevent aikido-sweep answer --review ID < reply.txt\n       leoprevent aikido-sweep resolve [--agent NAME]"

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
	Repo      string           `json:"repo"`
	Complete  bool             `json:"complete"`
	Files     int              `json:"files"`
	Issues    int              `json:"issues"`
	Planned   bool             `json:"plan_only,omitempty"`
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
}

func runAikidoSweep(args []string) int {
	if len(args) > 0 && args[0] == "answer" {
		return runSweepAnswer(args[1:], os.Stdin)
	}
	if len(args) > 0 && args[0] == "resolve" {
		return runSweepResolve(args[1:])
	}
	fs := flag.NewFlagSet("aikido-sweep", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	planOnly := fs.Bool("plan", false, "list the files holding open Aikido issues and send no code")
	agent := fs.String("agent", "", "the coding agent running the sweep")
	if err := fs.Parse(args); err != nil {
		return sweepUsage(err.Error())
	}
	if fs.NArg() > 0 {
		return sweepUsage(fmt.Sprintf("unexpected argument %q", fs.Arg(0)))
	}

	closeLog := logx.Setup("client", false)
	defer closeLog()

	client, ok := sweepClient()
	if !ok {
		return 1
	}
	cwd, _ := os.Getwd()
	root, repo := vcs.RepoRoot(cwd), vcs.RepoOrigin(cwd)
	if root == "" || repo == "" {
		fmt.Fprintln(os.Stderr, "leoprevent aikido-sweep: run this inside a git repository with an origin remote, which is how Aikido's repository is matched")
		return 1
	}

	plan, err := client.SweepPlan(wire.SweepPlanRequest{Repo: repo})
	if err != nil {
		fmt.Fprintf(os.Stderr, "leoprevent aikido-sweep: %v\n", err)
		return 1
	}
	if !plan.Connected {
		fmt.Fprintln(os.Stderr, "leoprevent aikido-sweep: Aikido is not connected for this account, or could not be read. An admin connects it in the dashboard under Integrations.")
		return 1
	}
	report := sweepReport{Repo: repo, Complete: plan.Complete, Files: len(plan.Files), Skipped: []sweep.Skipped{}, Batches: []sweepBatch{}, RealList: []sweepFinding{}}
	for _, f := range plan.Files {
		report.Issues += f.Issues
	}
	if *planOnly {
		report.Planned, report.Plan = true, plan.Files
		return printSweep(report)
	}

	var files []sweep.File
	for _, f := range plan.Files {
		if f.Issues > wire.MaxSweepIssues {
			report.Skipped = append(report.Skipped, sweep.Skipped{Path: f.Path, Reason: sweep.SkipTooMany})
			continue
		}
		content, skip := sweep.Read(root, f.Path)
		if skip != "" {
			report.Skipped = append(report.Skipped, sweep.Skipped{Path: f.Path, Reason: skip})
			continue
		}
		files = append(files, sweep.File{Path: f.Path, Issues: f.Issues, Content: content})
	}

	dev, devSource := vcs.DeveloperFrom(cwd)
	meta := wire.TurnMeta{
		Agent: *agent, Repo: repo, Developer: dev, DeveloperSource: devSource,
		OS: runtime.GOOS, Arch: runtime.GOARCH, ClientVersion: buildinfo.Version,
		ReviewLane: wire.LaneAikidoSweep,
	}
	state := sweep.State{Repo: repo}
	head := vcs.Head(root)
	for _, batch := range sweep.Batches(files, limits.MaxReviewBytes, wire.MaxSweepFiles, wire.MaxSweepIssues) {
		changes := make([]wire.ChangedFile, len(batch))
		for i, f := range batch {
			changes[i] = wire.ChangedFile{Path: f.Path, FullContent: f.Content}
		}
		resp, err := client.Sweep(wire.SweepRequest{Files: changes, Meta: meta})
		if err != nil {
			report.Failed++
			fmt.Fprintf(os.Stderr, "leoprevent aikido-sweep: a batch of %d files failed: %v\n", len(batch), err)
			continue
		}
		report.Checked += resp.Checked
		report.Disputed += resp.Disputed
		report.Real += resp.Real
		report.Absent += resp.Absent
		report.Unjudged += resp.Unjudged
		sent := map[string]string{}
		for _, f := range batch {
			sent[f.Path] = f.Content
		}
		open := sweep.Open{ReviewID: resp.ReviewID, Commit: head, At: time.Now()}
		for _, f := range resp.RealFindings {
			report.RealList = append(report.RealList, sweepFinding{Rule: f.Rule, Name: f.Name, Location: f.Location, Severity: f.Severity, Issue: f.Issue, Fix: f.Fix})
			path := wire.ParseLocation(f.Location).Path
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
		fmt.Fprintf(os.Stderr, "leoprevent aikido-sweep: could not save the sweep to answer later: %v\n", err)
		return 1
	}
	return printSweep(report)
}

func runSweepAnswer(args []string,
	stdin io.Reader) int {
	fs := flag.NewFlagSet("aikido-sweep answer", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	reviewID := fs.String("review", "", "the review_id of the batch being answered")
	agent := fs.String("agent", "", "the coding agent running the sweep")
	if err := fs.Parse(args); err != nil {
		return sweepUsage(err.Error())
	}
	if *reviewID == "" || fs.NArg() > 0 {
		return sweepUsage("answer needs --review ID and the reply on stdin")
	}

	closeLog := logx.Setup("client", false)
	defer closeLog()

	reply, err := io.ReadAll(io.LimitReader(stdin, limits.MaxAgentReplyBytes+1))
	if err != nil || strings.TrimSpace(string(reply)) == "" {
		fmt.Fprintln(os.Stderr, "leoprevent aikido-sweep: the answer is read from stdin and was empty")
		return 1
	}
	if len(reply) > limits.MaxAgentReplyBytes {
		fmt.Fprintf(os.Stderr, "leoprevent aikido-sweep: the answer is over %d bytes; keep it to one short line per finding\n", limits.MaxAgentReplyBytes)
		return 1
	}
	cwd, _ := os.Getwd()
	state, err := sweep.Load(vcs.RepoOrigin(cwd))
	if err != nil {
		fmt.Fprintf(os.Stderr, "leoprevent aikido-sweep: could not read the saved sweep: %v\n", err)
		return 1
	}
	pending, ok := state.Take(*reviewID)
	if !ok {
		fmt.Fprintf(os.Stderr, "leoprevent aikido-sweep: no unanswered batch %q; run the sweep again\n", *reviewID)
		return 1
	}
	client, ok := sweepClient()
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
		fmt.Fprintf(os.Stderr, "leoprevent aikido-sweep: the answer was not recorded, try again: %v\n", err)
		return 1
	}
	if err := sweep.Save(state); err != nil {
		fmt.Fprintf(os.Stderr, "leoprevent aikido-sweep: the answer was recorded but the saved sweep was not updated: %v\n", err)
	}
	return printSweep(map[string]any{"review_id": pending.ReviewID, "recorded": true, "remaining_batches": len(state.Pending)})
}

type resolveReport struct {
	Checked    int      `json:"checked"`
	Fixed      []string `json:"fixed"`
	StillOpen  []string `json:"still_open"`
	Unchanged  int      `json:"unchanged"`
	NotChecked int      `json:"not_checked"`
}

func runSweepResolve(args []string) int {
	fs := flag.NewFlagSet("aikido-sweep resolve", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	agent := fs.String("agent", "", "the coding agent running the fixes")
	if err := fs.Parse(args); err != nil {
		return sweepUsage(err.Error())
	}
	if fs.NArg() > 0 {
		return sweepUsage(fmt.Sprintf("unexpected argument %q", fs.Arg(0)))
	}

	closeLog := logx.Setup("client", false)
	defer closeLog()

	cwd, _ := os.Getwd()
	root, repo := vcs.RepoRoot(cwd), vcs.RepoOrigin(cwd)
	if root == "" || repo == "" {
		fmt.Fprintln(os.Stderr, "leoprevent aikido-sweep: run this inside the repository that was swept")
		return 1
	}
	state, err := sweep.Load(repo)
	if err != nil {
		fmt.Fprintf(os.Stderr, "leoprevent aikido-sweep: could not read the saved sweep: %v\n", err)
		return 1
	}
	state.DropExpired(time.Now())
	report := resolveReport{Fixed: []string{}, StillOpen: []string{}}
	if len(state.Open) == 0 {
		return printSweep(report)
	}
	client, ok := sweepClient()
	if !ok {
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
		fmt.Fprintf(os.Stderr, "leoprevent aikido-sweep: the fixes were recorded but the saved sweep was not updated: %v\n", err)
	}
	return printSweep(report)
}

func sweepClient() (*apiclient.Client, bool) {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "leoprevent aikido-sweep: %v\n", err)
		return nil, false
	}
	if cfg.Tier != config.TierCloud {
		fmt.Fprintln(os.Stderr, "leoprevent aikido-sweep: the sweep needs the cloud tier")
		return nil, false
	}
	if cfg.LicenseKey == "" {
		fmt.Fprintln(os.Stderr,
			"leoprevent aikido-sweep: no license key. Generate one in the dashboard under Plugin setup, "+
				"then run: leoprevent set-license <key>")
		return nil, false
	}
	return apiclient.New(cfg.ServerURL, cfg.LicenseKey), true
}

func printSweep(v any) int {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		fmt.Fprintf(os.Stderr, "leoprevent aikido-sweep: %v\n", err)
		return 1
	}
	return 0
}

func sweepUsage(msg string) int {
	fmt.Fprintf(os.Stderr, "leoprevent aikido-sweep: %s\n", msg)
	fmt.Fprintln(os.Stderr, sweepUsageLine)
	return 2
}
