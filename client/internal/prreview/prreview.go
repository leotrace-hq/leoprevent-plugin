package prreview

import (
	"fmt"
	"io"
	"runtime"
	"sort"
	"strings"

	"github.com/leotrace-hq/leoprevent-plugin/buildinfo"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/engine"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/gate"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/vcs"
	"github.com/leotrace-hq/leoprevent-plugin/prpost"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

// Options configures one pull-request review.
type Options struct {
	Cwd  string // the checkout; must be a git repository
	Base string // the pull request's target branch, ref or SHA
	PR   int    // the pull request number, for the comment API
	URL  string // the pull request's web URL, recorded on the event

	// Environment is the wire.Env* runtime this ran in, and EnvironmentRaw is the
	// unmapped signal behind it. Named by the caller rather than inferred here, the
	// same contract clirun.Options.Environment carries: an unrecognised CI provider
	// must arrive as EnvUnknown with the raw value beside it, never as a plausible
	// guess at a runtime we have not verified.
	Environment    string
	EnvironmentRaw string

	// Post, when non-nil, is where findings are published. Nil reviews and reports to
	// Out without touching GitHub — which is what `--dry-run` is, and what the tests
	// use.
	Post *prpost.Client

	Out io.Writer // human-facing progress; the CI step log
}

// Result reports what happened, for the caller's exit code and step summary.
type Result struct {
	Reviewed  bool   // the diff was actually judged
	Skip      string // why not, when Reviewed is false
	Findings  int    // total raised
	Inline    int    // attached to a line of the diff
	Posted    bool   // a review was published
	FilesSeen int    // files handed to the judge
}

// Run reviews the pull request's diff and posts the findings.
//
// The shape mirrors engine.Run's reviewed-turn path with the turn-specific halves
// removed rather than reimplemented differently: collect changes, drop secrets, run
// the inert gate, build the meta, review. What it deliberately does NOT do is
// everything that presupposes an agent — there is no re-wake, so no outcome is
// remembered and none is shipped; no ledger is carried; and no telemetry is sent,
// because /telemetry exists to make per-PROMPT analytics complete and a CI job is
// not a prompt anybody ran.
//
// It returns an error only for a caller mistake it cannot proceed past (no
// repository, no pull request number). Everything else — an unreviewable diff, a
// review error, a refused comment — is a Result the caller reports and exits 0 on.
func Run(r engine.Reviewer, opts Options) (Result, error) {
	out := opts.Out
	if out == nil {
		out = io.Discard
	}
	if opts.PR <= 0 {
		return Result{}, fmt.Errorf("prreview: no pull request number")
	}

	changes, skip, err := vcs.DiffRange(opts.Cwd, opts.Base)
	if err != nil || skip != "" {
		res := Result{Skip: skipReason(skip, err)}
		fmt.Fprintf(out, "not reviewed: %s\n", res.Skip)
		res.Posted = postSkip(opts, out, res.Skip, skipDetail(skip))
		return res, nil
	}
	if len(changes) == 0 {
		res := Result{Reviewed: true}
		fmt.Fprintln(out, "nothing changed against the merge base; nothing to review")
		res.Posted = post(opts, out, prpost.SummaryBody(prpost.SummaryInput{Base: shortBase(opts)}), nil)
		return res, nil
	}

	// Secrets are dropped before anything else reads them, mirroring
	// engine.changedFiles. That function's dropSecrets is private to engine, so the
	// filter is applied here with the same predicate rather than the check being
	// skipped: a .env or a private key committed to a branch must not be egressed to
	// /review, and a pull request is exactly where one turns up.
	kept, secrets := dropSecrets(changes)
	reviewable := gate.Run(kept)
	skipped := append(secrets, droppedPaths(kept, reviewable)...)
	sort.Strings(skipped)
	// The excluded paths go to the STEP LOG and never to the posted summary. Naming them
	// on the pull request was several screens of documentation, lockfiles and test files
	// above the findings a reviewer came for, and a reader who wants the list can read the
	// job output. The log is where a wrongly excluded file gets noticed.
	if len(skipped) > 0 {
		fmt.Fprintf(out, "not reviewed (inert or excluded): %s\n", strings.Join(skipped, ", "))
	}

	if len(reviewable) == 0 {
		res := Result{Reviewed: true}
		fmt.Fprintf(out, "every changed file is inert or excluded (%d file(s)); nothing to review\n", len(changes))
		res.Posted = post(opts, out, prpost.SummaryBody(prpost.SummaryInput{
			Base: shortBase(opts),
		}), nil)
		return res, nil
	}

	meta := turnMeta(opts, reviewable)
	fmt.Fprintf(out, "reviewing %d file(s) on PR #%d against %s\n", len(reviewable), opts.PR, shortBase(opts))

	rres, rerr := r.Review(opts.Cwd, reviewable, meta)
	if rerr != nil {
		// Fail open, exactly as the hook does. The difference is that a CI step CAN
		// say so out loud without interrupting anybody, so it does: a security check
		// that silently did nothing is the false assurance the skip notice exists for.
		res := Result{Skip: fmt.Sprintf("the review could not run: %v", rerr)}
		fmt.Fprintf(out, "review error (failing open): %v\n", rerr)
		res.Posted = postSkip(opts, out, "The review could not be completed.", rerr.Error())
		return res, nil
	}

	findings := findingsOf(rres)
	res := Result{Reviewed: true, Findings: len(findings), FilesSeen: len(reviewable)}
	// ⚠️ A CLEAN REVIEW POSTS NOTHING. The step log is where it is reported; a comment saying
	// "no findings" is one per push on a pull request that stays clean, which is the repetition
	// prpost.Assembled.Post exists to prevent. See there for the reversal and its cost.
	if len(findings) == 0 {
		fmt.Fprintln(out, "clean: no findings; not posting a comment")
		return res, nil
	}

	// The anchoring, the de-duplication and the summary are prpost's, shared with the
	// server-side lane. Two drivers, one decision about what a customer actually sees.
	anchors := make(prpost.Anchors, len(reviewable))
	for _, c := range reviewable {
		anchors.Add(c.FilePath, c.AddedLines)
	}
	posted := map[string]bool{}
	if opts.Post != nil {
		posted = opts.Post.PostedMarkers(opts.PR)
	}
	a := prpost.Assemble(prpost.AssembleInput{
		Findings:      findings,
		Anchors:       anchors,
		Posted:        posted,
		FilesReviewed: len(reviewable),
		Base:          shortBase(opts),
	})
	res.Inline = a.Inline

	// The step log carries every finding whatever happens to the comments. A pull
	// request whose GITHUB_TOKEN cannot write, or whose review call is refused, must
	// still leave the findings somewhere a person can read them.
	for _, f := range findings {
		fmt.Fprintf(out, "  \u2022 %s at %s\n", prpost.Headline(f), f.Location)
	}

	// Nothing new to say, so nothing is said — the step log above still carries every
	// finding, so a re-run is readable in CI without adding a comment nobody needed.
	// See prpost.Assembled.Post.
	if !a.Post() {
		fmt.Fprintln(out, "nothing new since the last review on this pull request; not posting again")
		return res, nil
	}

	res.Posted = post(opts, out, a.Body, a.Comments)
	return res, nil
}

// findingsOf recovers the findings from the reviewer's Result. The cloud tier hands
// them back on the Pending it builds for the outcome loop, which is the only
// structured copy — Result.Prompt is the re-wake TEXT, and this lane never re-wakes
// anything, so parsing that would be reading prose to recover data we already have.
//
// A local-tier reviewer sets no Pending: the local tier ships rule content to the
// device and the developer's OWN model judges, so there are no server findings to
// comment on. That is refused at the flag, not here.
func findingsOf(res engine.Result) []wire.Finding {
	if res.Pending == nil {
		return nil
	}
	return res.Pending.Findings
}

// turnMeta describes a review with no developer and no agent in it.
//
// ⚠️ Developer, Agent, AgentModel AND Prompt ARE ALL DELIBERATELY EMPTY, and that is
// the containment rather than an omission. `developer` is the attribution axis for
// every per-person figure in the product, so naming the pull request's author here
// would file a branch's accumulated findings — possibly several people's, over days —
// onto whoever opened it. There is no agent, so `agent`/`agent_model` would be
// inventing a vendor; and there is no prompt, so the honest value is the one that
// egresses nothing.
//
// What IS recorded: the repository (a fact, and what the findings are in), the
// runtime, the lane, and the platform and version this binary is.
func turnMeta(opts Options, reviewable []transcript.Change) wire.TurnMeta {
	return wire.TurnMeta{
		Repo:              vcs.RepoOrigin(opts.Cwd),
		OS:                runtime.GOOS,
		Arch:              runtime.GOARCH,
		ClientVersion:     buildinfo.Version,
		Environment:       opts.Environment,
		EnvironmentRaw:    opts.EnvironmentRaw,
		GitBaseline:       true, // DiffRange refuses outside a repository, so this is always the git path
		ReviewLane:        wire.LanePullRequest,
		PullRequestNumber: opts.PR,
		PullRequestURL:    opts.URL,
	}
}

// dropSecrets partitions the change set into what may be sent and what may not,
// returning the excluded paths so the summary can NAME them. A secret file that is
// silently absent reads as a file with nothing wrong in it.
func dropSecrets(changes []transcript.Change) (kept []transcript.Change, excluded []string) {
	for _, c := range changes {
		if gate.IsSecretPath(c.FilePath) {
			excluded = append(excluded, c.FilePath)
			continue
		}
		kept = append(kept, c)
	}
	return kept, excluded
}

// droppedPaths names what the inert gate removed, by comparing what went in with
// what came out.
func droppedPaths(before, after []transcript.Change) []string {
	keep := make(map[string]bool, len(after))
	for _, c := range after {
		keep[c.FilePath] = true
	}
	var out []string
	for _, c := range before {
		if !keep[c.FilePath] {
			out = append(out, c.FilePath)
		}
	}
	return out
}

// post publishes one assembled review, with the one retry that matters.
func post(opts Options, out io.Writer, body string, inline []prpost.InlineComment) bool {
	if opts.Post == nil {
		fmt.Fprintf(out, "\n--- would post (dry run) ---\n%s\n", body)
		for _, c := range inline {
			fmt.Fprintf(out, "--- inline %s:%d ---\n%s\n", c.Path, c.Line, c.Body)
		}
		return false
	}
	if err := opts.Post.PostReview(opts.PR, body, inline); err != nil {
		fmt.Fprintf(out, "posting the review failed: %v\n", err)
		// Retry with the summary alone. A refused comments array is almost always one
		// line GitHub disagrees with us about being in the diff; the findings are all
		// in the summary's prose either way, so the retry is what stops a single
		// unanchorable line silencing the whole review.
		if len(inline) == 0 {
			return false
		}
		fmt.Fprintln(out, "retrying with the summary alone")
		if err := opts.Post.PostReview(opts.PR, body, nil); err != nil {
			fmt.Fprintf(out, "posting the summary failed too: %v\n", err)
			return false
		}
	}
	return true
}

func postSkip(opts Options, out io.Writer, reason, detail string) bool {
	return post(opts, out, prpost.SkipBody(reason, detail), nil)
}

// skipReason turns a vcs.SkipReason into a sentence for the pull request. The
// shallow-clone case gets named explicitly because it is the one a maintainer can
// fix in one line, and it is the DEFAULT for actions/checkout — so it is the failure
// nearly every first installation hits.
func skipReason(skip vcs.SkipReason, err error) string {
	switch {
	case err != nil:
		return fmt.Sprintf("the diff could not be read: %v", err)
	case skip == vcs.SkipNotGitRepo:
		return "the working directory is not a git repository."
	case skip == vcs.SkipBaselineGone, skip == vcs.SkipEmptyBaseline:
		return "the base commit could not be resolved in this checkout."
	case skip == vcs.SkipNoCwdOrSession:
		return "no base branch was given."
	default:
		return fmt.Sprintf("the diff could not be read (%s).", skip)
	}
}

func skipDetail(skip vcs.SkipReason) string {
	if skip == vcs.SkipBaselineGone || skip == vcs.SkipEmptyBaseline {
		return "This is almost always a shallow clone: `actions/checkout` fetches one commit by default, so the base branch is not present to compare against. Set `fetch-depth: 0` on the checkout step."
	}
	return ""
}

func shortBase(opts Options) string {
	base := strings.TrimSpace(opts.Base)
	if mb := vcs.MergeBase(opts.Cwd, base); mb != "" && base != "" {
		short := mb
		if len(short) > 12 {
			short = short[:12]
		}
		return base + " (" + short + ")"
	}
	return base
}
