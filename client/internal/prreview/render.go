package prreview

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

// markerPrefix opens the hidden HTML comment every posted body carries. It is what
// makes a re-run idempotent: GitHub de-duplicates nothing, so without it every push
// to a branch would repeat the whole review.
const markerPrefix = "<!-- leoprevent:"

// AuthorshipNote is the sentence that has to appear on every surface this lane
// writes, and it is the copy half of the server's surfaced-only guarantee.
//
// ⚠️ A PULL REQUEST'S ADDED LINES ARE THE BRANCH'S, NOT ONE PERSON'S TURN'S. They may
// span days and several authors, so this review genuinely cannot say who wrote the
// line it is pointing at — and a security comment that reads as an accusation against
// whoever opened the pull request is both wrong and the fastest way to have the check
// switched off. Nothing here may say "you introduced", "your code" or "you added".
const AuthorshipNote = "LeoPrevent reviewed the diff on this pull request. It cannot tell who wrote any particular line, so nothing here is attributed to an author: each finding is raised for the reviewers to decide on."

// AdvisoryNote states the lane's own posture on the pull request, because a security
// comment from a bot is read as a gate unless it says otherwise. A reviewer who
// believes a merge is blocked goes looking for a check that does not exist.
const AdvisoryNote = "This is advisory. It blocks nothing and fails nothing."

// marker is the stable identity of one finding as a posted comment:
// (rule, path, line). Deliberately the same triple `history.Key` and every de-dup
// map in the product already use, minus the tenant — the pull request IS the scope
// here — so "the same finding" means the same thing on this lane as everywhere else.
//
// The RULE is half of it. Keyed on path and line alone, a genuinely different
// vulnerability appearing at a line we commented on before would read as already
// posted and be dropped: a missed detection wearing a duplicate's clothing.
func marker(f wire.Finding) string {
	path, line := SplitLocation(f.Location)
	return markerPrefix + f.Rule + ":" + path + ":" + strconv.Itoa(line) + " -->"
}

// MarkerLineTolerance is how far a finding's cited line may move between runs and
// still count as the SAME finding for de-duplication.
//
// ⚠️ WITHOUT IT THE DE-DUP DOES NOT SURVIVE A SECOND PUSH, AND THAT WAS MEASURED
// RATHER THAN REASONED ABOUT. On the LEO-231 test pull request, one push apart, the
// judge cited the same SSRF at `seeded_flaw.py:7` (`target = request.args.get("url")`)
// and then at `:8` (`resp = requests.get(target, ...)`). Both are defensible citations
// for one sink, the markers differed by one character, and the flaw was commented on
// twice. A cited line is a model judgement made afresh on every push, so keying
// equality on it exactly makes duplicates the normal outcome for any pull request that
// gets more than one push.
//
// ⚠️ THE RULE STAYS IN THE KEY AND THE TOLERANCE IS DELIBERATELY SMALL. Dropping the
// line entirely would collapse two genuinely separate instances of one rule in one file
// into a single comment, which is a missed detection wearing a duplicate's clothing —
// the same argument that put the rule in the key in the first place, one axis over. A
// few lines covers the drift between two citations of one construct without reaching
// the next unrelated sink.
//
// Accepted residue: a forged marker (see markerIn) can now suppress a real finding
// within this window rather than only at an exact line. `sanitiseProse` breaks the
// comment delimiters in every model-authored field, so a marker cannot be emitted by
// the judge at all; this widens a hole that guard already closes.
const MarkerLineTolerance = 3

// parseMarker reads a marker back into its three parts. A marker that does not parse is
// ignored by AlreadyPosted rather than treated as a match, so an unreadable comment
// fails TOWARD posting.
func parseMarker(m string) (rule, path string, line int, ok bool) {
	if !strings.HasPrefix(m, markerPrefix) || !strings.HasSuffix(m, " -->") {
		return "", "", 0, false
	}
	body := strings.TrimSuffix(strings.TrimPrefix(m, markerPrefix), " -->")
	// First colon closes the rule, last closes the path: a path may itself contain one.
	i := strings.Index(body, ":")
	j := strings.LastIndex(body, ":")
	if i < 0 || j <= i {
		return "", "", 0, false
	}
	n, err := strconv.Atoi(body[j+1:])
	if err != nil {
		return "", "", 0, false
	}
	return body[:i], body[i+1 : j], n, true
}

// AlreadyPosted answers whether this finding has been commented on by an earlier run.
//
// Exact match first, so the common case costs one map lookup and a marker written by an
// older build still matches itself.
func AlreadyPosted(posted map[string]bool, f wire.Finding) bool {
	if posted[marker(f)] {
		return true
	}
	path, line := SplitLocation(f.Location)
	if line == 0 {
		return false
	}
	for m := range posted {
		r, p, l, ok := parseMarker(m)
		if !ok || r != f.Rule || p != path {
			continue
		}
		if d := l - line; d <= MarkerLineTolerance && -d <= MarkerLineTolerance {
			return true
		}
	}
	return false
}

// markerIn extracts a marker from an existing comment body, or "" if it carries none
// (somebody else's comment, or one from before markers existed).
//
// ⚠️ IT TAKES THE LAST ONE, AND THAT IS A SUPPRESSION GUARD RATHER THAN A TIDY-UP.
// `CommentBody` appends the marker after the prose, and that prose is MODEL-AUTHORED: a
// prompt-injected judge could emit marker-shaped text inside a finding's `issue`, so a
// posted comment can carry two. Reading the FIRST would let the judge choose which marker
// this lane believes it has already posted — and a marker naming a DIFFERENT real finding
// would make that finding read as already-commented and be silently dropped. Suppressing a
// live vulnerability is the one failure this product exists to prevent, and it would leave no
// trace: the finding is detected, recorded and simply never mentioned.
//
// `sanitiseProse` is the other half and the stronger one, since it means a forged marker
// never survives into a body in the first place. This is the belt to that braces: the two
// guards fail in the same direction and neither depends on the other being right.
func markerIn(body string) string {
	i := strings.LastIndex(body, markerPrefix)
	if i < 0 {
		return ""
	}
	rest := body[i:]
	j := strings.Index(rest, " -->")
	if j < 0 {
		return ""
	}
	return rest[:j+len(" -->")]
}

// sanitiseProse neutralises HTML comment delimiters in MODEL-AUTHORED text before it is
// composed into a posted body.
//
// ⚠️ THE JUDGE'S `issue` AND `fix` ARE THE ONE PART OF A COMMENT WE DID NOT WRITE, AND THE
// DIFF UNDER REVIEW IS ATTACKER-INFLUENCED. The server already scrubs sentinels, redacts
// verbatim rule text and caps every field, but none of that stops an HTML comment: a judge
// coaxed into emitting `<!-- leoprevent:sql-injection:db.py:12 -->` inside its prose would
// forge this lane's de-duplication marker and suppress a real finding on the next run.
// Breaking the delimiter costs a comment two visible characters in the rare case a rule
// legitimately discusses one, and closes the forgery outright.
//
// It is applied to the PROSE only, never to the whole body: the body's own marker is the
// thing being protected, so sanitising after composition would strip it too.
func sanitiseProse(s string) string {
	s = strings.ReplaceAll(s, "<!--", "<! --")
	return strings.ReplaceAll(s, "-->", "-- >")
}

// SplitLocation splits a finding's `path:line` into its two halves. Line 0 means the
// location could not be parsed, which the caller must treat as unanchorable rather
// than as line zero — GitHub refuses a comment on it and would take the whole review
// down with it.
//
// It splits on the LAST colon, so a Windows-style drive letter or a path containing
// one does not lose its tail. A location with no colon at all is a bare path, which
// the judge emits on the transcript fallback where it has no line numbers to cite.
func SplitLocation(loc string) (string, int) {
	loc = strings.TrimSpace(loc)
	i := strings.LastIndexByte(loc, ':')
	if i <= 0 || i == len(loc)-1 {
		return loc, 0
	}
	n, err := strconv.Atoi(strings.TrimSpace(loc[i+1:]))
	if err != nil || n < 1 {
		return loc, 0
	}
	return loc[:i], n
}

// CommentBody renders one finding as an inline review comment.
//
// The judge's own `issue` and `fix` prose is what a reviewer needs; the severity and
// the rule name are what lets them triage a page of them. The fix is offered as a
// suggestion in words, NEVER as a GitHub ```suggestion block: that renders a
// one-click Commit button, so a reviewer would be applying a model's proposed
// security fix to a branch without reading it — the opposite of this lane's whole
// advisory posture, and a change no agent and no developer authored.
func CommentBody(f wire.Finding) string {
	var b strings.Builder
	b.WriteString("**")
	b.WriteString(headline(f))
	b.WriteString("**\n\n")
	if s := sanitiseProse(strings.TrimSpace(f.Issue)); s != "" {
		b.WriteString(s)
		b.WriteString("\n\n")
	}
	if s := sanitiseProse(strings.TrimSpace(f.Fix)); s != "" {
		b.WriteString("**Suggested fix.** ")
		b.WriteString(s)
		b.WriteString("\n\n")
	}
	b.WriteString("_")
	b.WriteString(AuthorshipNote)
	b.WriteString("_\n")
	b.WriteString(marker(f))
	return b.String()
}

// headline is the finding's one-line title: severity, then the rule's human name.
// The rule ID is deliberately absent — it is our vocabulary, not the reviewer's, and
// it already travels in the hidden marker for de-duplication.
func headline(f wire.Finding) string {
	name := strings.TrimSpace(f.Name)
	if name == "" {
		name = strings.TrimSpace(f.Rule)
	}
	if sev := strings.TrimSpace(f.Severity); sev != "" {
		return strings.ToUpper(sev[:1]) + sev[1:] + ": " + name
	}
	return name
}

// SummaryBody renders the review's top-level comment: what was reviewed, how many
// findings, and — in full — every finding that could NOT be anchored to a line of
// the diff.
//
// ⚠️ THE UNANCHORED FINDINGS ARE STATED IN FULL, NOT COUNTED. A finding whose cited
// line is outside the diff is usually the most interesting one on the pull request —
// existing code the proposed change routes into — and GitHub will not take an inline
// comment on it. Counting them would leave a reviewer knowing a number and having no
// way to reach what it counts, which on a security surface is worse than a long
// comment.
func SummaryBody(in SummaryInput) string {
	var b strings.Builder
	b.WriteString("## LeoPrevent security review\n\n")

	switch {
	case in.Total == 0:
		b.WriteString("No findings on the ")
		b.WriteString(plural(in.FilesReviewed, "reviewed file", "reviewed files"))
		b.WriteString(" in this pull request.\n\n")
	default:
		fmt.Fprintf(&b, "**%s** across %s.\n\n",
			plural(in.Total, "finding", "findings"),
			plural(in.FilesReviewed, "reviewed file", "reviewed files"))
	}

	if in.Inline > 0 {
		fmt.Fprintf(&b, "%s %s attached to the lines %s, in the diff below.\n\n",
			plural(in.Inline, "finding", "findings"),
			isAre(in.Inline), citeVerb(in.Inline))
	}
	if in.AlreadyPosted > 0 {
		fmt.Fprintf(&b, "%s already commented on an earlier push and %s not repeated here.\n\n",
			plural(in.AlreadyPosted, "finding was", "findings were"), isAre(in.AlreadyPosted))
	}

	if len(in.Unanchored) > 0 {
		b.WriteString("### Findings outside the diff\n\n")
		b.WriteString("These name code this pull request does not change, so they cannot be attached to a line of it. They are here rather than counted because existing code a change routes into is often the finding worth reading.\n\n")
		for _, f := range in.Unanchored {
			path, line := SplitLocation(f.Location)
			loc := path
			if line > 0 {
				loc = fmt.Sprintf("%s:%d", path, line)
			}
			fmt.Fprintf(&b, "- **%s** at `%s`", headline(f), loc)
			if s := sanitiseProse(strings.TrimSpace(f.Issue)); s != "" {
				b.WriteString("\n  " + indent(s))
			}
			if s := sanitiseProse(strings.TrimSpace(f.Fix)); s != "" {
				b.WriteString("\n  _Suggested fix._ " + indent(s))
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}

	if len(in.SkippedFiles) > 0 {
		b.WriteString("### Not reviewed\n\n")
		b.WriteString("Files the inert gate dropped as provably not shipped logic (documentation, lockfiles, generated output, tests, vendored trees) or excluded as secrets:\n\n")
		for _, p := range in.SkippedFiles {
			fmt.Fprintf(&b, "- `%s`\n", p)
		}
		b.WriteString("\n")
	}

	if in.Base != "" {
		fmt.Fprintf(&b, "Compared against `%s`.\n\n", in.Base)
	}
	b.WriteString(AuthorshipNote)
	b.WriteString(" ")
	b.WriteString(AdvisoryNote)
	b.WriteString("\n")
	return b.String()
}

// SummaryInput is what the summary states. Every count here is derived by the caller
// from one findings list, so the summary cannot claim a total its own sections
// contradict.
type SummaryInput struct {
	Total         int
	Inline        int
	AlreadyPosted int
	FilesReviewed int
	Unanchored    []wire.Finding
	SkippedFiles  []string
	Base          string
}

// SkipBody is the summary posted when the lane could not review at all. It exists
// because the alternative is silence, and silence on a security check reads as a
// clean bill of health — the same false assurance the plugin's own skip notice was
// added to remove.
func SkipBody(reason, detail string) string {
	var b strings.Builder
	b.WriteString("## LeoPrevent security review\n\n")
	b.WriteString("**This pull request was not reviewed.** ")
	b.WriteString(reason)
	b.WriteString("\n\n")
	if strings.TrimSpace(detail) != "" {
		// An error string can quote a server response, so it is not ours either.
		b.WriteString(sanitiseProse(strings.TrimSpace(detail)))
		b.WriteString("\n\n")
	}
	b.WriteString("Nothing was checked, so read this as an absence of review rather than an absence of findings. ")
	b.WriteString(AdvisoryNote)
	b.WriteString("\n")
	return b.String()
}

// SortFindings orders findings the way a reviewer reads them: severity first, then
// path, then line. Stable and total, so two runs over the same pull request post the
// same comments in the same order.
func SortFindings(fs []wire.Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		si, sj := severityRank(fs[i].Severity), severityRank(fs[j].Severity)
		if si != sj {
			return si < sj
		}
		pi, li := SplitLocation(fs[i].Location)
		pj, lj := SplitLocation(fs[j].Location)
		if pi != pj {
			return pi < pj
		}
		if li != lj {
			return li < lj
		}
		return fs[i].Rule < fs[j].Rule
	})
}

// severityRank orders the corpus's grades. An UNGRADED finding sorts LAST rather
// than first: it is a rule we cannot say is urgent, and leading the list with one
// would push a real critical below it.
func severityRank(sev string) int {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	default:
		return 4
	}
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}

func isAre(n int) string {
	if n == 1 {
		return "is"
	}
	return "are"
}

func citeVerb(n int) string {
	if n == 1 {
		return "it cites"
	}
	return "they cite"
}

// indent keeps a multi-line judge sentence inside its bullet.
func indent(s string) string {
	return strings.ReplaceAll(strings.TrimSpace(s), "\n", "\n  ")
}
