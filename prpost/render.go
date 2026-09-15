package prpost

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

// ⚠️ THE AUTHORSHIP DISCLAIMER IS GONE, AND WHAT IT PROTECTED IS A COPY RULE THAT STAYS.
// It read "LeoPrevent reviewed the diff on this pull request. It cannot tell who wrote any
// particular line, so nothing here is attributed to an author: each finding is raised for the
// reviewers to decide on." — 200 characters, italicised, on EVERY inline comment and again on
// the summary, so a pull request with five findings carried it six times.
//
// Removed on request, and it is the same call the rest of this lane keeps making: comment
// VOLUME is what gets the check deleted, which is why the two broadest rules are not posted at
// all, why the remedy is folded, and why a re-run with nothing new says nothing. A disclaimer
// repeated per comment is the loudest thing in a two-line finding.
//
// ⚠️ WHAT IT WAS DEFENDING IS UNCHANGED AND MUST STAY SO. A pull request's added lines are the
// BRANCH'S, not one person's turn's — they may span days and several authors — so nothing this
// lane writes may say "you introduced", "your code" or "you added", and no copy may name or
// imply an author. That rule never depended on the sentence: it is enforced by `surfaceAll`
// server-side (nothing on a laned review is classified as introduced) and by the fact that no
// rendered field here carries an identity. Removing a disclaimer about attribution is safe
// precisely because there is no attribution to disclaim.
//
// Pinned by TestNoPostedCopyNamesAnAuthor.

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
func Marker(f wire.Finding) string {
	path, line := SplitLocation(f.Location)
	m := markerPrefix + f.Rule + ":" + path + ":" + strconv.Itoa(line)
	// ⚠️ THE SPAN IS APPENDED AS `start-end`, AND A BARE `start` STILL PARSES. Markers written
	// before this exist on live pull requests; a format only the new code can read would make
	// every one of them unrecognisable and restate every finding once. See parseMarker.
	if e := f.EndLine; e > line && e-line <= MaxMarkerSpan {
		m += "-" + strconv.Itoa(e)
	}
	return m + " -->"
}

// reviewMarkerPrefix opens the SECOND hidden comment a posted finding carries: the id of
// the review that raised it.
//
// ⚠️ IT IS A SEPARATE MARKER RATHER THAN A FOURTH FIELD ON THE FINDING MARKER, AND THAT IS
// FORCED. `parseMarker` splits the finding marker on its first and LAST colon to recover
// (rule, path, line) — a path may itself contain one — so appending a fourth
// colon-separated component would make every existing marker's line number unparseable and
// every finding on every live pull request read as new. A distinct prefix also cannot
// collide: `markerPrefix` is `<!-- leoprevent:` and the next character here is `-`, so
// neither `markerIn` nor `markersIn` can see this one and `ReviewIDIn` cannot see theirs.
//
// ⚠️ WHAT IT BUYS IS THE ONLY THING THAT CAN CREDIT A LATER FIX. A resolution is recorded
// against the ORIGIN review's id (`preexistingResolvedByReview` keys on it), so a run that
// re-judges a comment posted three pushes ago has to know which review raised it. Nothing
// else on the pull request says: the thread carries our prose and a commit, not a review.
const reviewMarkerPrefix = "<!-- leoprevent-review:"

// maxReviewIDLen bounds what may be written into, or read back out of, a review marker.
// The value is a server-minted hex id; the bound is what stops an unexpected one becoming
// an unbounded string on a body we post or a map key we build from a pull request.
const maxReviewIDLen = 64

// ReviewMarker renders the review-id marker, or NOTHING for an id this lane will not
// vouch for.
//
// ⚠️ AN UNUSABLE ID EMITS NO MARKER RATHER THAN A MALFORMED ONE. The id is server-minted
// and travels through a response, so it is a value we did not choose; an empty marker
// costs a later push the ability to credit this finding's fix, where a marker carrying
// arbitrary text is something we wrote into a customer's pull request. The charset is the
// one an id can legitimately use, and nothing in it can close an HTML comment.
func ReviewMarker(id string) string {
	if !usableReviewID(id) {
		return ""
	}
	return reviewMarkerPrefix + id + " -->"
}

// ReviewIDIn recovers the review id from a posted body, or "" when there is none.
//
// It takes the LAST occurrence for `markerIn`'s reason: the prose above it is
// model-authored, and while `sanitiseProse` already breaks the delimiters, the two guards
// fail in the same direction and neither relies on the other. The recovered value is
// re-validated, so a body that somehow carries a malformed one yields nothing rather than
// a key we would then attribute a customer's fix to.
func ReviewIDIn(body string) string {
	i := strings.LastIndex(body, reviewMarkerPrefix)
	if i < 0 {
		return ""
	}
	rest := body[i+len(reviewMarkerPrefix):]
	j := strings.Index(rest, " -->")
	if j < 0 {
		return ""
	}
	id := rest[:j]
	if !usableReviewID(id) {
		return ""
	}
	return id
}

// usableReviewID is the one definition the write and the read share, so a marker this lane
// emits is one it can always read back.
func usableReviewID(id string) bool {
	if id == "" || len(id) > maxReviewIDLen {
		return false
	}
	for _, r := range id {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r == '-' || r == '_':
		default:
			return false
		}
	}
	return true
}

// MaxMarkerSpan bounds the span a marker may claim, read AND written.
//
// ⚠️ IT IS A READ-SIDE BOUND FIRST. A span suppresses every later finding of that rule inside
// it, so a marker claiming 1-9999 would silence a whole file for that rule — detected, recorded
// and never mentioned, which is the failure `sanitiseProse` and `markerIn` already exist to
// prevent from the other direction. The server validates spans it returns (api.clampFindingSpans,
// same 80-line ceiling) but a marker is read back off a pull request, so it is re-bounded here.
const MaxMarkerSpan = 80

// UnrefinedRules are the two rules a pull-request review does NOT comment on.
//
// ⚠️ THE SAME TWO THE CUSTOMER DASHBOARD ALREADY EXCLUDES, AND FOR A SHARPER REASON HERE.
// `no-input-validation` and `db-trust` are the corpus's broadest rules: both fire wherever a
// value crosses a trust boundary without an explicit check, so on a real repository they
// dominate by volume while being the findings a reader is least likely to act on — measured
// live on the LeoTrace account, 30 of 41 entries in the Issues log. The dashboard answers that
// by hiding them from its default view, where the cost of being wrong is a figure somebody has
// to click once to see. On a PULL REQUEST the same volume is comments in somebody's review
// conversation, and the team's answer to a bot that comments on every function is to delete the
// bot. So here they are not posted at all.
//
// ⚠️ AND THE DASHBOARD'S READMISSION CLAUSE HAS NO COUNTERPART HERE, THOUGH THE REASON HAS
// NARROWED. There, an unrefined rule that was actually REMEDIATED comes back into view, because
// a flaw somebody acted on is not noise. The earlier reasoning — that a laned review can never
// be remediated, having no outcome and no re-judge — is now only half true: the resolution pass
// does re-judge a laned finding on a later push (see the server's prresolve.go). What still
// holds is that a rule dropped HERE never became a comment, so there is no thread to resolve and
// nothing for a readmission to act on. The rule test remains the whole of it.
//
// ⚠️ MATCHED ON THE RULE ID, NEVER THE TITLE — a corpus reword would silently stop refining,
// with nothing on the pull request saying so. Same call `refined.ts` records.
//
// ⚠️ IT IS A POSTING FILTER, NOT A SUPPRESSION. The finding is detected, returned by the judge,
// recorded on the audit event in full and counted on both dashboards exactly as before; what
// changes is whether it becomes a comment. `packages/metrics` still decides what the dashboard
// reports, and nothing here subtracts from a count.
var UnrefinedRules = []string{"no-input-validation", "db-trust"}

// IsRefined reports whether a finding's rule is one this lane comments on.
//
// An UNKNOWN or absent rule is REFINED — the safe direction, and the same one
// `refined.ts:isRefinedRule` takes: a finding we cannot classify must not be the one we drop.
func IsRefined(rule string) bool {
	for _, r := range UnrefinedRules {
		if rule == r {
			return false
		}
	}
	return true
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
func parseMarker(m string) (rule, path string, line, end int, ok bool) {
	if !strings.HasPrefix(m, markerPrefix) || !strings.HasSuffix(m, " -->") {
		return "", "", 0, 0, false
	}
	body := strings.TrimSuffix(strings.TrimPrefix(m, markerPrefix), " -->")
	// First colon closes the rule, last closes the path: a path may itself contain one.
	i := strings.Index(body, ":")
	j := strings.LastIndex(body, ":")
	if i < 0 || j <= i {
		return "", "", 0, 0, false
	}
	// The final component is `start` or `start-end`. A bare start is every marker written
	// before spans existed, and it reads as a one-line span.
	start, span, hasSpan := strings.Cut(body[j+1:], "-")
	n, err := strconv.Atoi(start)
	if err != nil {
		return "", "", 0, 0, false
	}
	e := n
	if hasSpan {
		v, err := strconv.Atoi(span)
		if err != nil {
			return "", "", 0, 0, false
		}
		// A malformed or oversized span is IGNORED rather than honoured, so the marker
		// degrades to its own line and the tolerance window still applies. Honouring it
		// would let one bad value suppress a rule across a file.
		if v > n && v-n <= MaxMarkerSpan {
			e = v
		}
	}
	return body[:i], body[i+1 : j], n, e, true
}

// ParseMarker recovers (rule, path, line) from a posted marker, for a caller outside this
// package. `ok` is false for anything that does not parse, which every caller must treat as
// "this comment names no finding" rather than as a finding at line zero.
//
// The SPAN is deliberately not returned. It is a de-duplication widening — it decides
// whether two citations of one construct are the same finding — and a finding's IDENTITY is
// still `path:line`, which is what every credit, every RuleLoc and every dashboard key is
// built from. Handing the span out would invite a caller to key on it and quietly create a
// second notion of which finding this is.
func ParseMarker(m string) (rule, path string, line int, ok bool) {
	r, p, l, _, k := parseMarker(m)
	return r, p, l, k
}

// AlreadyPosted answers whether this finding has been commented on by an earlier run.
//
// Exact match first, so the common case costs one map lookup and a marker written by an
// older build still matches itself.
func AlreadyPosted(posted map[string]bool, f wire.Finding) bool {
	if posted[Marker(f)] {
		return true
	}
	path, line := SplitLocation(f.Location)
	if line == 0 {
		return false
	}
	end := line
	if f.EndLine > line && f.EndLine-line <= MaxMarkerSpan {
		end = f.EndLine
	}
	for m := range posted {
		r, p, l, e, ok := parseMarker(m)
		if !ok || r != f.Rule || p != path {
			continue
		}
		// ⚠️ THE SPAN IS CHECKED BOTH WAYS, AND ONE DIRECTION IS NOT ENOUGH. The judge cites
		// whichever line of a construct it considers the flaw, and which one that is moves
		// between runs: on the LEO-231 smoke test the same SSRF came back as the taint source
		// (`target = request.args.get(...)`, line 13) and then as the sink
		// (`requests.get(target)`, line 17). Either run may be the one that carried the span,
		// so a posted span must cover a new citation AND a new span must cover a posted
		// citation. Checking only the stored one leaves the source-then-sink order unmatched.
		if l <= end && line <= e {
			return true
		}
		// The tolerance window survives as the fallback for a finding with no span at all,
		// which is every one the judge decides is a single line.
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

// markersIn extracts EVERY marker in a body, for the summary.
//
// ⚠️ IT IS THE ONE PLACE THAT DOES NOT TAKE THE LAST MARKER, AND THE REASON markerIn DOES IS
// SATISFIED ELSEWHERE. That guard exists because a comment's model-authored prose could carry a
// forged marker naming a DIFFERENT real finding, which would then read as already-posted and be
// silently dropped. Here every marker is one WE appended, one per unanchored finding, and the
// prose between them has already been through `sanitiseProse` — which breaks the delimiters, so
// a forged marker cannot survive into the body this reads. Taking only the last would recognise
// one unanchored finding per summary and restate the rest on every push.
func markersIn(body string) []string {
	var out []string
	rest := body
	for {
		i := strings.Index(rest, markerPrefix)
		if i < 0 {
			return out
		}
		rest = rest[i:]
		j := strings.Index(rest, " -->")
		if j < 0 {
			return out
		}
		out = append(out, rest[:j+len(" -->")])
		rest = rest[j+len(" -->"):]
	}
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
//
// reviewID names the review that raised this finding and is carried as a second hidden
// marker, so a LATER push can re-judge this comment's finding and credit the fix against
// the right review. It is optional: the workflow-driven lane has no resolution pass, and a
// body without it is byte-identical to what this lane has always posted.
func CommentBody(f wire.Finding, reviewID string) string {
	var b strings.Builder
	b.WriteString("**")
	b.WriteString(Headline(f))
	b.WriteString("**\n\n")
	if s := sanitiseProse(strings.TrimSpace(f.Issue)); s != "" {
		b.WriteString(s)
		b.WriteString("\n\n")
	}
	b.WriteString(foldedFix(f))
	b.WriteString(Marker(f))
	if rm := ReviewMarker(reviewID); rm != "" {
		b.WriteString(rm)
	}
	return b.String()
}

// foldedFix renders the remedy inside a collapsed <details>, or nothing when there is none.
//
// ⚠️ FOLDED RATHER THAN SHORTENED, AND THE DIFFERENCE IS THE WHOLE POINT. The judge's `fix` is
// routinely a numbered remedy of five or six steps — correct, and a wall of text in a review
// conversation where the finding itself is one paragraph. Live on the LEO-231 smoke test one SSRF
// comment ran to 1.4 KB, nearly all of it the recipe.
//
// ⚠️ BUT TRUNCATING IT IS WORSE THAN LEAVING IT OUT, WHICH IS THE CALL LEO-120 ALREADY MADE ONE
// SURFACE OVER: a developer who applies half a guard has shipped an incomplete fix believing they
// followed the advice. That notice could drop the prose outright because the agent had already
// been handed it verbatim in the re-wake. Here nobody has: a pull-request comment is the only
// place this remedy is ever shown, so dropping it loses the most actionable half of the finding.
// A fold keeps every word and costs one click, so nothing is lost in either direction.
//
// GitHub renders <details> in comment markdown. A client that does not falls back to showing the
// contents, which is the behaviour this replaces rather than a new failure.
func foldedFix(f wire.Finding) string {
	s := sanitiseProse(strings.TrimSpace(f.Fix))
	if s == "" {
		return ""
	}
	// The blank lines inside the block are required: without them GitHub renders the markdown
	// as literal text, so a numbered remedy arrives as one unbroken paragraph.
	return "<details><summary><b>Suggested fix</b></summary>\n\n" + s + "\n\n</details>\n\n"
}

// headline is the finding's one-line title: severity, then the rule's human name.
// The rule ID is deliberately absent — it is our vocabulary, not the reviewer's, and
// it already travels in the hidden marker for de-duplication.
func Headline(f wire.Finding) string {
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
			fmt.Fprintf(&b, "- **%s** at `%s`", Headline(f), loc)
			if s := sanitiseProse(strings.TrimSpace(f.Issue)); s != "" {
				b.WriteString("\n  " + indent(s))
			}
			// Folded for CommentBody's reason: these carry the same remedy, and several of
			// them in one summary is the longest thing this lane ever posts.
			if s := sanitiseProse(strings.TrimSpace(f.Fix)); s != "" {
				b.WriteString("\n  <details><summary><b>Suggested fix</b></summary>\n\n  " +
					indent(s) + "\n\n  </details>")
			}
			// ⚠️ AN UNANCHORED FINDING CARRIES ITS MARKER TOO, OR IT IS THE ONE CLASS A RE-RUN
			// CANNOT RECOGNISE. It never becomes an inline comment, so without a marker
			// somewhere `PostedMarkers` has nothing to find and every later push restates it.
			// It goes AFTER the model-authored prose for `markerIn`'s reason, and that prose
			// has already been through `sanitiseProse`, so a forged marker cannot reach here.
			b.WriteString("\n  " + Marker(f))
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

	if in.Truncated {
		b.WriteString("**This pull request is larger than this review covers.** Some of its files were not read, so treat the result as covering part of the change.\n\n")
	}

	// ⚠️ A CLEAN REVIEW STOPS HERE, AND THE TWO FOOTERS IT DROPS ARE BOTH ABOUT FINDINGS
	// IT DOES NOT HAVE. `AdvisoryNote` exists because a security comment from a bot is read as
	// a gate; "no findings" cannot be read as a gate, so on this path the sentence answers a
	// question nobody asked and is the second of three paragraphs under a one-line result. The
	// base is what the findings were found against, and with none there is nothing for it to
	// qualify. On a pull request that gets several pushes this block is most of what the lane
	// ever says, and a bot that says three paragraphs to report nothing is one people mute.
	//
	// ⚠️ THE SECTIONS ABOVE ARE NOT FOOTERS AND ARE DELIBERATELY OUTSIDE THIS: a clean
	// review that SKIPPED files still names them, and a TRUNCATED one still says it covered part
	// of the change. Those state what was not looked at, which is exactly the claim a bare "no
	// findings" would otherwise overstate.
	if in.Total == 0 {
		return b.String()
	}

	if in.Base != "" {
		fmt.Fprintf(&b, "Compared against `%s`.\n\n", in.Base)
	}
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
	// Truncated says the pull request was larger than the lane's own caps, so this
	// review covers PART of it.
	//
	// ⚠️ IT IS STATED, NEVER LEFT TO THE READER TO INFER. A partial review presented as
	// a whole one is the one failure every bounded read in this codebase is written to
	// avoid, and here it would put a green "no findings" on a pull request most of which
	// nothing looked at.
	Truncated bool
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

// ANCHORING AND DE-DUPLICATION, SHARED BY BOTH DRIVERS.
//
// ⚠️ THIS IS THE HALF THAT MUST NOT EXIST TWICE. There are two things driving this lane
// now — a workflow runner with the repository on disk, and the server answering a webhook
// — and everything below decides what a customer actually sees: which findings are
// attached to a line, which are stated in prose because their line is outside the diff,
// and which are held back as already posted. A second copy would drift, and the ways it
// drifts are all silent: a duplicated comment on every push, or a finding suppressed
// because one driver's marker comparison is a shade different from the other's.
//
// What the drivers keep for themselves is how they LEARN the change set (git, or the REST
// API) and how they report progress (a step log, or slog).

// Anchors is the set of line numbers a finding may be attached to, per path.
//
// ⚠️ IT IS BUILT FROM THE ADDED LINES, AND THE CHECK BEFORE POSTING IS NOT OPTIONAL.
// GitHub refuses the WHOLE comments array if one comment names a line outside the diff, so
// a single unanchorable finding would silence every other comment on the review.
type Anchors map[string]map[int]bool

// Add records a path's added line numbers.
func (a Anchors) Add(path string, lines []int) {
	if len(lines) == 0 {
		return
	}
	m := a[path]
	if m == nil {
		m = make(map[int]bool, len(lines))
		a[path] = m
	}
	for _, n := range lines {
		m[n] = true
	}
}

// Has reports whether a comment at path:line would sit inside the diff.
func (a Anchors) Has(path string, line int) bool { return a[path][line] }

// AnchorsFor builds the index from a wire change set.
func AnchorsFor(changes []wire.ChangedFile) Anchors {
	a := make(Anchors, len(changes))
	for _, c := range changes {
		a.Add(c.Path, c.AddedLines)
	}
	return a
}

// AssembleInput is one review's worth of material.
type AssembleInput struct {
	// Findings as the judge returned them. Assemble sorts them in place.
	Findings []wire.Finding
	Anchors  Anchors
	// Posted are the markers already on the pull request from an earlier push. A nil map
	// posts everything, which is the safe direction: a duplicate comment is a nuisance, a
	// suppressed finding is a missed detection.
	Posted        map[string]bool
	FilesReviewed int
	SkippedFiles  []string
	Base          string
	Truncated     bool
	// ReviewID is the review this run's findings came from, carried into every inline
	// comment so a later push can credit a fix back to it. Empty simply omits the marker.
	ReviewID string
	// ReviewIDByMarker overrides ReviewID per finding, keyed by Marker(f). It exists
	// because a change set too large for one request is reviewed in SEVERAL, and each
	// finding then came from a different review.
	//
	// ⚠️ THE ATTRIBUTION IS LOAD-BEARING, NOT COSMETIC. prresolve groups open threads by
	// (ReviewID, commit) and re-judges each group against that review, writing the
	// resolution event under it. One review id stamped across findings that came from
	// several reviews would credit fixes to a review that never raised them — a quietly
	// wrong remediation record, which is worse than a missing one.
	//
	// A marker absent here falls back to ReviewID, so the single-request lane and every
	// existing caller are unaffected by passing nothing.
	ReviewIDByMarker map[string]string
}

// reviewIDFor is the one place the per-finding override and the whole-run default meet.
func (in AssembleInput) reviewIDFor(f wire.Finding) string {
	if id, ok := in.ReviewIDByMarker[Marker(f)]; ok && id != "" {
		return id
	}
	return in.ReviewID
}

// Assembled is what to post, plus the counts the caller reports.
type Assembled struct {
	Body     string
	Comments []InlineComment
	// Total, Inline and AlreadyPosted are derived from the ONE findings list the body
	// states, so a caller's own log cannot disagree with the summary a reader sees.
	Total         int
	Inline        int
	AlreadyPosted int
	Unanchored    []wire.Finding
	// New counts the findings this run would say something about that an earlier push has
	// not already said — the inline comments plus any unanchored finding stated for the
	// first time. It is what `Post` reads; see there for why a run with none posts nothing.
	New int
	// Unrefined counts what UnrefinedRules dropped. Reported in the caller's log and
	// deliberately NOWHERE in the posted body: a pull request stating "2 findings were not
	// shown" invites exactly the question the exclusion exists to stop asking.
	Unrefined int
}

// Post reports whether this run has anything worth posting.
//
// ⚠️ A RE-RUN WITH NOTHING NEW POSTS NOTHING AT ALL, AND THE SUMMARY IS THE REASON. The marker
// de-dup already stops an inline comment repeating, but the summary body was posted
// unconditionally, so every push added another "## LeoPrevent security review" block to the
// conversation: ten pushes, ten summaries, each individually accurate and collectively the
// noise that gets the check deleted. Observed on the LEO-231 smoke-test pull request.
//
// ⚠️ THE FIRST RUN ALWAYS POSTS, INCLUDING A CLEAN ONE. `New` is zero on a clean pull request,
// and a clean review is the one result a reader most needs stated — silence is what an
// unconfigured lane looks like. So an empty `Posted` map means nothing has been said yet and
// this run says it; a later push with nothing new stays quiet.
//
// ACCEPTED COST, stated rather than hidden: a re-run that changes only the SKIPPED files or the
// truncation notice says nothing, because no finding is new. The summary already on the pull
// request is then one push stale about which files were excluded.
func (a Assembled) Post(posted map[string]bool) bool {
	return a.New > 0 || len(posted) == 0
}

// Assemble decides what a review posts.
func Assemble(in AssembleInput) Assembled {
	SortFindings(in.Findings)
	out := Assembled{}
	for _, f := range in.Findings {
		// The two broadest rules never become a comment. Dropped BEFORE the totals, so the
		// summary counts what it actually reports rather than a figure the reader cannot
		// reconcile with the comments beneath it. See UnrefinedRules.
		if !IsRefined(f.Rule) {
			out.Unrefined++
			continue
		}
		out.Total++
		path, line := SplitLocation(f.Location)
		if line == 0 || !in.Anchors.Has(path, line) {
			// Stated IN FULL in the summary rather than counted: existing code a change
			// routes into is often the finding worth reading. It carries its marker there,
			// so a later push can tell it has already been stated.
			if AlreadyPosted(in.Posted, f) {
				out.AlreadyPosted++
			} else {
				out.New++
			}
			out.Unanchored = append(out.Unanchored, f)
			continue
		}
		if AlreadyPosted(in.Posted, f) {
			out.AlreadyPosted++
			continue
		}
		out.New++
		out.Comments = append(out.Comments, InlineComment{
			Path: path, Line: line, Side: "RIGHT", Body: CommentBody(f, in.reviewIDFor(f)),
		})
	}
	out.Inline = len(out.Comments)
	out.Body = SummaryBody(SummaryInput{
		Total:         out.Total,
		Inline:        out.Inline,
		AlreadyPosted: out.AlreadyPosted,
		FilesReviewed: in.FilesReviewed,
		Unanchored:    out.Unanchored,
		SkippedFiles:  in.SkippedFiles,
		Base:          in.Base,
		Truncated:     in.Truncated,
	})
	return out
}
