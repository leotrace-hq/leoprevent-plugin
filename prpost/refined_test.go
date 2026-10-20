package prpost

import (
	"strings"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

// THE TWO RULES A PULL REQUEST IS NEVER COMMENTED ON, AND THE COUNTS THAT FOLLOW FROM IT.
//
// These fire wherever a value crosses a trust boundary without an explicit check, so on a real
// repository they dominate by volume. On a dashboard that costs a click; in a review conversation
// it is a bot commenting on every function, and the team's answer is to remove the bot.

func find(rule, loc string) wire.Finding {
	return wire.Finding{Rule: rule, Location: loc, Issue: "i", Fix: "f"}
}

func anchors(path string, lines ...int) Anchors {
	a := Anchors{}
	a.Add(path, lines)
	return a
}

func TestTheTwoBroadestRulesAreNeverCommentedOn(t *testing.T) {
	// Arrange
	in := AssembleInput{
		Findings: []wire.Finding{
			find("no-input-validation", "app.py:3"),
			find("db-trust", "app.py:3"),
			find("ssrf", "app.py:3"),
		},
		Anchors:       anchors("app.py", 3),
		FilesReviewed: 1,
	}

	// Act
	a := Assemble(in)

	// Assert
	if a.Inline != 1 || len(a.Comments) != 1 {
		t.Fatalf("got %d inline comments, want only the ssrf one", a.Inline)
	}
	if a.Comments[0].Body == "" || !strings.Contains(a.Comments[0].Body, "leoprevent:ssrf") {
		t.Fatalf("the surviving comment is not the ssrf one:\n%s", a.Comments[0].Body)
	}
	if a.Unrefined != 2 {
		t.Errorf("Unrefined = %d, want 2", a.Unrefined)
	}
}

// ⚠️ THE TOTAL COUNTS WHAT IS REPORTED, NOT WHAT WAS DETECTED. A summary reading "3 findings"
// above one comment is a figure the reader cannot reconcile with the page in front of them.
func TestTheSummaryCountsOnlyWhatItReports(t *testing.T) {
	a := Assemble(AssembleInput{
		Findings:      []wire.Finding{find("db-trust", "app.py:3"), find("ssrf", "app.py:3")},
		Anchors:       anchors("app.py", 3),
		FilesReviewed: 1,
	})
	if a.Total != 1 {
		t.Fatalf("Total = %d, want 1", a.Total)
	}
	if strings.Contains(a.Body, "2 findings") {
		t.Errorf("the body counts a finding it does not show:\n%s", a.Body)
	}
}

// ⚠️ AND IT SAYS NOTHING ABOUT WHAT IT DROPPED. "2 findings were not shown" invites exactly the
// question the exclusion exists to stop being asked, on somebody else's pull request.
func TestTheBodyNeverMentionsTheDroppedRules(t *testing.T) {
	a := Assemble(AssembleInput{
		Findings:      []wire.Finding{find("db-trust", "app.py:3"), find("ssrf", "app.py:3")},
		Anchors:       anchors("app.py", 3),
		FilesReviewed: 1,
	})
	for _, w := range []string{"db-trust", "no-input-validation", "not shown", "excluded", "hidden"} {
		if strings.Contains(strings.ToLower(a.Body), w) {
			t.Errorf("the body mentions %q:\n%s", w, a.Body)
		}
	}
}

// An unknown rule is REFINED — a finding we cannot classify must not be the one we drop.
func TestAnUnknownRuleIsStillCommentedOn(t *testing.T) {
	if !IsRefined("some-rule-added-next-quarter") || !IsRefined("") {
		t.Fatal("an unclassifiable rule was dropped")
	}
}

// --- posting only when there is something new ------------------------------------------

func TestARerunWithNothingNewPostsNothing(t *testing.T) {
	// Arrange: the one finding is already commented on.
	f := find("ssrf", "app.py:3")
	posted := map[string]bool{Marker(f): true}

	// Act
	a := Assemble(AssembleInput{
		Findings: []wire.Finding{f}, Anchors: anchors("app.py", 3), Posted: posted, FilesReviewed: 1,
	})

	// Assert
	if a.New != 0 {
		t.Fatalf("New = %d, want 0", a.New)
	}
	if a.Post() {
		t.Error("a re-run with nothing new would have posted another summary")
	}
}

func TestARerunWithANewFindingStillPosts(t *testing.T) {
	old := find("ssrf", "app.py:3")
	posted := map[string]bool{Marker(old): true}
	a := Assemble(AssembleInput{
		Findings: []wire.Finding{old, find("open-redirect", "app.py:2")},
		Anchors:  anchors("app.py", 2, 3), Posted: posted, FilesReviewed: 1,
	})
	if a.New != 1 {
		t.Fatalf("New = %d, want 1", a.New)
	}
	if !a.Post() {
		t.Error("a genuinely new finding was not posted")
	}
}

// ⚠️ A CLEAN RUN POSTS NOTHING, THE FIRST ONE INCLUDED — the reversal of "the first run always
// posts". A clean review carries no marker, so it read as a first run on EVERY push and left one
// "No findings" comment per push. Mutation check: restore `|| len(posted) == 0` and this fails.
func TestACleanRunPostsNothingEvenTheFirstTime(t *testing.T) {
	a := Assemble(AssembleInput{FilesReviewed: 1})
	if a.New != 0 {
		t.Fatalf("New = %d, want 0 on a clean run", a.New)
	}
	if a.Post() {
		t.Error("a clean run would have posted a comment nobody needed")
	}
}

// The same run, twice: nothing this lane posts on a clean review can make the second one differ,
// which is why the first one has to stay quiet too.
func TestACleanRunStaysQuietOnEveryPush(t *testing.T) {
	first := Assemble(AssembleInput{FilesReviewed: 1})
	posted := map[string]bool{}
	for _, m := range markersIn(first.Body) {
		posted[m] = true
	}
	if len(posted) != 0 {
		t.Fatalf("a clean summary carried markers: %v", posted)
	}
	second := Assemble(AssembleInput{FilesReviewed: 1, Posted: posted})
	if second.Post() {
		t.Error("the second push would have repeated the clean comment")
	}
}

// Nothing reviewed is not a clean result and does not borrow one's wording — but it is still
// nothing to say, so it is not a comment either.
func TestARunThatReviewedNothingPostsNothing(t *testing.T) {
	if Assemble(AssembleInput{FilesReviewed: 0}).Post() {
		t.Error("a pull request with nothing reviewable would have been commented on")
	}
}

// --- the unanchored finding, which has no inline comment to carry its marker ------------

func TestAnUnanchoredFindingCarriesItsMarkerInTheSummary(t *testing.T) {
	// Arrange: the cited line is outside the diff, so it can never be an inline comment.
	f := find("ssrf", "other.py:99")

	// Act
	a := Assemble(AssembleInput{Findings: []wire.Finding{f}, Anchors: anchors("app.py", 3), FilesReviewed: 1})

	// Assert
	if len(a.Unanchored) != 1 || a.Inline != 0 {
		t.Fatalf("expected one unanchored finding and no comment; got %+v", a)
	}
	if !strings.Contains(a.Body, Marker(f)) {
		t.Fatalf("the summary carries no marker, so a later push cannot tell it was stated:\n%s", a.Body)
	}
	if got := markersIn(a.Body); len(got) != 1 || got[0] != Marker(f) {
		t.Fatalf("markersIn read %v", got)
	}
}

func TestAnUnanchoredFindingIsNotRestatedOnTheNextPush(t *testing.T) {
	f := find("ssrf", "other.py:99")
	first := Assemble(AssembleInput{Findings: []wire.Finding{f}, Anchors: anchors("app.py", 3), FilesReviewed: 1})

	// The next push reads the markers back out of the summary it posted.
	posted := map[string]bool{}
	for _, m := range markersIn(first.Body) {
		posted[m] = true
	}
	second := Assemble(AssembleInput{
		Findings: []wire.Finding{f}, Anchors: anchors("app.py", 3), Posted: posted, FilesReviewed: 1,
	})
	if second.New != 0 || second.AlreadyPosted != 1 {
		t.Fatalf("New=%d AlreadyPosted=%d, want 0 and 1", second.New, second.AlreadyPosted)
	}
	if second.Post() {
		t.Error("the same out-of-diff finding would have been restated")
	}
}

// ⚠️ markersIn TAKES EVERY MARKER, unlike markerIn. Two unanchored findings in one summary means
// the second would be restated on every push if only the last were read.
func TestMarkersInReadsAllOfThem(t *testing.T) {
	a := Assemble(AssembleInput{
		Findings:      []wire.Finding{find("ssrf", "other.py:99"), find("open-redirect", "other.py:12")},
		Anchors:       anchors("app.py", 3),
		FilesReviewed: 1,
	})
	if got := markersIn(a.Body); len(got) != 2 {
		t.Fatalf("markersIn read %d markers, want 2: %v", len(got), got)
	}
}

// --- the span, and the duplicate it exists to stop ---------------------------------------

func spanned(rule, loc string, end int) wire.Finding {
	f := find(rule, loc)
	f.EndLine = end
	return f
}

// ⚠️ THE LIVE DUPLICATE THIS FIXES. On the LEO-231 smoke test the same SSRF came back as the
// taint source (`target = request.args.get(...)`, line 13) and then as the sink
// (`requests.get(target)`, line 17) — both defensible citations of one flaw, four lines apart,
// where MarkerLineTolerance is three. It was commented on twice.
func TestASinkAndItsTaintSourceAreOneFinding(t *testing.T) {
	// Arrange: the first run cited the source and marked the whole handler.
	first := spanned("ssrf", "app.py:13", 22)
	posted := map[string]bool{Marker(first): true}

	// Act: the next run cites the sink, outside the tolerance window.
	later := find("ssrf", "app.py:17")

	// Assert
	if !AlreadyPosted(posted, later) {
		t.Fatal("the sink read as a new finding, so the same flaw is commented on twice")
	}
}

// ⚠️ AND THE OTHER WAY ROUND, because either run may be the one that carried the span.
func TestASpanAlsoCoversAPreviouslyPostedLine(t *testing.T) {
	posted := map[string]bool{Marker(find("ssrf", "app.py:17")): true}
	if !AlreadyPosted(posted, spanned("ssrf", "app.py:13", 22)) {
		t.Fatal("a new span covering the posted line read as a new finding")
	}
}

// ⚠️ AND A POSTED SPAN LATER IN THE FILE MUST NOT SWALLOW AN EARLIER FINDING. This is the case
// a one-sided check gets wrong: testing only that the new line falls under the posted span's END
// matches any finding above it, so a span at 100-120 would suppress a real finding at line 13 —
// detected, recorded and never mentioned. Both bounds, or the containment is not containment.
func TestAPostedSpanDoesNotSwallowAnEarlierFinding(t *testing.T) {
	posted := map[string]bool{Marker(spanned("ssrf", "app.py:100", 120)): true}
	if AlreadyPosted(posted, find("ssrf", "app.py:13")) {
		t.Fatal("a finding 87 lines above the posted span was suppressed")
	}
}

// ⚠️ A SPAN MUST NOT COLLAPSE TWO GENUINELY SEPARATE FINDINGS — the reason the tolerance was
// kept small in the first place. Two sinks of one rule in one file, outside each other's spans,
// are two comments.
func TestTwoSeparateSinksAreStillTwoFindings(t *testing.T) {
	posted := map[string]bool{Marker(spanned("ssrf", "app.py:10", 20)): true}
	if AlreadyPosted(posted, spanned("ssrf", "app.py:80", 90)) {
		t.Fatal("a separate sink was suppressed — a missed detection wearing a duplicate's clothing")
	}
}

// ⚠️ MARKERS WRITTEN BEFORE SPANS EXISTED ARE ON LIVE PULL REQUESTS. A format only the new code
// reads would make every one unrecognisable and restate every finding once.
func TestALineOnlyMarkerStillParsesAndStillMatches(t *testing.T) {
	legacy := markerPrefix + "ssrf:app.py:13 -->"
	r, p, l, e, ok := parseMarker(legacy)
	if !ok || r != "ssrf" || p != "app.py" || l != 13 || e != 13 {
		t.Fatalf("parseMarker(%q) = %q %q %d %d %v", legacy, r, p, l, e, ok)
	}
	if !AlreadyPosted(map[string]bool{legacy: true}, find("ssrf", "app.py:14")) {
		t.Error("the tolerance window stopped working for a marker with no span")
	}
}

// ⚠️ AN OVERSIZED OR MALFORMED SPAN IS IGNORED, NOT HONOURED. A marker claiming 1-9999 would
// silence a whole file for that rule; the marker degrades to its own line instead.
func TestAnOversizedSpanIsIgnored(t *testing.T) {
	huge := markerPrefix + "ssrf:app.py:1-9999 -->"
	_, _, l, e, ok := parseMarker(huge)
	if !ok || l != 1 || e != 1 {
		t.Fatalf("an oversized span was honoured: line=%d end=%d ok=%v", l, e, ok)
	}
	if AlreadyPosted(map[string]bool{huge: true}, find("ssrf", "app.py:500")) {
		t.Error("a forged span suppressed a finding 500 lines away")
	}
}

func TestMarkerWritesTheSpanOnlyWhenThereIsOne(t *testing.T) {
	if got := Marker(find("ssrf", "app.py:13")); got != markerPrefix+"ssrf:app.py:13 -->" {
		t.Errorf("Marker with no span = %q", got)
	}
	if got := Marker(spanned("ssrf", "app.py:13", 22)); got != markerPrefix+"ssrf:app.py:13-22 -->" {
		t.Errorf("Marker with a span = %q", got)
	}
	// An over-cap span is not written either, so it cannot be read back.
	if got := Marker(spanned("ssrf", "app.py:13", 13+MaxMarkerSpan+1)); !strings.HasSuffix(got, ":13 -->") {
		t.Errorf("an over-cap span reached the marker: %q", got)
	}
}

// --- the folded remedy ------------------------------------------------------------------

// ⚠️ FOLDED, NEVER TRUNCATED. A developer who applies half a guard has shipped an incomplete fix
// believing they followed the advice — LEO-120's call, and here the comment is the ONLY place
// this remedy is shown, so dropping it outright is not available either.
func TestTheRemedyIsFoldedAndComplete(t *testing.T) {
	f := find("ssrf", "app.py:13")
	f.Fix = "1. Parse the URL.\n2. Resolve it.\n3. Reject private ranges."
	body := CommentBody(f, "")

	if !strings.Contains(body, "<details><summary><b>Suggested fix</b></summary>") {
		t.Fatalf("the remedy is not folded:\n%s", body)
	}
	if !strings.Contains(body, "3. Reject private ranges.") {
		t.Errorf("the remedy was truncated; every word must survive the fold:\n%s", body)
	}
	// The issue itself stays open: it is the finding, and folding it would hide what was found.
	if !strings.Contains(body, f.Issue) || strings.Index(body, f.Issue) > strings.Index(body, "<details>") {
		t.Errorf("the issue must render above the fold:\n%s", body)
	}
}

func TestAFindingWithNoRemedyRendersNoFold(t *testing.T) {
	f := find("ssrf", "app.py:13")
	f.Fix = ""
	if strings.Contains(CommentBody(f, ""), "<details>") {
		t.Error("an empty remedy rendered an empty fold")
	}
}
