package prpost

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

// TestNoPostedCopyNamesAnAuthor is the surviving half of the authorship guarantee.
//
// ⚠️ THE DISCLAIMER WAS REMOVED AND THE RULE IT DEFENDED WAS NOT. A pull request's added lines
// are the BRANCH'S, possibly several people's over days, so nothing this lane writes may
// attribute a line to whoever opened the pull request. That was previously asserted by
// requiring a sentence SAYING so, which is the weaker test of the two: it passes over copy that
// both disclaims authorship and then accuses somebody two paragraphs later.
//
// So the assertion is now purely the property, over every surface this lane posts. And the
// removed sentence is pinned as an ABSENCE, because restoring it reads like an improvement: it
// is 200 italicised characters on EVERY comment, which on a five-finding pull request is six
// repetitions of a disclaimer about an attribution nothing here makes.
func TestNoPostedCopyNamesAnAuthor(t *testing.T) {
	f := wire.Finding{Rule: "ssrf", Name: "SSRF", Severity: "high", Location: "app.py:3", Issue: "i", Fix: "f"}
	bodies := []string{
		CommentBody(f, ""),
		CommentBody(f, "rev1"),
		SummaryBody(SummaryInput{Total: 1, Inline: 1, FilesReviewed: 1, Base: "main"}),
		SummaryBody(SummaryInput{Total: 1, Inline: 0, Unanchored: []wire.Finding{f}, FilesReviewed: 1, Base: "main"}),
		SummaryBody(SummaryInput{FilesReviewed: 3, Base: "main"}),
		SkipBody("The review could not be completed.", "boom"),
	}
	banned := []string{"you introduced", "your code", "you added", "you wrote", "the author of", "authored by"}
	for _, b := range bodies {
		low := strings.ToLower(b)
		for _, phrase := range banned {
			if strings.Contains(low, phrase) {
				t.Errorf("copy attributes authorship (%q) in:\n%s", phrase, b)
			}
		}
		if strings.Contains(low, "cannot tell who wrote") {
			t.Errorf("the authorship disclaimer is back; it was removed on purpose (see render.go):\n%s", b)
		}
	}
}

func TestNoDashesInPostedCopy(t *testing.T) {
	f := wire.Finding{Rule: "ssrf", Name: "SSRF", Severity: "high", Location: "app.py:3", Issue: "i", Fix: "f"}
	bodies := map[string]string{
		"inline":  CommentBody(f, ""),
		"summary": SummaryBody(SummaryInput{Total: 1, Inline: 1, AlreadyPosted: 1, FilesReviewed: 2, Unanchored: []wire.Finding{f}, SkippedFiles: []string{"README.md"}, Base: "main"}),
		"clean":   SummaryBody(SummaryInput{FilesReviewed: 3, Base: "main"}),
		"skip":    SkipBody("The review could not be completed.", "boom"),
	}
	for name, b := range bodies {
		for _, dash := range []string{"\u2014", "\u2013"} {
			if strings.Contains(b, dash) {
				t.Errorf("%s body uses a dash as punctuation: %s", name, b)
			}
		}
	}
}

func TestNoSuggestionBlock(t *testing.T) {
	f := wire.Finding{Rule: "ssrf", Location: "app.py:3", Issue: "i", Fix: "resolve the host first"}
	if strings.Contains(CommentBody(f, ""), "```suggestion") {
		t.Error("no comment may carry a GitHub suggestion block")
	}
}

func TestTheTokenIsNeverSentToAnUnvalidatedOrigin(t *testing.T) {
	for _, tc := range []struct {
		name, base string
		ok         bool
	}{
		{"github", "https://api.github.com", true},
		{"enterprise", "https://github.acme.com/api/v3", true},
		{"trailing slash", "https://api.github.com/", true},
		{"loopback http, for tests and local development", "http://127.0.0.1:8080", true},
		{"localhost http", "http://localhost:8080", true},

		{"plaintext elsewhere", "http://api.github.com", false},
		{"another scheme entirely", "file:///etc/passwd", false},
		// ⚠️ Reads as GitHub to a human and resolves to evil.example. A hostname
		// allowlist would miss this one too, which is why the check is on the PARSE.
		{"userinfo disguising the host", "https://api.github.com@evil.example", false},
		{"no host at all", "https:///repos", false},
		{"a query on the base", "https://api.github.com?x=1", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Client{API: tc.base}.api()
			if tc.ok && err != nil {
				t.Errorf("base %q should be accepted: %v", tc.base, err)
			}
			if !tc.ok && err == nil {
				t.Errorf("base %q must be REFUSED: the token would be sent to it", tc.base)
			}
		})
	}
}

func TestARefusedBaseDoesNotFallBackToGithub(t *testing.T) {
	if err := (Client{API: "http://evil.example"}).PostReview(1, "body", nil); err == nil {
		t.Fatal("PostReview must refuse an unusable base rather than post somewhere else")
	}
}

func TestAForgedMarkerCannotSuppressAFinding(t *testing.T) {
	victim := wire.Finding{Rule: "sql-injection", Location: "db.py:12"}
	attacker := wire.Finding{
		Rule:     "ssrf",
		Location: "app.py:3",
		Issue:    "looks fine to me " + Marker(victim),
		Fix:      "nothing to do",
	}

	body := CommentBody(attacker, "")

	// The forged marker must not survive into the body at all.
	if strings.Contains(body, Marker(victim)) {
		t.Errorf("the judge's prose smuggled a marker into a posted body:\n%s", body)
	}
	// And whatever a body does carry, the marker READ back must be the one this lane
	// appended — never one chosen by the model.
	if got := markerIn(body); got != Marker(attacker) {
		t.Errorf("markerIn = %q, want this lane's own %q", got, Marker(attacker))
	}
}

func TestTheProseGuardIsAppliedToEveryModelAuthoredSurface(t *testing.T) {
	victim := wire.Finding{Rule: "sql-injection", Location: "db.py:12"}
	forged := Marker(victim)
	unanchored := wire.Finding{Rule: "ssrf", Location: "other.py:99", Issue: "x " + forged, Fix: "y " + forged}

	summary := SummaryBody(SummaryInput{Total: 1, FilesReviewed: 1, Unanchored: []wire.Finding{unanchored}, Base: "main"})
	if strings.Contains(summary, forged) {
		t.Errorf("the summary's unanchored list smuggled a marker:\n%s", summary)
	}
	// A skip notice quotes a server error, which is not ours either.
	if skip := SkipBody("The review could not be completed.", "boom "+forged); strings.Contains(skip, forged) {
		t.Errorf("the skip notice smuggled a marker:\n%s", skip)
	}
}

func TestNoPathCanMoveTheRequestOffTheAPIOrigin(t *testing.T) {
	var elsewhereReached bool
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		elsewhereReached = true
		w.WriteHeader(http.StatusOK)
	}))
	defer elsewhere.Close()

	var apiHits []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiHits = append(apiHits, r.URL.Path)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()
	c := Client{Token: "t", Owner: "o", Repo: "r", API: srv.URL}

	for _, path := range []string{
		"//evil.example/x",
		elsewhere.URL + "/x",
		"/repos/o/r/pulls/1/comments",
	} {
		_, _, _ = c.do(http.MethodGet, path, nil)
	}

	if elsewhereReached {
		t.Error("a request left the API origin: `do` must not be able to be handed one")
	}
	if len(apiHits) == 0 {
		t.Error("no request reached the API origin at all, so this proves nothing")
	}
}

func TestTheClientDoesNotFollowRedirects(t *testing.T) {
	var followed bool
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		followed = true
		if r.Header.Get("Authorization") != "" {
			t.Error("the token was sent to the redirect target")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer elsewhere.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+"/steal", http.StatusFound)
	}))
	defer srv.Close()

	c := Client{Token: "t", Owner: "o", Repo: "r", API: srv.URL}
	if err := c.PostReview(1, "body", nil); err == nil {
		t.Error("a redirect must surface as an error, not be followed and read as the API's answer")
	}
	if followed {
		t.Error("the client followed a redirect off the validated origin")
	}
}

func TestTheSummarySentencesReadAsEnglish(t *testing.T) {
	for _, tc := range []struct {
		name   string
		in     SummaryInput
		expect string
	}{
		{
			name:   "plural",
			in:     SummaryInput{Total: 2, Inline: 2, FilesReviewed: 1, Base: "main"},
			expect: "2 findings are attached to the lines they cite, in the diff below.",
		},
		{
			name:   "singular",
			in:     SummaryInput{Total: 1, Inline: 1, FilesReviewed: 1, Base: "main"},
			expect: "1 finding is attached to the lines it cites, in the diff below.",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := SummaryBody(tc.in)
			if !strings.Contains(body, tc.expect) {
				t.Fatalf("summary does not carry %q; got:\n%s", tc.expect, body)
			}
		})
	}

	// A doubled word is the shape the bug took, so it is refused generally rather than by
	// name. On WORD BOUNDARIES: a naive substring scan for "is is" matches inside "This is
	// advisory", which is the same false positive TestTheDefaultIsAdvisory had to be rewritten
	// to avoid.
	// Go's regexp is RE2 and has no backreferences, so the doubled word is found by walking
	// the words rather than by matching a pattern.
	word := regexp.MustCompile(`[A-Za-z]+`)
	for _, in := range []SummaryInput{
		{Total: 2, Inline: 2, AlreadyPosted: 1, FilesReviewed: 1, Base: "main"},
		{Total: 1, Inline: 1, AlreadyPosted: 2, FilesReviewed: 3, Base: "main"},
	} {
		body := SummaryBody(in)
		for _, line := range strings.Split(body, "\n") {
			words := word.FindAllString(line, -1)
			for i := 1; i < len(words); i++ {
				if strings.EqualFold(words[i], words[i-1]) {
					t.Fatalf("summary repeats %q:\n%s", words[i], body)
				}
			}
		}
	}
}

func TestTheToleranceNeverSuppressesADifferentFinding(t *testing.T) {
	posted := map[string]bool{
		"<!-- leoprevent:ssrf:app/handlers.py:40 -->": true,
	}
	for _, tc := range []struct {
		name string
		f    wire.Finding
	}{
		{"a different rule at the same line", wire.Finding{Rule: "no-input-validation", Location: "app/handlers.py:40"}},
		{"the same rule in a different file", wire.Finding{Rule: "ssrf", Location: "app/other.py:40"}},
		{"the same rule far enough away to be another sink", wire.Finding{Rule: "ssrf", Location: "app/handlers.py:44"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if AlreadyPosted(posted, tc.f) {
				t.Errorf("suppressed %s — a detected flaw would be recorded and never mentioned", tc.name)
			}
		})
	}

	// A marker that does not parse must fail TOWARD posting, never toward silence.
	for _, bad := range []string{
		"<!-- leoprevent:ssrf:app/handlers.py:notanumber -->",
		"<!-- leoprevent:nocolons -->",
		"not a marker at all",
	} {
		if AlreadyPosted(map[string]bool{bad: true}, wire.Finding{Rule: "ssrf", Location: "app/handlers.py:40"}) {
			t.Errorf("an unparseable marker (%q) suppressed a finding", bad)
		}
	}

	// A path carrying a colon still resolves, since the rule closes at the FIRST and
	// the line opens at the LAST.
	weird := map[string]bool{"<!-- leoprevent:ssrf:a:b/c.py:12 -->": true}
	if !AlreadyPosted(weird, wire.Finding{Rule: "ssrf", Location: "a:b/c.py:13"}) {
		t.Error("a path containing a colon broke the marker parse")
	}
}

// TestACleanReviewSaysOnlyThat pins the clean summary at its two lines.
//
// ⚠️ IT IS AN EXACT-EQUALITY ASSERTION, deliberately. Every other test here reaches for
// `strings.Contains`, which cannot see a paragraph being ADDED — and what this pins is an
// absence, so a containment test on the two lines it keeps would pass with three paragraphs of
// boilerplate under them. The rendered string is the whole comment a reviewer reads.
func TestACleanReviewSaysOnlyThat(t *testing.T) {
	const want = "## LeoPrevent security review\n\n" +
		"No findings on the 9 reviewed files in this pull request.\n\n"

	if got := SummaryBody(SummaryInput{FilesReviewed: 9, Base: "main"}); got != want {
		t.Fatalf("a clean review says more than its result:\nwant %q\ngot  %q", want, got)
	}
}

// TestACleanReviewStillNamesWhatItDidNotLookAt is the carve-out, and it is the half of the
// change that must not be lost to a later tidy-up of the one above.
//
// Dropping the footers is about findings the review does not have. What it did NOT look at is a
// different claim entirely: a silently absent file reads as one with nothing wrong in it, and a
// partial review presented as a whole one is the failure every bounded read in this codebase is
// written to prevent. Both are strictly MORE important on a clean pass, because "no findings" is
// what a reader would otherwise take them to qualify.
func TestACleanReviewStillNamesWhatItDidNotLookAt(t *testing.T) {
	body := SummaryBody(SummaryInput{
		FilesReviewed: 9,
		Base:          "main",
		SkippedFiles:  []string{"README.md"},
		Truncated:     true,
	})

	for _, want := range []string{"### Not reviewed", "README.md", "larger than this review covers"} {
		if !strings.Contains(body, want) {
			t.Fatalf("a clean review dropped %q along with its footers:\n%s", want, body)
		}
	}
}

// TestASummaryWITHFindingsKeepsItsFooters is the other side of the same rule, and without it the
// trim above is one edit away from applying to every review.
//
// Here both sentences earn their place: the base says what the findings were found against, and
// the advisory note answers the question a reviewer actually has on seeing security findings on
// their pull request, which is whether this blocks the merge. A reviewer who believes a merge is
// blocked goes looking for a check that does not exist.
func TestASummaryWITHFindingsKeepsItsFooters(t *testing.T) {
	body := SummaryBody(SummaryInput{Total: 1, Inline: 1, FilesReviewed: 1, Base: "main"})

	if !strings.Contains(body, "Compared against `main`.") {
		t.Error("a summary with findings no longer says what they were found against")
	}
	if !strings.Contains(body, AdvisoryNote) {
		t.Error("a summary with findings no longer says it blocks nothing")
	}
}
