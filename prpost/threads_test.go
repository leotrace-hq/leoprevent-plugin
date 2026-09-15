package prpost

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

// THE RESOLVE HALF — the parts a type check cannot see and a live run fails quietly on.
//
// Every failure here is silent by construction: a GraphQL error arrives as HTTP 200, a
// wrong endpoint answers 404 on Enterprise alone, and a thread we should not have touched
// resolves exactly as cleanly as one we should. So these assert the bytes on the wire and
// the threads that survive the filter.

// graphQLStub serves one canned GraphQL response and records the request body.
func graphQLStub(t *testing.T, body string) (*Client, *string, *string) {
	t.Helper()
	var path, sent string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		sent = string(b)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return &Client{Token: "t", Owner: "acme", Repo: "api", API: srv.URL}, &path, &sent
}

// threadsResponse renders the shape GitHub returns for the reviewThreads connection.
func threadsResponse(nodes string) string {
	return `{"data":{"repository":{"pullRequest":{"reviewThreads":{` +
		`"pageInfo":{"hasNextPage":false,"endCursor":""},"nodes":[` + nodes + `]}}}}}`
}

func threadNode(id, body string, mine, resolved bool, commit string) string {
	b, _ := json.Marshal(body)
	oc := "null"
	if commit != "" {
		oc = `{"oid":"` + commit + `"}`
	}
	m, r := "false", "false"
	if mine {
		m = "true"
	}
	if resolved {
		r = "true"
	}
	return `{"id":"` + id + `","isResolved":` + r +
		`,"comments":{"nodes":[{"id":"` + id + `_c","body":` + string(b) +
		`,"viewerDidAuthor":` + m + `,"isMinimized":false,"originalCommit":` + oc + `}]}}`
}

func TestAThreadCarriesTheFindingAndTheReviewThatRaisedIt(t *testing.T) {
	// Arrange: a body exactly as CommentBody composes one.
	f := wire.Finding{Rule: "ssrf", Location: "app/fetch.py:13", Issue: "attacker controlled url"}
	body := CommentBody(f, "rev123")
	c, path, _ := graphQLStub(t, threadsResponse(threadNode("T_1", body, true, false, "oldsha")))

	// Act
	got, err := c.ReviewThreads(4)

	// Assert
	if err != nil {
		t.Fatalf("ReviewThreads: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d threads, want 1", len(got))
	}
	if got[0].ID != "T_1" || got[0].CommentID != "T_1_c" || got[0].Commit != "oldsha" || got[0].Resolved {
		t.Fatalf("thread = %+v", got[0])
	}
	if got[0].Marker != Marker(f) {
		t.Fatalf("marker = %q, want %q", got[0].Marker, Marker(f))
	}
	// Without this the resolution pass has no review to credit the fix against, so the
	// dashboard row stays Warned however cleanly the flaw was fixed.
	if got[0].ReviewID != "rev123" {
		t.Fatalf("ReviewID = %q, want rev123", got[0].ReviewID)
	}
	if *path != "/graphql" {
		t.Fatalf("posted to %s", *path)
	}
}

func TestAThreadThisAppDidNotWriteIsNeverReturned(t *testing.T) {
	// ⚠️ A MARKER IS TEXT ANYBODY CAN TYPE. Keyed on it alone, a human review comment
	// quoting one of ours would come back as a thread of ours — and the only thing this
	// package does with a thread is RESOLVE it, i.e. close somebody's question as though we
	// had answered it. Authorship is GitHub's own answer and cannot be spoofed by content.
	// Arrange
	body := CommentBody(wire.Finding{Rule: "ssrf", Location: "a.py:1"}, "rev1")
	c, _, _ := graphQLStub(t, threadsResponse(threadNode("T_theirs", body, false, false, "sha")))

	// Act
	got, err := c.ReviewThreads(4)

	// Assert
	if err != nil {
		t.Fatalf("ReviewThreads: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("a thread we did not author came back: %+v", got)
	}
}

func TestAThreadWithNoMarkerNamesNoFinding(t *testing.T) {
	// Arrange: our own comment, but prose only — a reply, or a comment from some other
	// feature. There is nothing a re-judge could decide about it.
	c, _, _ := graphQLStub(t, threadsResponse(threadNode("T_2", "thanks, fixed", true, false, "sha")))

	// Act
	got, _ := c.ReviewThreads(4)

	// Assert
	if len(got) != 0 {
		t.Fatalf("a markerless thread came back: %+v", got)
	}
}

func TestAGraphQLErrorIsAFailureEvenThoughItArrivesAs200(t *testing.T) {
	// ⚠️ THE ONE FAILURE `do`'S STATUS CHECK CANNOT SEE. A permission refusal, a malformed
	// query or a rate limit all answer 200 with an `errors` array and an empty `data`, so a
	// caller reading only the status would see "no threads" — which is indistinguishable
	// from "nothing left to resolve", i.e. a resolution pass that had silently stopped
	// working.
	// Arrange
	c, _, _ := graphQLStub(t, `{"data":null,"errors":[{"message":"Resource not accessible by integration"}]}`)

	// Act
	_, err := c.ReviewThreads(4)

	// Assert
	if err == nil {
		t.Fatal("a GraphQL error read as a successful empty response")
	}
	if !strings.Contains(err.Error(), "not accessible") {
		t.Fatalf("the error did not carry GitHub's own message: %v", err)
	}
}

func TestClosingAFindingResolvesTheConversation(t *testing.T) {
	// ⚠️ THE CONVERSATION, NOT JUST THE COMMENT. Collapsing our own comment leaves the thread
	// open, so the pull request goes on counting it as an unresolved conversation and the
	// "Resolve conversation" button stays on screen — which is what a reviewer reads as the
	// finding still being outstanding.
	// Arrange
	c, path, sent := graphQLStub(t, `{"data":{"resolveReviewThread":{"thread":{"id":"T_1","isResolved":true}}}}`)

	// Act
	how, err := c.MarkResolved("T_1", "T_1_c")

	// Assert
	if err != nil {
		t.Fatalf("MarkResolved: %v", err)
	}
	if how != ClosedThread {
		t.Fatalf("closed = %q, want %q", how, ClosedThread)
	}
	if *path != "/graphql" {
		t.Fatalf("posted to %s", *path)
	}
	if !strings.Contains(*sent, "resolveReviewThread") {
		t.Fatalf("the thread mutation was not sent: %s", *sent)
	}
	// The id travels as a VARIABLE rather than interpolated into the query, so a node id
	// GitHub gave us cannot become part of the document we send.
	var req graphQLRequest
	if err := json.Unmarshal([]byte(*sent), &req); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if req.Variables["id"] != "T_1" {
		t.Fatalf("variables = %+v", req.Variables)
	}
	if strings.Contains(req.Query, "T_1") {
		t.Fatalf("the id was interpolated into the query: %s", req.Query)
	}
}

func TestAnInstallationWithoutWriteStillGetsItsCommentCollapsed(t *testing.T) {
	// ⚠️ THIS IS THE ROLLOUT, NOT A CONTINGENCY. `resolveReviewThread` needs push access to
	// the repository (`contents: write` for an App), and adding a permission does NOT reach
	// existing installations: GitHub mails every org owner and each keeps its old set until a
	// human accepts. So for as long as that takes, some installations can close a conversation
	// and some cannot — and the second group must still get its fixed findings collapsed
	// rather than nothing at all.
	// Arrange: the thread mutation refused exactly as GitHub refuses it, the comment one fine.
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		calls++
		if strings.Contains(string(b), "resolveReviewThread") {
			_, _ = w.Write([]byte(`{"data":{"resolveReviewThread":null},"errors":[{"message":"Resource not accessible by integration"}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"data":{"minimizeComment":{"minimizedComment":{"isMinimized":true,"minimizedReason":"resolved"}}}}`))
	}))
	t.Cleanup(srv.Close)
	c := Client{Token: "t", Owner: "acme", Repo: "api", API: srv.URL}

	// Act
	how, err := c.MarkResolved("T_1", "T_1_c")

	// Assert
	if err != nil {
		t.Fatalf("a permission refusal was reported as a failure: %v", err)
	}
	if how != ClosedComment {
		t.Fatalf("closed = %q, want %q", how, ClosedComment)
	}
	if calls != 2 {
		t.Fatalf("made %d calls, want 2 (the refusal, then the fallback)", calls)
	}
}

func TestAnOrdinaryFailureIsNotAnsweredByTheWeakerMutation(t *testing.T) {
	// ⚠️ ONLY A PERMISSION REFUSAL EARNS THE FALLBACK. A network failure, a bad id or a rate
	// limit answered by collapsing the comment instead would report a narrower success for a
	// call that never had a permission problem, and would bury the real error behind a second
	// one — on the path whose whole job is telling a reviewer a finding is closed.
	// Arrange
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		_, _ = w.Write([]byte(`{"data":null,"errors":[{"message":"Something went wrong while executing your query"}]}`))
	}))
	t.Cleanup(srv.Close)
	c := Client{Token: "t", Owner: "acme", Repo: "api", API: srv.URL}

	// Act
	_, err := c.MarkResolved("T_1", "T_1_c")

	// Assert
	if err == nil {
		t.Fatal("an ordinary GraphQL failure was reported as a close")
	}
	if calls != 1 {
		t.Fatalf("made %d calls, want 1: the fallback ran for a non-permission failure", calls)
	}
}

func TestGraphQLIsASiblingOfTheRestRootOnEnterprise(t *testing.T) {
	// ⚠️ ENTERPRISE SERVES REST AT `/api/v3` AND GRAPHQL AT `/api/graphql`. Appending to the
	// REST root addresses `/api/v3/graphql`, which does not exist — so the resolution pass
	// would 404 on every Enterprise installation while working perfectly on github.com,
	// which is the shape nobody notices until a customer reports it.
	// Arrange / Act / Assert
	for _, tc := range []struct{ base, want string }{
		{"", "/graphql"},
		{"https://api.github.com", "/graphql"},
		{"https://ghe.acme.test/api/v3", "/api/graphql"},
	} {
		c := Client{API: tc.base}
		if got := c.graphQLPath(); got != tc.want {
			t.Fatalf("base %q: graphQLPath = %q, want %q", tc.base, got, tc.want)
		}
	}
}

func TestTheReviewMarkerCannotBeConfusedWithAFindingMarker(t *testing.T) {
	// The two markers sit in one body, so each reader must see only its own. A collision
	// either way is silent: the de-duplication would key on a review id, or the resolution
	// pass would credit a fix to a rule name.
	// Arrange
	f := wire.Finding{Rule: "ssrf", Location: "app/fetch.py:13"}
	body := CommentBody(f, "rev123")

	// Act / Assert
	if got := markerIn(body); got != Marker(f) {
		t.Fatalf("markerIn = %q, want %q", got, Marker(f))
	}
	if got := ReviewIDIn(body); got != "rev123" {
		t.Fatalf("ReviewIDIn = %q, want rev123", got)
	}
	if got := markersIn(body); len(got) != 1 || got[0] != Marker(f) {
		t.Fatalf("markersIn = %q", got)
	}
	// A body from before the review marker existed still parses, and still de-duplicates:
	// every comment on every live pull request is one of those.
	legacy := CommentBody(f, "")
	if strings.Contains(legacy, reviewMarkerPrefix) {
		t.Fatalf("an empty review id emitted a marker: %s", legacy)
	}
	if got := markerIn(legacy); got != Marker(f) {
		t.Fatalf("legacy markerIn = %q", got)
	}
	if got := ReviewIDIn(legacy); got != "" {
		t.Fatalf("legacy ReviewIDIn = %q, want empty", got)
	}
}

func TestAnUnusableReviewIDIsNeitherWrittenNorRead(t *testing.T) {
	// The id is server-minted and arrives through a response, so it is a value we did not
	// choose; and what is written here goes into a customer's pull request.
	// Act / Assert
	for _, bad := range []string{"", "rev 123", "rev\"123", "rev-->", strings.Repeat("a", maxReviewIDLen+1)} {
		if got := ReviewMarker(bad); got != "" {
			t.Fatalf("ReviewMarker(%q) = %q, want nothing", bad, got)
		}
	}
	if got := ReviewIDIn("<!-- leoprevent-review:rev 123 -->"); got != "" {
		t.Fatalf("a malformed marker read back as %q", got)
	}
	if got := ReviewMarker("rev_123-abc"); got == "" {
		t.Fatal("a legitimate id emitted no marker")
	}
}

func TestACommentWeAlreadyCollapsedIsNotOfferedAgain(t *testing.T) {
	// ⚠️ THE DONE STATE IS TWO FLAGS OR'D, AND ONE OF THEM IS THE ONLY ONE WE EVER SET.
	// `minimizeComment` collapses the comment and leaves the THREAD open, so reading
	// `isResolved` alone would report every finding this lane has ever closed as still open —
	// re-judging each of them on every push for ever, at Opus prices, to reach the answer
	// already on the page.
	// Arrange: our own comment, already minimized, on an unresolved thread.
	body := CommentBody(wire.Finding{Rule: "ssrf", Location: "a.py:1"}, "rev1")
	b, _ := json.Marshal(body)
	node := `{"id":"T_1","isResolved":false,"comments":{"nodes":[{"id":"T_1_c","body":` + string(b) +
		`,"viewerDidAuthor":true,"isMinimized":true,"originalCommit":{"oid":"sha"}}]}}`
	c, _, _ := graphQLStub(t, threadsResponse(node))

	// Act
	got, err := c.ReviewThreads(4)

	// Assert
	if err != nil {
		t.Fatalf("ReviewThreads: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d threads, want 1", len(got))
	}
	if !got[0].Resolved {
		t.Fatal("a comment we had already collapsed came back as still open")
	}
}
