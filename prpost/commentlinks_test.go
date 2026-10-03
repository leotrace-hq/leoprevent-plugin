package prpost

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

// WHERE EACH FINDING WAS PUBLISHED.
//
// The review POST answers with the REVIEW, whose anchor names the whole block, so a comment's
// own `#discussion_r<id>` exists only after GitHub has minted it. These pin the read-back and
// the two directions it is allowed to fail in.

// commentsStub serves one page of review comments.
func commentsStub(t *testing.T, body string) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, body)
	}))
	t.Cleanup(srv.Close)
	return &Client{Token: "t", Owner: "o", Repo: "r", API: srv.URL}
}

func TestCommentLinksMapsEachMarkerToItsOwnComment(t *testing.T) {
	// Arrange
	c := commentsStub(t, `[
	  {"body":"SSRF here.\n\n<!-- leoprevent:ssrf:app/fetch.py:17 -->","html_url":"https://github.com/o/r/pull/1#discussion_r1"},
	  {"body":"IDOR here.\n\n<!-- leoprevent:idor-object-level-authz:report.py:15 -->","html_url":"https://github.com/o/r/pull/1#discussion_r2"}
	]`)

	// Act
	got := c.CommentLinks(1)

	// Assert
	want := map[string]string{
		"<!-- leoprevent:ssrf:app/fetch.py:17 -->":                 "https://github.com/o/r/pull/1#discussion_r1",
		"<!-- leoprevent:idor-object-level-authz:report.py:15 -->": "https://github.com/o/r/pull/1#discussion_r2",
	}
	for marker, url := range want {
		if got[marker] != url {
			t.Errorf("marker %q mapped to %q, want %q", marker, got[marker], url)
		}
	}
	// ⚠️ ONE ANCHOR PER FINDING, NEVER ONE PER PULL REQUEST. Two findings on one pull request
	// share every part of the URL but the fragment, so a read that lost the fragment would look
	// entirely correct while landing every reader at the top of the same conversation.
	if got["<!-- leoprevent:ssrf:app/fetch.py:17 -->"] == got["<!-- leoprevent:idor-object-level-authz:report.py:15 -->"] {
		t.Error("two findings resolved to one URL: the per-comment anchor was dropped")
	}
}

func TestACommentWithNoMarkerOrNoURLIsNotLinked(t *testing.T) {
	// A human's reply carries no marker of ours, and a comment we cannot address is worse than
	// no link: the caller falls back to the pull request, which is where the link pointed before.
	// Arrange
	c := commentsStub(t, `[
	  {"body":"Looks fine to me.","html_url":"https://github.com/o/r/pull/1#discussion_r9"},
	  {"body":"SSRF.\n\n<!-- leoprevent:ssrf:app/fetch.py:17 -->","html_url":""}
	]`)

	// Act
	got := c.CommentLinks(1)

	// Assert
	if len(got) != 0 {
		t.Errorf("linked %v; a comment with no marker, or no URL, must not be linked", got)
	}
}

func TestAFailedListingLosesLinksAndNeverSuppressesAFinding(t *testing.T) {
	// THE TWO CALLERS FAIL IN OPPOSITE DIRECTIONS OFF ONE WALK, which is why they share it:
	// a truncated read leaves `CommentLinks` without a URL (a link to the pull request, never a
	// link to the wrong comment) and leaves `PostedMarkers` believing fewer findings are posted
	// (a duplicate comment, never a suppressed finding).
	// Arrange
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	c := Client{Token: "t", Owner: "o", Repo: "r", API: srv.URL}

	// Act
	links := c.CommentLinks(1)
	posted := c.PostedMarkers(1)

	// Assert
	if len(links) != 0 {
		t.Errorf("a failed listing invented links: %v", links)
	}
	if len(posted) != 0 {
		t.Errorf("a failed listing invented posted markers: %v", posted)
	}
}

func TestACommentLinkResolvesBackToTheFindingThatWroteIt(t *testing.T) {
	// THE MARKER IS THE ONLY IDENTITY A COMMENT AND A FINDING SHARE, so the body this lane
	// writes and the key the link is filed under have to agree. Driven through `CommentBody`
	// rather than a hand-written marker, since a test writing its own string would go green
	// against a renderer that had stopped emitting one.
	// Arrange
	f := wire.Finding{Rule: "ssrf", Location: "app/fetch.py:17", Issue: "i", Fix: "f"}
	c := commentsStub(t, fmt.Sprintf(`[{"body":%q,"html_url":"https://github.com/o/r/pull/1#discussion_r1"}]`,
		CommentBody(f, "rev1")))

	// Act
	got := c.CommentLinks(1)

	// Assert
	rule, path, line, ok := ParseMarker(Marker(f))
	if !ok {
		t.Fatal("the finding's own marker does not parse")
	}
	if rule != "ssrf" || path != "app/fetch.py" || line != 17 {
		t.Fatalf("marker parsed as %q %q %d", rule, path, line)
	}
	if got[Marker(f)] != "https://github.com/o/r/pull/1#discussion_r1" {
		t.Errorf("the finding's own marker did not resolve: %v", got)
	}
}
