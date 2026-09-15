package prpost

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// THE READ HALF'S URLs, which no type check can see and a live run fails quietly on.
//
// A malformed contents URL does not error: GitHub answers 404, `FileContent` reports
// "not there", and the review proceeds against the diff alone. So the judge silently
// loses the full file for exactly the files it most needs one for, and every test that
// stubs the Fetcher still passes. These assert the bytes that actually go on the wire.

// capture serves a stub API and records what was asked for.
func capture(t *testing.T, status int, body string) (*Client, *string) {
	t.Helper()
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.RequestURI()
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return &Client{Token: "t", Owner: "acme", Repo: "api", API: srv.URL}, &got
}

func TestAFileBelowTheRepositoryRootIsAddressable(t *testing.T) {
	// Arrange
	c, got := capture(t, http.StatusOK, "print('hi')\n")

	// Act
	content, ok, err := c.FileContent("src/app/handlers.py", "abc123")

	// Assert
	if err != nil || !ok {
		t.Fatalf("FileContent: ok=%v err=%v", ok, err)
	}
	if content != "print('hi')\n" {
		t.Fatalf("content = %q", content)
	}
	if strings.Contains(*got, "%2F") {
		t.Fatalf("the separators were escaped, so every nested file 404s: %s", *got)
	}
	if !strings.HasPrefix(*got, "/repos/acme/api/contents/src/app/handlers.py?") {
		t.Fatalf("asked for %s", *got)
	}
	if !strings.Contains(*got, "ref=abc123") {
		t.Fatalf("the ref did not reach the query: %s", *got)
	}
}

func TestAMissingFileIsAnAnswerAndAnOutageIsNot(t *testing.T) {
	// ok=false must mean "not there" — a deletion, or a path the API declines — never
	// "we could not tell". Treating an outage as an empty file judges a change against
	// code the judge never saw.
	// Arrange
	gone, _ := capture(t, http.StatusNotFound, `{"message":"Not Found"}`)
	broken, _ := capture(t, http.StatusInternalServerError, `{"message":"boom"}`)

	// Act + Assert
	if _, ok, err := gone.FileContent("src/app.py", "abc"); ok || err != nil {
		t.Fatalf("a 404 gave ok=%v err=%v, want false / nil", ok, err)
	}
	if _, _, err := broken.FileContent("src/app.py", "abc"); err == nil {
		t.Fatal("a 500 was reported as a file that is simply not there")
	}
}

func TestTheFilesPageIsAskedForWholePages(t *testing.T) {
	// Arrange
	c, got := capture(t, http.StatusOK, `[]`)

	// Act
	if _, err := c.Files(42, 2); err != nil {
		t.Fatalf("Files: %v", err)
	}

	// Assert
	if *got != "/repos/acme/api/pulls/42/files?per_page=100&page=2" {
		t.Fatalf("asked for %s", *got)
	}
}

func TestAPathCannotSmuggleAnOriginPastTheEscape(t *testing.T) {
	// The path reaches us from GitHub's own files listing, so it is a value we did not
	// choose. `do` proves the origin whatever happens; this keeps the path from even
	// trying, which is what makes that proof a second line rather than the only one.
	// Arrange
	c, got := capture(t, http.StatusOK, "x")

	// Act
	if _, _, err := c.FileContent("/../../evil.example/x", "r"); err != nil {
		t.Fatalf("FileContent: %v", err)
	}

	// Assert
	if strings.Contains(*got, "//") || strings.Contains(*got, "/../") {
		t.Fatalf("the path kept a traversal or an authority: %s", *got)
	}
	if !strings.HasPrefix(*got, "/repos/acme/api/contents/") {
		t.Fatalf("asked for %s", *got)
	}
}
