// Package prreview drives the PULL-REQUEST review lane: it runs the same
// gate → select → judge loop the Stop hook runs, over a pull request's diff instead
// of one turn's, and posts what it finds as review comments.
//
// Faithfulness is by REUSE, exactly as clirun's is: the changes come from
// vcs.DiffRange (the hook path's own collector over a commit range), the inert gate
// is gate.Run, and the review is an engine.Reviewer built by delivery.New. Nothing
// here judges anything.
//
// ⚠️ ADVISORY, ALWAYS. This lane never blocks a merge and never fails a build by
// default, which is the no-blocking-gate non-negotiable in its second costume. A
// false positive that blocks a Stop costs one developer one turn; a false positive
// that blocks a merge queue costs a whole team, and the first one uninstalls the
// product. Every failure path here — a review error, an unreachable server, a
// refused comment, a malformed event — logs and exits 0.
package prreview

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// defaultAPI is github.com's REST root. Overridden by $GITHUB_API_URL, which GitHub
// Enterprise Server sets for us, so an Enterprise customer needs no flag.
const defaultAPI = "https://api.github.com"

// maxCommentPages bounds the existing-comment scan. A pull request with more than
// this many pages of review comments is not one anybody is reading, and an unbounded
// walk on a lane that must never delay a build is a worse failure than a duplicate
// comment. Over the bound we post anyway: repeating a finding is a nuisance, and
// staying silent about one is the thing this product exists to prevent.
const maxCommentPages = 5

// Client is the narrow slice of GitHub's REST API this lane needs. It is
// deliberately hand-rolled on net/http rather than pulling in a client library: the
// plugin module is self-contained and open-sourceable, and its dependency list is
// part of what a customer audits before installing a security tool.
type Client struct {
	Token string // the workflow's GITHUB_TOKEN; needs pull-requests: write
	Owner string
	Repo  string
	API   string // defaults to defaultAPI
	HTTP  *http.Client
}

// InlineComment is one finding anchored to a line of the pull request's diff.
type InlineComment struct {
	Path string `json:"path"`
	Line int    `json:"line"`
	Side string `json:"side"` // always "RIGHT": a finding names a line of the proposed code
	Body string `json:"body"`
}

type reviewPayload struct {
	Body     string          `json:"body"`
	Event    string          `json:"event"`
	Comments []InlineComment `json:"comments,omitempty"`
}

// api resolves the REST root and PROVES it is somewhere we may send a credential.
//
// ⚠️ THE BASE COMES FROM $GITHUB_API_URL, SO IT IS A VALUE WE DID NOT CHOOSE, AND EVERY
// REQUEST BUILT ON IT CARRIES `Authorization: Bearer <GITHUB_TOKEN>`. Left unchecked, a base
// pointing anywhere would exfiltrate a token with `pull-requests: write` on the customer's
// repository — the whole point of the header is that it is only ever sent to GitHub.
//
// Three things it checks, in the order that matters:
//   - it PARSES. A prefix test says the string looks right; `url.Parse` says where a request
//     will actually go. The parser also strips tabs and rewrites backslashes, so
//     `https:/<TAB>/evil.example` does not sneak past a `strings.HasPrefix`.
//   - the SCHEME is https, or http on a LOOPBACK host. Loopback is carved out for tests and a
//     developer running a fake API locally; nothing else may downgrade, because a plaintext
//     hop puts the token on the wire.
//   - it carries NO USERINFO, query or fragment. A base of
//     `https://evil.example@api.github.com` reads as GitHub to a human and resolves to
//     `evil.example`, which is the one shape a hostname allowlist would also miss.
//
// A base that fails any of these is REFUSED rather than replaced with the default: falling
// back would silently send an Enterprise customer's review to github.com. The refusal
// surfaces as an error on the one call that needs it, and the lane fails open around it.
func (c Client) api() (*url.URL, error) {
	raw := strings.TrimSpace(c.API)
	if raw == "" {
		raw = defaultAPI
	}
	raw = strings.TrimRight(raw, "/")
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("github: unusable API base %q: %w", raw, err)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("github: API base %q names no host", raw)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("github: API base %q carries credentials or a query; refusing to send a token to it", raw)
	}
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && isLoopback(u.Hostname()):
	default:
		return nil, fmt.Errorf("github: API base %q is not https (and not loopback); refusing to send a token over it", raw)
	}
	// Returned as the PARSED root, and every request is then assembled from its fields
	// rather than by concatenating strings. A URL built by string arithmetic is a URL
	// nobody can reason about: the scheme, the host and the path stop being separable, so
	// a mistake in the path can only be caught by re-parsing and comparing, which is a
	// guard that has to be remembered. Assembling from a validated root means the origin
	// is not a value the path can reach at all.
	return &url.URL{Scheme: u.Scheme, Host: u.Host, Path: strings.TrimRight(u.Path, "/")}, nil
}

// isLoopback reports whether a host is this machine. Named hosts are compared literally
// rather than resolved: a DNS lookup here would let a name that resolves to 127.0.0.1 today
// point elsewhere tomorrow, which is the whole class this guard exists for.
func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

func (c Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	// A bounded timeout because this runs inside a CI step: a hung GitHub call must
	// cost the job seconds, not its whole time budget.
	//
	// ⚠️ REDIRECTS ARE NOT FOLLOWED, AND THAT IS WHAT MAKES THE ORIGIN CHECK MEAN ANYTHING.
	// Validating the base is worthless against a 302: Go's default client follows up to ten
	// of them and RE-SENDS the Authorization header on a same-host hop, so a validated origin
	// answering `Location: http://169.254.169.254/…` would walk the token straight to a cloud
	// metadata endpoint. ErrUseLastResponse hands the 3xx back instead, which the status check
	// in `do` then reports as a legible error rather than as data.
	return &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// pathFor builds an API URL with every interpolated segment escaped. The owner and
// repository come from $GITHUB_REPOSITORY, which is ours, but they are still values
// we did not choose — and a segment carrying `..` or a query character addresses a
// different resource entirely.
func (c Client) pathFor(format string, args ...any) string {
	esc := make([]any, len(args))
	for i, a := range args {
		switch v := a.(type) {
		case string:
			esc[i] = url.PathEscape(v)
		default:
			esc[i] = a
		}
	}
	return fmt.Sprintf(format, esc...)
}

// do issues one request against the API, and it RESOLVES AND RE-PROVES THE ORIGIN ITSELF
// rather than accepting a URL from a caller.
//
// ⚠️ THE VALIDATION IS AT THE SINK, WHICH IS THE POINT. An earlier version took a fully
// composed `target string` and trusted that whoever built it had validated the base. That is
// check-then-use across a function boundary: the guard was real but nothing tied it to the
// request, so a call site added later — or a helper that composed a URL some other way —
// would silently reach `http.NewRequest` unvalidated. Taking a PATH makes the origin
// impossible to supply, and the request cannot be built without `api()` having passed. It is
// the same call `lib/sameorigin.ts` makes one console over, for the same reason.
//
// The resolved URL is then compared against the validated base ORIGIN, because resolution can
// move it: a path beginning `//evil.example/x` resolves to a different host entirely, and a
// path is a value we format rather than a constant.
func (c Client) do(method, path string, body any) ([]byte, *http.Response, error) {
	root, err := c.api()
	if err != nil {
		return nil, nil, err
	}
	// The request URL is ASSEMBLED from the validated root's own fields. The path supplies
	// only Path and RawQuery, so it cannot name a scheme, a host or userinfo however it is
	// spelled — the origin is structurally out of its reach rather than checked afterwards.
	rel, err := url.Parse(path)
	if err != nil {
		return nil, nil, fmt.Errorf("github: unusable request path %q: %w", path, err)
	}
	u := &url.URL{
		Scheme:   root.Scheme,
		Host:     root.Host,
		Path:     root.Path + rel.Path,
		RawQuery: rel.RawQuery,
	}
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, nil, err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, u.String(), rdr)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	// Bounded read: the response is ours to parse, and an unbounded ReadAll on a
	// remote body is a memory hole even when the remote is trustworthy.
	data, rerr := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if rerr != nil {
		return nil, resp, rerr
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return data, resp, fmt.Errorf("github: %s %s: %s: %s",
			method, redactTarget(path), resp.Status, firstLine(string(data)))
	}
	return data, resp, nil
}

// PostedMarkers returns the marker of every finding this lane has already commented
// on this pull request, so a re-run after a push does not repeat itself.
//
// ⚠️ IT FAILS TOWARD POSTING. A failed or truncated scan returns what it managed to
// read, so the worst outcome is a duplicated comment; returning "everything is
// already posted" on a failed read would silently suppress a real finding, which is
// the one direction this lane may not fail in.
func (c Client) PostedMarkers(pr int) map[string]bool {
	seen := map[string]bool{}
	for page := 1; page <= maxCommentPages; page++ {
		path := c.pathFor("/repos/%s/%s/pulls/%d/comments?per_page=100&page=%d", c.Owner, c.Repo, pr, page)
		data, _, err := c.do(http.MethodGet, path, nil)
		if err != nil {
			return seen
		}
		var batch []struct {
			Body string `json:"body"`
		}
		if json.Unmarshal(data, &batch) != nil {
			return seen
		}
		for _, cm := range batch {
			if m := markerIn(cm.Body); m != "" {
				seen[m] = true
			}
		}
		if len(batch) < 100 {
			break
		}
	}
	return seen
}

// PostReview posts ONE review carrying the summary body and every inline comment,
// as event COMMENT.
//
// ⚠️ COMMENT, NEVER REQUEST_CHANGES. REQUEST_CHANGES registers as a blocking review
// on the pull request — it is the merge-blocking gate this lane exists not to be,
// arrived at through a payload field rather than through a required check. There is
// no flag for it.
//
// One call rather than one per comment: a partial post leaves a review whose summary
// counts findings it did not manage to attach, and GitHub applies the whole array
// atomically. If the array is refused as a whole (a line outside the diff that our
// own anchoring check missed), the caller retries with the summary alone, so the
// findings still reach the pull request.
func (c Client) PostReview(pr int, body string, comments []InlineComment) error {
	path := c.pathFor("/repos/%s/%s/pulls/%d/reviews", c.Owner, c.Repo, pr)
	_, _, err := c.do(http.MethodPost, path, reviewPayload{Body: body, Event: "COMMENT", Comments: comments})
	return err
}

// redactTarget strips the query string from a request path before it reaches a log line.
// Only paging parameters travel there today, but an error message is the one place a future
// credential-bearing parameter would leak without anybody noticing.
func redactTarget(target string) string {
	if i := strings.IndexByte(target, '?'); i >= 0 {
		return target[:i]
	}
	return target
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}
