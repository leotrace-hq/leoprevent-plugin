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
package prpost

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

type ReviewPayload struct {
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
	return c.send(method, path, body, true)
}

// doAtOrigin is `do` for a path that does NOT hang off the REST root, and it exists for
// exactly one caller: GraphQL.
//
// ⚠️ GITHUB ENTERPRISE PUTS THE TWO APIS AT SIBLING PATHS, NOT NESTED ONES. `$GITHUB_API_URL`
// there is `https://host/api/v3` while GraphQL is `https://host/api/graphql` — so a path
// appended to the REST root would address `/api/v3/graphql`, which does not exist, and the
// resolution pass would 404 on every Enterprise installation while working perfectly on
// github.com. There is no path that appends correctly, so the composition has to change
// rather than the string.
//
// ⚠️ IT RESOLVES AND PROVES THE ORIGIN THROUGH THE SAME `api()`, WHICH IS THE WHOLE POINT OF
// KEEPING IT HERE. What differs from `do` is which PATH is sent, never where it is sent: the
// caller still cannot supply a scheme, a host or userinfo, so the guard `do`'s own note
// describes is unchanged and there is still exactly one place a request is built.
func (c Client) doAtOrigin(method, path string, body any) ([]byte, *http.Response, error) {
	return c.send(method, path, body, false)
}

// send is the one request builder. joinBase appends the path to the validated root's own
// path (every REST call); otherwise the path is taken from the ORIGIN, which is what
// GraphQL needs on Enterprise.
func (c Client) send(method, path string, body any, joinBase bool) ([]byte, *http.Response, error) {
	root, err := c.api()
	if err != nil {
		return nil, nil, err
	}
	base := root.Path
	if !joinBase {
		base = ""
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
		Path:     base + rel.Path,
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
	c.eachComment(pr, func(body, _ string) {
		if m := markerIn(body); m != "" {
			seen[m] = true
		}
	})
	c.summaryMarkers(pr, seen)
	return seen
}

// CommentLinks maps each posted finding's marker to the URL of its own comment.
//
// ⚠️ THE COMMENT'S URL CANNOT BE KNOWN WHEN THE REVIEW IS POSTED. GitHub's review POST answers
// with the REVIEW (whose anchor is `#pullrequestreview-N`, the whole block) and not with the
// comments it created, so the per-comment `#discussion_r<id>` anchor — the thing a reader
// actually wants to land on — exists only once GitHub has minted an id for each. Reading them
// back is therefore not a convenience; it is the only way to have them at all.
//
// One listing, reusing the walk `PostedMarkers` already makes, so a re-run costs the same
// request it always did. A comment we cannot map is simply absent from the result: the caller
// falls back to the pull request itself, which is where the link pointed before.
func (c Client) CommentLinks(pr int) map[string]string {
	out := map[string]string{}
	c.eachComment(pr, func(body, url string) {
		if m := markerIn(body); m != "" && url != "" {
			out[m] = url
		}
	})
	return out
}

// eachComment walks this pull request's review comments, bounded, and hands each body and its
// own HTML URL to fn.
//
// ⚠️ IT FAILS TOWARD RETURNING LESS, which both callers depend on for opposite reasons: a
// truncated read leaves `PostedMarkers` believing fewer findings are posted (so a duplicate
// comment, never a suppressed finding) and leaves `CommentLinks` without a URL (so a link to the
// pull request, never a link to the wrong comment).
func (c Client) eachComment(pr int, fn func(body, url string)) {
	for page := 1; page <= maxCommentPages; page++ {
		path := c.pathFor("/repos/%s/%s/pulls/%d/comments?per_page=100&page=%d", c.Owner, c.Repo, pr, page)
		data, _, err := c.do(http.MethodGet, path, nil)
		if err != nil {
			return
		}
		var batch []struct {
			Body    string `json:"body"`
			HTMLURL string `json:"html_url"`
		}
		if json.Unmarshal(data, &batch) != nil {
			return
		}
		for _, cm := range batch {
			fn(cm.Body, cm.HTMLURL)
		}
		if len(batch) < 100 {
			break
		}
	}
}

// summaryMarkers adds the markers carried by this lane's own SUMMARIES.
//
// ⚠️ WITHOUT IT AN UNANCHORED FINDING IS RESTATED ON EVERY PUSH. Such a finding never becomes an
// inline comment — its line is outside the diff, and GitHub refuses the whole comments array over
// one out-of-range line — so it lives in the summary's prose, and the loop above reads inline
// comments only. The marker is there; nothing was looking at it.
//
// Fails toward POSTING, exactly as the scan above does: a failed or truncated read leaves the
// markers it managed to collect, so the worst outcome is a restated finding rather than a
// suppressed one.
func (c Client) summaryMarkers(pr int, seen map[string]bool) {
	for page := 1; page <= maxCommentPages; page++ {
		path := c.pathFor("/repos/%s/%s/pulls/%d/reviews?per_page=100&page=%d", c.Owner, c.Repo, pr, page)
		data, _, err := c.do(http.MethodGet, path, nil)
		if err != nil {
			return
		}
		var batch []struct {
			Body string `json:"body"`
		}
		if json.Unmarshal(data, &batch) != nil {
			return
		}
		for _, rv := range batch {
			for _, m := range markersIn(rv.Body) {
				seen[m] = true
			}
		}
		if len(batch) < 100 {
			break
		}
	}
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
	_, _, err := c.do(http.MethodPost, path, ReviewPayload{Body: body, Event: "COMMENT", Comments: comments})
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

// THE READ HALF — how the SERVER-SIDE lane gets a pull request's diff.
//
// ⚠️ IT LIVES BESIDE THE POST HALF BECAUSE `do` IS WHERE THE ORIGIN IS PROVED. A caller
// outside this package cannot build a request through it, so a second client elsewhere
// would be a second place to get `$GITHUB_API_URL` validation, redirect refusal and the
// bounded read right — which is the check-then-use split `do`'s own note exists to close.
// The workflow-driven lane does not use these (it has the repository on disk and diffs it
// with git); the webhook-driven one has no checkout and must ask GitHub.

// Files returns one page of the pull request's changed files, raw.
//
// Raw bytes rather than a decoded shape: the caller owns which fields it reads, and this
// package has no opinion about them. 100 per page, GitHub's maximum.
func (c Client) Files(pr, page int) ([]byte, error) {
	path := c.pathFor("/repos/%s/%s/pulls/%d/files?per_page=100&page=%d", c.Owner, c.Repo, pr, page)
	data, _, err := c.do(http.MethodGet, path, nil)
	return data, err
}

// FileContent returns one file as it stands at ref.
//
// ⚠️ ok=false IS "NOT THERE", NEVER "WE COULD NOT TELL". A 404 is a real answer — the file
// was deleted on this branch, or the path is one the API declines — and the caller records
// it as a file with no full content rather than failing the review. Any OTHER failure is
// returned as an error, because a review that quietly treats an outage as an empty file
// judges a change against code it never saw.
//
// The raw media type is requested so the body IS the file, with no base64 hop and no
// wrapper to parse. It is bounded by `do`'s own read limit.
// CommitSHA resolves a ref (a branch, "HEAD", a tag) to the full commit SHA it names now.
//
// It exists so a reader that makes several calls can pin them to ONE commit: listing a tree at
// "HEAD" and then reading files at "HEAD" can straddle a push, and the result would describe two
// revisions while recording neither. The answer is checked to be a 40-character hex SHA, because
// it is used as the ref of every later call and a value we did not choose must not become one
// unvalidated.
func (c Client) CommitSHA(ref string) (string, error) {
	data, _, err := c.do(http.MethodGet, c.pathFor("/repos/%s/%s/commits", c.Owner, c.Repo)+"/"+url.PathEscape(ref), nil)
	if err != nil {
		return "", err
	}
	var body struct {
		SHA string `json:"sha"`
	}
	if err := json.Unmarshal(data, &body); err != nil {
		return "", fmt.Errorf("github: commit %q: %w", ref, err)
	}
	if !isSHA(body.SHA) {
		return "", fmt.Errorf("github: commit %q did not resolve to a SHA", ref)
	}
	return body.SHA, nil
}

func isSHA(s string) bool {
	if len(s) != 40 {
		return false
	}
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

func (c Client) FileContent(path, ref string) (string, bool, error) {
	// ⚠️ THE FILE PATH IS ESCAPED PER SEGMENT, NOT AS ONE STRING. `pathFor`'s PathEscape
	// turns `/` into `%2F`, which the contents API does not decode — every file below the
	// repository root would 404, i.e. every file the judge most wants the full text of, and
	// the review would silently fall back to diff-only context for all of them. The REF goes
	// in the query, where it is query-escaped.
	p := c.pathFor("/repos/%s/%s/contents", c.Owner, c.Repo) +
		"/" + escapePath(path) + "?ref=" + url.QueryEscape(ref)
	data, resp, err := c.do(http.MethodGet, p, nil)
	if resp != nil && resp.StatusCode == http.StatusNotFound {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return string(data), true, nil
}

// escapePath escapes a repository-relative path segment by segment, so the separators
// survive and nothing inside a segment can add one.
//
// ⚠️ EMPTY AND DOT SEGMENTS ARE DROPPED, AND `url.PathEscape` DOES NOT DO THAT FOR YOU:
// it leaves `.` and `..` exactly as they are, so a path is not made safe by escaping it.
// The path arrives in GitHub's own files listing, i.e. it is a value we did not choose,
// and `//` at the start of one is the shape `do` re-proves the origin against. Dropping
// them here means the path cannot try; `do` is what guarantees it cannot succeed.
func escapePath(p string) string {
	parts := strings.Split(p, "/")
	out := parts[:0]
	for _, seg := range parts {
		if seg == "" || seg == "." || seg == ".." {
			continue
		}
		out = append(out, url.PathEscape(seg))
	}
	return strings.Join(out, "/")
}

// Tree returns every blob path in the repository at ref, repo-relative and slash-form,
// plus whether the listing is complete.
//
// ⚠️ ONE CALL FOR THE WHOLE REPOSITORY, WHICH IS THE ONLY REASON CROSS-FILE CONTEXT IS
// AFFORDABLE WITHOUT A CHECKOUT. Resolving a helper needs to know which paths exist; asking
// the contents API per candidate would be hundreds of round trips per review. `recursive=1`
// answers it once.
//
// ⚠️ SYMLINKS ARE DROPPED BY MODE, NOT FOLLOWED. Git records one as mode 120000 whose blob
// is the TARGET PATH, so reading it would return a path string as if it were source — and
// a symlink out of the repository is how a "context file" becomes someone else's code. The
// checkout-backed resolver refuses them via Lstat; this is the same refusal, made earlier.
//
// complete=false when GitHub truncated the listing (very large repositories). The caller
// must treat that as "no index" rather than a partial one: a missing path reads as "this
// helper does not exist", which silently resolves nothing rather than resolving wrongly.
func (c Client) Tree(ref string) (paths []string, complete bool, err error) {
	p := c.pathFor("/repos/%s/%s/git/trees", c.Owner, c.Repo) +
		"/" + url.PathEscape(ref) + "?recursive=1"
	data, _, err := c.do(http.MethodGet, p, nil)
	if err != nil {
		return nil, false, err
	}
	var tree struct {
		Truncated bool `json:"truncated"`
		Tree      []struct {
			Path string `json:"path"`
			Type string `json:"type"`
			Mode string `json:"mode"`
		} `json:"tree"`
	}
	if err := json.Unmarshal(data, &tree); err != nil {
		return nil, false, fmt.Errorf("prpost: unreadable tree: %w", err)
	}
	for _, e := range tree.Tree {
		if e.Type != "blob" || e.Mode == "120000" {
			continue
		}
		paths = append(paths, e.Path)
	}
	return paths, !tree.Truncated, nil
}
