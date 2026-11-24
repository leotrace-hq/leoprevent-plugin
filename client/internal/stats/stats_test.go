package stats

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

// capture records what the dashboard actually received.
type capture struct {
	path   string
	query  url.Values
	header http.Header
}

func serverFor(t *testing.T, status int, body string, got *capture) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.path = r.URL.Path
		got.query = r.URL.Query()
		got.header = r.Header.Clone()
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestReadSendsTheKeyAsABearerTokenAndNothingElse(t *testing.T) {
	// ⚠️ THE EGRESS STATEMENT DEPENDS ON THIS. Agent read access adds a READ, not a
	// disclosure: the request carries a view name, a few bounded filters and the license key.
	// Anything else appearing here would be a change to what leaves the developer's machine,
	// which is a docs/security.md change and not a quiet one.
	var got capture
	srv := serverFor(t, 200, `{"view":"stats"}`, &got)

	if _, err := New(srv.URL, "lp_live_secret").Read(Query{View: "stats", Days: 7}); err != nil {
		t.Fatal(err)
	}
	if got.path != "/api/agent" {
		t.Errorf("path = %q", got.path)
	}
	if auth := got.header.Get("Authorization"); auth != "Bearer lp_live_secret" {
		t.Errorf("Authorization = %q", auth)
	}
	if v := got.header.Get(wire.ClientVersionHeader); v == "" {
		t.Error("the client version header should be stamped, as it is on every review call")
	}
	// The key must never travel in the URL: it would land in every proxy log between the
	// developer and Vercel, and in the dashboard's own request log.
	for key, vals := range got.query {
		for _, v := range vals {
			if strings.Contains(v, "lp_live") {
				t.Errorf("the license key reached the query string as %s=%s", key, v)
			}
		}
	}
}

func TestEmptyQueryFieldsAreOmitted(t *testing.T) {
	// A `repo=` with no value is a filter the server would have to decide how to read. Not
	// sending it leaves one meaning for "no filter".
	var got capture
	srv := serverFor(t, 200, `{}`, &got)

	if _, err := New(srv.URL, "k").Read(Query{View: "repos"}); err != nil {
		t.Fatal(err)
	}
	for _, absent := range []string{"scope", "days", "repo", "rule", "limit"} {
		if got.query.Has(absent) {
			t.Errorf("%s should not have been sent, got %q", absent, got.query.Get(absent))
		}
	}
	if got.query.Get("view") != "repos" {
		t.Errorf("view = %q", got.query.Get("view"))
	}
}

func TestEveryFilterReachesTheQuery(t *testing.T) {
	var got capture
	srv := serverFor(t, 200, `{}`, &got)

	q := Query{View: "findings", Scope: "team", Days: 7, Repo: "leoprevent", Rule: "ssrf", Limit: 5}
	if _, err := New(srv.URL, "k").Read(q); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{
		"view": "findings", "scope": "team", "days": "7",
		"repo": "leoprevent", "rule": "ssrf", "limit": "5",
	} {
		if got.query.Get(key) != want {
			t.Errorf("%s = %q, want %q", key, got.query.Get(key), want)
		}
	}
}

func TestTheBodyIsReturnedVerbatim(t *testing.T) {
	// This package deliberately does not decode the response: the shapes are defined once, in
	// TypeScript, by the app that computes them. Mirroring them in Go would be a second copy
	// that goes stale SILENTLY — a new field would simply vanish from the tool result.
	body := `{"view":"stats","turns":120,"flaws":{"caught":10}}`
	var got capture
	srv := serverFor(t, 200, body, &got)

	out, err := New(srv.URL, "k").Read(Query{View: "stats"})
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != body {
		t.Errorf("body was rewritten: %q", out)
	}
}

func TestARefusalCarriesTheDashboardsOwnMessage(t *testing.T) {
	// ⚠️ EVERY REFUSAL THIS API PRODUCES IS ACTIONABLE BY THE DEVELOPER READING IT, which is
	// why the message travels rather than a status code. Swallowing it leaves them with a
	// broken feature and no next step, which for a fail-open product is the failure worth
	// avoiding hardest.
	var got capture
	srv := serverFor(t, 403, `{"error":"This is a legacy account-wide key, which names no individual."}`, &got)

	_, err := New(srv.URL, "k").Read(Query{View: "stats"})
	if err == nil {
		t.Fatal("want an error")
	}
	if !strings.Contains(err.Error(), "legacy account-wide key") {
		t.Errorf("message lost: %v", err)
	}
	se, ok := err.(*Error)
	if !ok || se.Status != 403 {
		t.Errorf("want a *stats.Error carrying 403, got %#v", err)
	}
}

func TestANonJSONRefusalStillSaysSomethingUseful(t *testing.T) {
	// An edge proxy or a WAF answers in HTML. Echoing that into an agent's context helps
	// nobody, so it degrades to a status line rather than to the page.
	var got capture
	srv := serverFor(t, 502, `<html><body>Bad gateway</body></html>`, &got)

	_, err := New(srv.URL, "k").Read(Query{View: "stats"})
	if err == nil {
		t.Fatal("want an error")
	}
	if strings.Contains(err.Error(), "<html>") {
		t.Errorf("the proxy's page reached the agent: %v", err)
	}
	if !strings.Contains(err.Error(), "502") {
		t.Errorf("the status should survive: %v", err)
	}
}

func TestNoDashboardURLIsRefusedBeforeAnyRequest(t *testing.T) {
	if _, err := New("", "k").Read(Query{View: "stats"}); err == nil {
		t.Fatal("want a refusal rather than a request to a relative URL")
	}
}

func TestOpenAndAllTimeReachTheQuery(t *testing.T) {
	var got capture
	srv := serverFor(t, 200, `{}`, &got)

	if _, err := New(srv.URL, "k").Read(Query{View: "findings", Open: true, AllTime: true, Days: 7}); err != nil {
		t.Fatal(err)
	}
	if v := got.query.Get("open"); v != "1" {
		t.Errorf("open = %q", v)
	}
	if v := got.query.Get("days"); v != "all" {
		t.Errorf("days = %q, want all", v)
	}
}

func TestTriagePostsTheDecisionWithTheKeyInTheHeader(t *testing.T) {
	var gotBody map[string]string
	var gotAuth, gotPath, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod, gotAuth = r.URL.Path, r.Method, r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_, _ = w.Write([]byte(`{"id":"rev_1-0","state":"ignored"}`))
	}))
	t.Cleanup(srv.Close)

	body, err := New(srv.URL, "lp_live_secret").Triage(TriageRequest{ID: "rev_1-0", State: "ignored", Note: "Test fixture"})
	if err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodPost || gotPath != "/api/agent/triage" {
		t.Errorf("request = %s %s", gotMethod, gotPath)
	}
	if gotAuth != "Bearer lp_live_secret" {
		t.Errorf("Authorization = %q", gotAuth)
	}
	want := map[string]string{"id": "rev_1-0", "state": "ignored", "note": "Test fixture"}
	for k, v := range want {
		if gotBody[k] != v {
			t.Errorf("body[%s] = %q, want %q", k, gotBody[k], v)
		}
	}
	if _, ok := gotBody["scope"]; ok {
		t.Error("an empty scope should be omitted")
	}
	if string(body) != `{"id":"rev_1-0","state":"ignored"}` {
		t.Errorf("body = %s", body)
	}
}

func TestATriageRefusalCarriesTheDashboardsOwnMessage(t *testing.T) {
	var got capture
	srv := serverFor(t, 409, `{"error":"Only an open finding can be ignored or resolved."}`, &got)

	_, err := New(srv.URL, "k").Triage(TriageRequest{ID: "x", State: "ignored", Note: "n"})
	var e *Error
	if !errors.As(err, &e) || e.Status != 409 || e.Message != "Only an open finding can be ignored or resolved." {
		t.Fatalf("err = %v", err)
	}
}
