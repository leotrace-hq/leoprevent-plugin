package apiclient

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/outcome"
	"github.com/leotrace-hq/leoprevent-plugin/rulespec"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

// TestMain shrinks the transient-retry backoffs so tests that exhaust the retry
// budget (persistent 500, unreachable server) don't sleep 4s each.
func TestMain(m *testing.M) {
	postBackoffs = []time.Duration{time.Millisecond, time.Millisecond}
	os.Exit(m.Run())
}

func TestReviewAndRulesRoundTrip(t *testing.T) {
	var gotReview wire.ReviewRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch r.URL.Path {
		case "/review":
			_ = json.NewDecoder(r.Body).Decode(&gotReview)
			w.Write([]byte(`{"verdict":"triggered","findings":[{"rule":"ssrf","location":"a.py:1","issue":"x","fix":"y"}]}`))
		case "/rules":
			w.Write([]byte(`{"rules":[{"id":"ssrf","name":"SSRF","look_for":"..."}],"meta_policy":"audit"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c := New(srv.URL, "")

	meta := wire.TurnMeta{AgentModel: "claude-opus-4-8", Repo: "github.com/acme/app", Developer: "Dev <d@acme.com>", Prompt: "add a fetch", InputTokens: 5, OutputTokens: 7, DurationMs: 1234}
	rev, err := c.Review([]wire.ChangedFile{{Path: "a.py", AddedText: "requests.get(u)"}}, nil, meta)
	if err != nil {
		t.Fatalf("Review: %v", err)
	}
	if rev.Verdict != wire.VerdictTriggered || len(rev.Findings) != 1 || rev.Findings[0].Rule != "ssrf" {
		t.Errorf("unexpected review response: %+v", rev)
	}
	// The coding-agent turn metadata must ride along in the request body.
	if !reflect.DeepEqual(gotReview.Meta, meta) {
		t.Errorf("meta not transmitted: got %+v, want %+v", gotReview.Meta, meta)
	}

	rl, err := c.Rules([]string{"ssrf"})
	if err != nil {
		t.Fatalf("Rules: %v", err)
	}
	if len(rl.Rules) != 1 || rl.Rules[0].ID != "ssrf" || rl.MetaPolicy != "audit" {
		t.Errorf("unexpected rules response: %+v", rl)
	}
	_ = rulespec.Rule{} // ensure the shared type is the one decoded into
}

// Telemetry POSTs the turn metadata to /telemetry and accepts the 202 the server
// returns, carrying the Bearer key.
func TestTelemetryRoundTrip(t *testing.T) {
	var got wire.TelemetryRequest
	var gotAuth string
	hit := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/telemetry" {
			http.NotFound(w, r)
			return
		}
		hit = true
		gotAuth = r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"accepted":true}`))
	}))
	defer srv.Close()

	c := New(srv.URL, "lp_live_k")
	req := wire.TelemetryRequest{
		Meta:         wire.TurnMeta{AgentModel: "claude-opus-4-8", Repo: "github.com/acme/app", Developer: "Dev <d@acme.com>", InputTokens: 5, DurationMs: 99},
		Reason:       wire.TelemetryNoChange,
		ChangedFiles: 0,
	}
	if err := c.Telemetry(req); err != nil {
		t.Fatalf("Telemetry: %v", err)
	}
	if !hit {
		t.Fatal("Telemetry must POST /telemetry")
	}
	if gotAuth != "Bearer lp_live_k" {
		t.Errorf("Authorization = %q, want Bearer lp_live_k", gotAuth)
	}
	if got.Reason != wire.TelemetryNoChange || got.Meta.AgentModel != "claude-opus-4-8" || got.Meta.Repo != "github.com/acme/app" {
		t.Errorf("telemetry request wrong: %+v", got)
	}
}

// Outcome distinguishes "re-judged and clean" from "never judged": a scored response
// returns nil error; an UNSCORED one — the 202 capacity skip, or a 200 without
// scored:true (re-judge failure / old server) — returns outcome.ErrUnscored so the
// engine keeps its ledger instead of crediting empty lists as "everything resolved".
func TestOutcomeUnscoredIsSentinelError(t *testing.T) {
	status, respBody := http.StatusOK, `{"accepted":true,"scored":true}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(respBody))
	}))
	defer srv.Close()
	c := New(srv.URL, "")

	// Scored 200 → nil error (a real verdict; empty lists mean genuinely clean).
	if _, err := c.Outcome(wire.OutcomeRequest{ReviewID: "rid-1"}); err != nil {
		t.Fatalf("scored response must not error: %v", err)
	}

	// 200 without scored (re-judge failure / nil model / old server) → ErrUnscored.
	respBody = `{"accepted":true}`
	if _, err := c.Outcome(wire.OutcomeRequest{ReviewID: "rid-1"}); !errors.Is(err, outcome.ErrUnscored) {
		t.Errorf("unscored 200 must surface outcome.ErrUnscored, got %v", err)
	}

	// 202 capacity skip → ErrUnscored too (no verdict either).
	status, respBody = http.StatusAccepted, `{"accepted":true}`
	if _, err := c.Outcome(wire.OutcomeRequest{ReviewID: "rid-1"}); !errors.Is(err, outcome.ErrUnscored) {
		t.Errorf("202 skip must surface outcome.ErrUnscored, got %v", err)
	}
}

// TestRetryRecoversTransient500: two 5xx replies then a 200 — the client retries
// (with backoff) inside the same deadline and the caller sees SUCCESS, not a
// fail-open. This is the 20_-eval failure mode (network blips / 429 / 5xx were
// instant fail-opens = silently unreviewed turns).
func TestRetryRecoversTransient500(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) <= 2 {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		w.Header().Set("content-type", "application/json")
		w.Write([]byte(`{"verdict":"clean"}`))
	}))
	defer srv.Close()

	resp, err := New(srv.URL, "").Review(nil, nil, wire.TurnMeta{})
	if err != nil {
		t.Fatalf("Review after transient 500s: %v", err)
	}
	if resp.Verdict != "clean" {
		t.Errorf("verdict = %q, want clean", resp.Verdict)
	}
	if got := calls.Load(); got != 3 {
		t.Errorf("server calls = %d, want 3 (2 failures + 1 success)", got)
	}
}

// TestRetryRecoversDroppedConnection: the FIRST connection is severed mid-request
// (a transport error, not a status) — the retry recovers it.
func TestRetryRecoversDroppedConnection(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			hj, ok := w.(http.Hijacker)
			if !ok {
				t.Fatal("no hijacker")
			}
			conn, _, _ := hj.Hijack()
			conn.(*net.TCPConn).SetLinger(0) // RST, not FIN — a real broken pipe
			conn.Close()
			return
		}
		w.Header().Set("content-type", "application/json")
		w.Write([]byte(`{"verdict":"clean"}`))
	}))
	defer srv.Close()

	if _, err := New(srv.URL, "").Review(nil, nil, wire.TurnMeta{}); err != nil {
		t.Fatalf("Review after dropped connection: %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("server calls = %d, want 2", got)
	}
}

// TestNoRetryOnAuthError: a 401 is NOT transient — retrying can't fix a bad
// license, so exactly one attempt is made and the StatusError surfaces.
func TestNoRetryOnAuthError(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.Error(w, "no", http.StatusUnauthorized)
	}))
	defer srv.Close()

	_, err := New(srv.URL, "bad").Review(nil, nil, wire.TurnMeta{})
	var se *StatusError
	if !errors.As(err, &se) || se.Status != http.StatusUnauthorized {
		t.Fatalf("err = %v, want StatusError 401", err)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("server calls = %d, want 1 (no retry on auth errors)", got)
	}
}

func TestNon200IsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	if _, err := New(srv.URL, "").Rules([]string{"ssrf"}); err == nil {
		t.Error("expected error on 500")
	}
}

func TestUnreachableIsError(t *testing.T) {
	// Nothing listening on this address → transport error → engine fails open.
	if _, err := New("http://127.0.0.1:0", "").Review(nil, nil, wire.TurnMeta{}); err == nil {
		t.Error("expected error for unreachable server")
	}
}

// TestSendsBearerWhenKeySet: a non-empty license key rides as an Authorization
// Bearer header on every request; an empty key sends no Authorization header.
func TestSendsBearerWhenKeySet(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("content-type", "application/json")
		w.Write([]byte(`{"rules":[],"meta_policy":""}`))
	}))
	defer srv.Close()

	if _, err := New(srv.URL, "lp_live_secret123").Rules([]string{"ssrf"}); err != nil {
		t.Fatalf("Rules: %v", err)
	}
	if gotAuth != "Bearer lp_live_secret123" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "Bearer lp_live_secret123")
	}

	gotAuth = ""
	if _, err := New(srv.URL, "").Rules([]string{"ssrf"}); err != nil {
		t.Fatalf("Rules: %v", err)
	}
	if gotAuth != "" {
		t.Errorf("empty key must send no Authorization header, got %q", gotAuth)
	}
}
