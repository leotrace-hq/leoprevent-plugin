package delivery

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/apiclient"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/config"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/outcome"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/review"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
	"github.com/leotrace-hq/leoprevent-plugin/limits"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

// TestCloudResolvesAndSendsCrossFileContext is the end-to-end wiring proof: given a
// real on-disk git repo where the changed file imports+calls a local helper, the
// cloud tier must RESOLVE that helper and SEND it in the /review request's Context.
// (The resolver itself is unit-tested in internal/imports; the server's use of
// Context is proven by TestCrossFileRecall. This closes the seam between them.)
func TestCloudResolvesAndSendsCrossFileContext(t *testing.T) {
	root := t.TempDir()
	git := func(args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = root
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Skipf("git unavailable (%v): %s", err, out)
		}
	}
	git("init")
	write := func(rel, body string) {
		if err := os.WriteFile(filepath.Join(root, rel), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("app.py", "from netutil import safe_fetch\nurl = req.args['url']\nreturn safe_fetch(url)\n")
	write("netutil.py", "import requests\ndef safe_fetch(u):\n    return requests.get(u).text\n")

	var got wire.ReviewRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"verdict":"clean"}`))
	}))
	t.Cleanup(srv.Close)

	h := Cloud{client: apiclient.New(srv.URL, ""), resolveImports: true}
	ch := []transcript.Change{{
		FilePath:    "app.py",
		AddedText:   "url = req.args['url']\nreturn safe_fetch(url)",
		FullContent: "from netutil import safe_fetch\nurl = req.args['url']\nreturn safe_fetch(url)\n",
	}}
	if _, err := h.Review(root, ch, wire.TurnMeta{}); err != nil {
		t.Fatalf("Review: %v", err)
	}
	if len(got.Context) != 1 || got.Context[0].Path != "netutil.py" {
		t.Fatalf("cloud tier must send the imported helper as context; got %+v", got.Context)
	}
	if !strings.Contains(got.Context[0].Content, "def safe_fetch") {
		t.Errorf("context content should be the helper's body, got %q", got.Context[0].Content)
	}

	// And with resolution disabled, NO context is sent (the egress opt-out works).
	got = wire.ReviewRequest{}
	off := Cloud{client: apiclient.New(srv.URL, ""), resolveImports: false}
	if _, err := off.Review(root, ch, wire.TurnMeta{}); err != nil {
		t.Fatalf("Review (off): %v", err)
	}
	if len(got.Context) != 0 {
		t.Errorf("resolveImports=false must send no context, got %+v", got.Context)
	}
}

// stubServer answers /rules and /review with the supplied bodies.
func stubServer(t *testing.T, rulesBody, reviewBody string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch r.URL.Path {
		case "/rules":
			w.Write([]byte(rulesBody))
		case "/review":
			w.Write([]byte(reviewBody))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func skipReason(t *testing.T, err error) review.SkipReason {
	t.Helper()
	var se *review.SkipError
	if !errors.As(err, &se) {
		t.Fatalf("error is not a *review.SkipError: %v", err)
	}
	return se.Reason
}

// classifyServerErr maps apiclient failures to the developer-facing skip reason:
// 401/403 → license problem, other non-200 → server fault, transport/timeout →
// unreachable. This is what drives the right "this turn was NOT reviewed" notice.
func TestClassifyServerErr(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want review.SkipReason
	}{
		{"401 unauthorized", &apiclient.StatusError{Path: "/review", Status: 401}, review.SkipUnauthorized},
		{"403 forbidden (tier)", &apiclient.StatusError{Path: "/rules", Status: 403}, review.SkipUnauthorized},
		{"500 server fault", &apiclient.StatusError{Path: "/review", Status: 500}, review.SkipServerError},
		{"400 bad request", &apiclient.StatusError{Path: "/review", Status: 400}, review.SkipServerError},
		{"transport / down", errors.New("apiclient: POST /review: dial tcp: connection refused"), review.SkipUnreachable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := skipReason(t, classifyServerErr(tc.err)); got != tc.want {
				t.Errorf("classifyServerErr(%v) reason = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// A server-side rejection must reach the engine as a classified SkipError (not a
// bare error), through the real apiclient — so both tiers surface a skip reason.
func TestTiersClassifyServerRejection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	client := apiclient.New(srv.URL, "")

	if _, err := (Cloud{client: client}).Review("", ssrfChange, wire.TurnMeta{}); skipReason(t, err) != review.SkipUnauthorized {
		t.Errorf("cloud tier should surface SkipUnauthorized on 403")
	}
	if _, err := (Local{client: client}).Review("", ssrfChange, wire.TurnMeta{}); skipReason(t, err) != review.SkipUnauthorized {
		t.Errorf("local tier should surface SkipUnauthorized on 403")
	}
}

var ssrfChange = []transcript.Change{{
	FilePath:  "/p/app.py",
	AddedText: "url = request.args['url']\nresp = requests.get(url)",
}}

func TestLocalTierFetchesRulesAndBuildsPrompt(t *testing.T) {
	srv := stubServer(t,
		`{"rules":[{"id":"ssrf","name":"SSRF","look_for":"http client with untrusted url.","suggestion":"resolve to IP and reject private ranges","does_not_apply_when":"hardcoded url"}],"meta_policy":"audit its implementation"}`,
		"")
	r, err := New(&config.Config{ServerURL: srv.URL, Tier: config.TierLocal})
	if err != nil {
		t.Fatal(err)
	}
	res, err := r.Review("", ssrfChange, wire.TurnMeta{})
	prompt := res.Prompt
	if err != nil {
		t.Fatalf("Review: %v", err)
	}
	// The local prompt shows the rule NAME ("SSRF"), not the kebab ID.
	for _, want := range []string{"SSRF", "resolve to IP and reject private ranges", "Task tool", "Candidate rules"} {
		if !strings.Contains(prompt, want) {
			t.Errorf("local prompt missing %q", want)
		}
	}
}

func TestLocalTierNeutralChangeSelectsNothing(t *testing.T) {
	srv := stubServer(t, `{"rules":[],"meta_policy":""}`, "")
	r, _ := New(&config.Config{ServerURL: srv.URL, Tier: config.TierLocal})
	res, err := r.Review("", []transcript.Change{{FilePath: "/p/x.py", AddedText: "def add(a,b): return a+b"}}, wire.TurnMeta{})
	prompt := res.Prompt
	if err != nil {
		t.Fatal(err)
	}
	if prompt != "" {
		t.Errorf("neutral change should yield empty prompt, got %q", prompt)
	}
}

func TestLocalTierFiltersByLanguage(t *testing.T) {
	// The changed file is /p/app.py; a rule scoped to java only must be dropped
	// after /rules returns it (applies_to language filtering), yielding "".
	srv := stubServer(t,
		`{"rules":[{"id":"java-thing","name":"X","look_for":"y.","suggestion":"z","applies_to":["java"]}],"meta_policy":""}`,
		"")
	r, _ := New(&config.Config{ServerURL: srv.URL, Tier: config.TierLocal})
	res, err := r.Review("", ssrfChange, wire.TurnMeta{})
	prompt := res.Prompt
	if err != nil {
		t.Fatal(err)
	}
	if prompt != "" {
		t.Errorf("java-only rule must be filtered out for a .py change, got %q", prompt)
	}
}

func TestCloudTierTriggeredBuildsFindingsPrompt(t *testing.T) {
	// The server fills the human rule Name; the client groups by it.
	srv := stubServer(t, "",
		`{"verdict":"triggered","findings":[{"rule":"ssrf","name":"Server-Side Request Forgery","location":"app.py:2","issue":"unvalidated url","fix":"resolve and reject private ranges"}]}`)
	r, _ := New(&config.Config{ServerURL: srv.URL, Tier: config.TierCloud})
	res, err := r.Review("", ssrfChange, wire.TurnMeta{})
	prompt := res.Prompt
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Server-Side Request Forgery", "app.py:2", "unvalidated url", "resolve and reject private ranges"} {
		if !strings.Contains(prompt, want) {
			t.Errorf("cloud findings prompt missing %q", want)
		}
	}
	// The kebab rule ID stays out of the agent-/dev-visible prompt (we show the name).
	if strings.Contains(prompt, "ssrf") {
		t.Errorf("cloud findings prompt leaks the rule ID:\n%s", prompt)
	}
}

// On a triggered cloud review, Result.Pending is populated (review_id + findings +
// before-code) so the engine can track the fix outcome; a clean review leaves it nil.
func TestCloudTierTriggeredReturnsPending(t *testing.T) {
	srv := stubServer(t, "",
		`{"verdict":"triggered","review_id":"rid-42","findings":[{"rule":"ssrf","name":"SSRF","location":"app.py:2","issue":"x","fix":"y"}]}`)
	r, _ := New(&config.Config{ServerURL: srv.URL, Tier: config.TierCloud})
	res, err := r.Review("", ssrfChange, wire.TurnMeta{Repo: "github.com/acme/app", Developer: "Ada"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Pending == nil {
		t.Fatal("triggered cloud review must return a pending outcome")
	}
	if res.Pending.ReviewID != "rid-42" || res.Pending.Repo != "github.com/acme/app" ||
		len(res.Pending.Findings) != 1 || len(res.Pending.Before) != 1 {
		t.Errorf("pending outcome wrong: %+v", res.Pending)
	}
}

// ShipOutcome POSTs to /outcome; a 202 (re-judge skipped at capacity) is a
// successful POST but an UNSCORED verdict — surfaced as outcome.ErrUnscored.
func TestCloudShipOutcomePostsOutcome(t *testing.T) {
	var got wire.OutcomeRequest
	hit := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/outcome" {
			hit = true
			_ = json.NewDecoder(r.Body).Decode(&got)
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"accepted":true}`))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)

	r, _ := New(&config.Config{ServerURL: srv.URL, Tier: config.TierCloud})
	p := outcome.Pending{ReviewID: "rid-7", Repo: "github.com/acme/app", Findings: []wire.Finding{{Rule: "ssrf"}}, Before: []wire.ChangedFile{{Path: "a.py", AddedText: "requests.get(u)"}}}
	after := []transcript.Change{{FilePath: "a.py", AddedText: "ip = resolve(h)"}}
	// Full-turn meta (final-Stop capture) must ride the request so a blocked turn's
	// per-agent cost/latency spans the re-wake.
	meta := wire.TurnMeta{AgentModel: "claude-opus-4-8", InputTokens: 100, OutputTokens: 50, CacheReadTokens: 9000, CacheCreationTokens: 200, DurationMs: 48000}
	// A 202 means the server ACCEPTED the outcome but SKIPPED the re-judge (capacity):
	// the POST succeeds, and the unscored verdict surfaces as ErrUnscored so the
	// caller never mistakes "no verdict" for "all clear".
	_, _, err := r.ShipOutcome(p, after, "I resolved it to an IP.", meta)
	if !errors.Is(err, outcome.ErrUnscored) {
		t.Fatalf("ShipOutcome on a 202 skip = %v, want outcome.ErrUnscored", err)
	}
	if !hit {
		t.Fatal("ShipOutcome must POST /outcome")
	}
	if got.ReviewID != "rid-7" || len(got.After) != 1 || got.After[0].AddedText != "ip = resolve(h)" ||
		got.AgentResponse != "I resolved it to an IP." {
		t.Errorf("outcome request wrong: %+v", got)
	}
	if got.AgentModel != "claude-opus-4-8" || got.InputTokens != 100 || got.OutputTokens != 50 ||
		got.CacheReadTokens != 9000 || got.CacheCreationTokens != 200 || got.DurationMs != 48000 {
		t.Errorf("outcome request missing full-turn meta: %+v", got)
	}
}

// The re-wake asks the agent what it assumed (review.AssumptionsAsk) and the answer
// comes back inside the reply, so ShipOutcome must parse it out and ship it. This is
// the ONLY place that happens, which is what gives the headless `exec` loop the same
// behaviour as the Stop hook for free — both reach the server through here.
func TestCloudShipOutcomeParsesAssumptionsFromTheReply(t *testing.T) {
	var got wire.OutcomeRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write([]byte(`{"accepted":true,"scored":true}`))
	}))
	t.Cleanup(srv.Close)

	r, _ := New(&config.Config{ServerURL: srv.URL, Tier: config.TierCloud})
	reply := "Resolved it to an IP.\n\n<leoprevent-assumptions>\n- the caller is already authenticated\n- LOG_DIR is set\n</leoprevent-assumptions>"
	if _, _, err := r.ShipOutcome(outcome.Pending{ReviewID: "rid-9"}, nil, reply, wire.TurnMeta{}); err != nil {
		t.Fatalf("ShipOutcome: %v", err)
	}
	if !got.AssumptionsReported {
		t.Fatal("assumptions_reported must be true when the agent answered")
	}
	if len(got.Assumptions) != 2 || got.Assumptions[0] != "the caller is already authenticated" {
		t.Fatalf("assumptions wrong: %q", got.Assumptions)
	}
	// The reply is the record of what the agent said. Lifting the block out of it into
	// a structured field must not also EDIT that record.
	if got.AgentResponse != reply {
		t.Errorf("agent_response must ship verbatim, got %q", got.AgentResponse)
	}
}

// An agent that ignores the ask (or a surface with no transcript to read the reply
// back from) must record "never answered", not an empty answer.
func TestCloudShipOutcomeReportsNoAssumptionsWhenUnanswered(t *testing.T) {
	var got wire.OutcomeRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write([]byte(`{"accepted":true,"scored":true}`))
	}))
	t.Cleanup(srv.Close)

	r, _ := New(&config.Config{ServerURL: srv.URL, Tier: config.TierCloud})
	if _, _, err := r.ShipOutcome(outcome.Pending{ReviewID: "rid-9"}, nil, "Fixed it.", wire.TurnMeta{}); err != nil {
		t.Fatalf("ShipOutcome: %v", err)
	}
	if got.AssumptionsReported || len(got.Assumptions) != 0 {
		t.Fatalf("unanswered ask must record nothing: reported=%v %q", got.AssumptionsReported, got.Assumptions)
	}
}

// ShipOutcome returns BOTH the introduced and pre-existing still-firing sets so the
// engine can warn in-turn AND seed the cross-turn ledger.
func TestCloudShipOutcomeReturnsBothStillFiringSets(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"accepted":true,"scored":true,"introduced_still_firing":[{"rule":"ssrf","location":"a.py:1"}],"preexisting_still_firing":[{"rule":"idor-object-level-authz","location":"main.py:44","preexisting":true}]}`))
	}))
	t.Cleanup(srv.Close)
	r, _ := New(&config.Config{ServerURL: srv.URL, Tier: config.TierCloud})
	intro, pre, err := r.ShipOutcome(outcome.Pending{ReviewID: "rid-1"}, nil, "", wire.TurnMeta{})
	if err != nil {
		t.Fatalf("ShipOutcome: %v", err)
	}
	if len(intro) != 1 || intro[0].Rule != "ssrf" {
		t.Errorf("introduced still-firing = %+v, want [ssrf]", intro)
	}
	if len(pre) != 1 || pre[0].Rule != "idor-object-level-authz" || !pre[0].Preexisting {
		t.Errorf("pre-existing still-firing = %+v, want [idor-object-level-authz preexisting]", pre)
	}
}

// ShipResolution POSTs /outcome with resolution:true, carries the after-code + origin
// review_id, sends NO agent token/latency meta (avoids double-count), and parses the
// remaining-open pre-existing findings from the response.
func TestCloudShipResolutionPostsResolution(t *testing.T) {
	var got wire.OutcomeRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/outcome" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"accepted":true,"scored":true,"preexisting_still_firing":[{"rule":"no-input-validation","location":"main.py:49","preexisting":true}]}`))
	}))
	t.Cleanup(srv.Close)

	r, _ := New(&config.Config{ServerURL: srv.URL, Tier: config.TierCloud})
	p := outcome.Pending{
		ReviewID: "rid-1", Repo: "github.com/acme/app",
		Findings: []wire.Finding{
			{Rule: "idor-object-level-authz", Location: "main.py:44", Preexisting: true},
			{Rule: "no-input-validation", Location: "main.py:49", Preexisting: true},
		},
		Before: []wire.ChangedFile{{Path: "main.py", AddedText: "old"}},
	}
	after := []transcript.Change{{FilePath: "main.py", AddedText: "fixed", FullContent: "safe\n"}}
	// Meta with token counts present — must NOT be forwarded on a resolution.
	meta := wire.TurnMeta{AgentModel: "claude-opus-4-8", InputTokens: 999, OutputTokens: 999, DurationMs: 12345}
	stillOpen, err := r.ShipResolution(p, after, meta)
	if err != nil {
		t.Fatalf("ShipResolution: %v", err)
	}
	if !got.Resolution {
		t.Error("resolution request must set resolution:true")
	}
	if got.ReviewID != "rid-1" || len(got.After) != 1 || got.After[0].FullContent != "safe\n" || len(got.Findings) != 2 {
		t.Errorf("resolution request wrong: %+v", got)
	}
	if got.InputTokens != 0 || got.OutputTokens != 0 || got.DurationMs != 0 {
		t.Errorf("resolution must NOT send agent token/latency meta (double-count): %+v", got)
	}
	if len(stillOpen) != 1 || stillOpen[0].Rule != "no-input-validation" || !stillOpen[0].Preexisting {
		t.Errorf("still-open = %+v, want [no-input-validation preexisting]", stillOpen)
	}
}

// ShipResolution returns the UNION of still-firing findings (introduced AND pre-existing),
// each keeping its Preexisting flag, so the ledger retains the correct open set across
// both classes for a future cross-turn re-judge.
func TestCloudShipResolutionReturnsBothClasses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"accepted":true,"scored":true,"introduced_still_firing":[{"rule":"ssrf","location":"app.py:9"}],"preexisting_still_firing":[{"rule":"idor-object-level-authz","location":"main.py:44","preexisting":true}]}`))
	}))
	t.Cleanup(srv.Close)
	r, _ := New(&config.Config{ServerURL: srv.URL, Tier: config.TierCloud})
	stillOpen, err := r.ShipResolution(outcome.Pending{ReviewID: "rid-1"}, nil, wire.TurnMeta{})
	if err != nil {
		t.Fatalf("ShipResolution: %v", err)
	}
	if len(stillOpen) != 2 {
		t.Fatalf("union still-open = %d findings, want 2 (intro + pre): %+v", len(stillOpen), stillOpen)
	}
	var sawIntro, sawPre bool
	for _, f := range stillOpen {
		if f.Rule == "ssrf" && !f.Preexisting {
			sawIntro = true
		}
		if f.Rule == "idor-object-level-authz" && f.Preexisting {
			sawPre = true
		}
	}
	if !sawIntro || !sawPre {
		t.Errorf("union must carry both classes with correct flags: %+v", stillOpen)
	}
}

// ShipTelemetry (cloud) POSTs to /telemetry, DROPS the dev's prompt (minimal
// egress), and forwards the rest of the metadata + reason.
func TestCloudShipTelemetryPostsAndDropsPrompt(t *testing.T) {
	var got wire.TelemetryRequest
	hit := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/telemetry" {
			hit = true
			_ = json.NewDecoder(r.Body).Decode(&got)
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"accepted":true}`))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)

	r, _ := New(&config.Config{ServerURL: srv.URL, Tier: config.TierCloud})
	meta := wire.TurnMeta{AgentModel: "claude-opus-4-8", Repo: "github.com/acme/app", Developer: "Dev <d@acme.com>", Prompt: "SECRET PROMPT", InputTokens: 5, DurationMs: 42}
	if err := r.ShipTelemetry(meta, wire.TelemetryInert, 3); err != nil {
		t.Fatalf("ShipTelemetry: %v", err)
	}
	if !hit {
		t.Fatal("cloud ShipTelemetry must POST /telemetry")
	}
	if got.Meta.Prompt != "" {
		t.Errorf("the dev's prompt must NOT be egressed on a telemetry turn, got %q", got.Meta.Prompt)
	}
	if got.Reason != wire.TelemetryInert || got.ChangedFiles != 3 || got.Meta.Repo != "github.com/acme/app" || got.Meta.Developer != "Dev <d@acme.com>" {
		t.Errorf("telemetry request wrong: %+v", got)
	}
}

// ShipTelemetry (local) is a no-op: the local tier never sends metadata, so it
// makes NO network call.
func TestLocalShipTelemetryIsNoOp(t *testing.T) {
	hit := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)

	r, _ := New(&config.Config{ServerURL: srv.URL, Tier: config.TierLocal})
	if err := r.ShipTelemetry(wire.TurnMeta{Repo: "x"}, wire.TelemetryNoChange, 0); err != nil {
		t.Fatalf("local ShipTelemetry should be a silent no-op, got %v", err)
	}
	if hit {
		t.Error("local tier must make NO network call for telemetry")
	}
}

func TestCloudTierCleanIsSilent(t *testing.T) {
	srv := stubServer(t, "", `{"verdict":"clean"}`)
	r, _ := New(&config.Config{ServerURL: srv.URL, Tier: config.TierCloud})
	res, err := r.Review("", ssrfChange, wire.TurnMeta{})
	prompt := res.Prompt
	if err != nil {
		t.Fatal(err)
	}
	if prompt != "" {
		t.Errorf("clean verdict should yield empty prompt, got %q", prompt)
	}
}

// A multi-batch turn must send the turn's tokens/duration/prompt on the FIRST
// batch only: re-sending them per batch double-counts the agent's cost in the
// per-engineer analytics and persists the dev's prompt once per batch. Continuation
// batches keep the identity dimensions (model/repo/developer) and carry
// ContinuesReviewID pointing at the first batch's event, where the cost lives.
func TestCloudMultiBatchMetaOnFirstBatchOnly(t *testing.T) {
	var metas []wire.TurnMeta
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/review" {
			http.NotFound(w, r)
			return
		}
		var req wire.ReviewRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		metas = append(metas, req.Meta)
		id := "rv-first"
		if len(metas) > 1 {
			id = "rv-later"
		}
		_, _ = w.Write([]byte(`{"verdict":"clean","review_id":"` + id + `"}`))
	}))
	t.Cleanup(srv.Close)

	// Two files each just over half the batch budget → exactly two batches.
	big := strings.Repeat("x", limits.MaxReviewBytes/2+1024)
	changes := []transcript.Change{{FilePath: "a.py", AddedText: big}, {FilePath: "b.py", AddedText: big}}
	meta := wire.TurnMeta{AgentModel: "claude-opus-4-8", Repo: "github.com/acme/app", Developer: "Dev <d@acme.com>",
		Prompt: "SECRET PROMPT", InputTokens: 5, OutputTokens: 7, DurationMs: 9}

	r, _ := New(&config.Config{ServerURL: srv.URL, Tier: config.TierCloud})
	if _, err := r.Review("", changes, meta); err != nil {
		t.Fatalf("Review: %v", err)
	}
	if len(metas) != 2 {
		t.Fatalf("want exactly 2 batches, got %d", len(metas))
	}
	first, second := metas[0], metas[1]
	if first.Prompt != "SECRET PROMPT" || first.InputTokens != 5 || first.OutputTokens != 7 ||
		first.DurationMs != 9 || first.ContinuesReviewID != "" {
		t.Errorf("first batch must carry the full turn meta: %+v", first)
	}
	if second.Prompt != "" || second.InputTokens != 0 || second.OutputTokens != 0 || second.DurationMs != 0 {
		t.Errorf("continuation batch must NOT re-send cost/prompt (double-count): %+v", second)
	}
	if second.ContinuesReviewID != "rv-first" {
		t.Errorf("continuation batch must point at the first batch's review_id, got %q", second.ContinuesReviewID)
	}
	if second.AgentModel != meta.AgentModel || second.Repo != meta.Repo || second.Developer != meta.Developer {
		t.Errorf("continuation batch must keep the identity dimensions: %+v", second)
	}
}

func TestPackReviewBatches_SplitsAndPreservesAllFiles(t *testing.T) {
	mk := func(p string, n int) wire.ChangedFile {
		return wire.ChangedFile{Path: p, AddedText: strings.Repeat("x", n)}
	}
	// Three files each larger than the per-request budget → must split into ≥2 batches, all kept.
	files := []wire.ChangedFile{mk("a", 2_500_000), mk("b", 2_500_000), mk("c", 2_500_000)}
	batches := packReviewBatches(files, limits.MaxReviewBytes)
	if len(batches) < 2 {
		t.Fatalf("expected ≥2 batches for 7.5MB over a 6MiB budget, got %d", len(batches))
	}
	seen := map[string]bool{}
	for _, b := range batches {
		sz := 0
		for _, f := range b {
			seen[f.Path] = true
			sz += fileBytes(f)
		}
		if sz > limits.MaxSingleFileBytes && len(b) > 1 {
			t.Errorf("batch exceeds single-file ceiling with multiple files: %d", sz)
		}
	}
	for _, p := range []string{"a", "b", "c"} {
		if !seen[p] {
			t.Errorf("file %q was dropped from all batches", p)
		}
	}
}

func TestFitFile_TruncatesOnlyOversizeSingleFile(t *testing.T) {
	small := wire.ChangedFile{Path: "ok.go", AddedText: "package main"}
	if got := fitFile(small); got.AddedText != small.AddedText {
		t.Error("small file must be untouched")
	}
	huge := wire.ChangedFile{Path: "blob", AddedText: strings.Repeat("y", 9<<20)} // 9 MiB
	got := fitFile(huge)
	if fileBytes(got) > limits.MaxSingleFileBytes {
		t.Errorf("oversized file not brought under ceiling: %d", fileBytes(got))
	}
	if !strings.Contains(got.AddedText, "truncated") {
		t.Error("truncation marker missing")
	}
}

func TestPackReviewBatches_EmptyYieldsOneBatch(t *testing.T) {
	if got := packReviewBatches(nil, limits.MaxReviewBytes); len(got) != 1 {
		t.Fatalf("empty input must yield exactly one (empty) batch, got %d", len(got))
	}
}
