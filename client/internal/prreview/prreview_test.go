package prreview

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/engine"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/outcome"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
	"github.com/leotrace-hq/leoprevent-plugin/prpost"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

// fakeReviewer returns scripted findings and RECORDS every call, so a test can
// assert on what this lane must never do — ship an outcome, resolve a ledger, send
// telemetry — as well as on what it must.
type fakeReviewer struct {
	findings   []wire.Finding
	err        error
	sawChanges []transcript.Change
	sawMeta    wire.TurnMeta
	outcomes   int
	resolves   int
	reasons    int
	telemetry  int
}

func (f *fakeReviewer) Review(cwd string, changes []transcript.Change, meta wire.TurnMeta) (engine.Result, error) {
	f.sawChanges, f.sawMeta = changes, meta
	if f.err != nil {
		return engine.Result{}, f.err
	}
	if len(f.findings) == 0 {
		return engine.Result{}, nil
	}
	return engine.Result{
		Prompt:  "fix it",
		Pending: &outcome.Pending{ReviewID: "rev1", Findings: f.findings},
	}, nil
}

func (f *fakeReviewer) ShipOutcome(outcome.Pending, []transcript.Change, string, wire.TurnMeta) ([]wire.Finding, []wire.Finding, error) {
	f.outcomes++
	return nil, nil, nil
}

func (f *fakeReviewer) ShipResolution(outcome.Pending, []transcript.Change, wire.TurnMeta) ([]wire.Finding, error) {
	f.resolves++
	return nil, nil
}

func (f *fakeReviewer) ShipReasons(outcome.Pending, string, string, wire.TurnMeta) error {
	f.reasons++
	return nil
}

func (f *fakeReviewer) ShipTelemetry(wire.TurnMeta, string, int) error {
	f.telemetry++
	return nil
}

func repo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	for _, args := range [][]string{
		{"init", "-q", "-b", "main"},
		{"config", "user.email", "t@t"},
		{"config", "user.name", "t"},
	} {
		if out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	return dir
}

func gitc(t *testing.T, dir string, args ...string) {
	t.Helper()
	if out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func put(t *testing.T, dir, rel, body string) {
	t.Helper()
	p := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// branchWith seeds main, forks a branch and commits the given files on it.
func branchWith(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := repo(t)
	put(t, dir, "seed.py", "seed = 1\n")
	gitc(t, dir, "add", "-A")
	gitc(t, dir, "commit", "-qm", "seed")
	gitc(t, dir, "checkout", "-q", "-b", "feature")
	for rel, body := range files {
		put(t, dir, rel, body)
	}
	gitc(t, dir, "add", "-A")
	gitc(t, dir, "commit", "-qm", "work")
	return dir
}

// fakeGitHub records the review payloads posted to it and answers the
// existing-comments scan with whatever bodies the test seeds.
type fakeGitHub struct {
	existing []string
	posted   []prpost.ReviewPayload
	postErr  int // status to answer the first N posts with; 0 = always succeed
}

func (g *fakeGitHub) client(t *testing.T) *prpost.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/comments"):
			out := make([]map[string]string, 0, len(g.existing))
			for _, b := range g.existing {
				out = append(out, map[string]string{"body": b})
			}
			_ = json.NewEncoder(w).Encode(out)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/reviews"):
			var p prpost.ReviewPayload
			_ = json.NewDecoder(r.Body).Decode(&p)
			g.posted = append(g.posted, p)
			if g.postErr > 0 {
				g.postErr--
				w.WriteHeader(http.StatusUnprocessableEntity)
				_, _ = w.Write([]byte(`{"message":"line must be part of the diff"}`))
				return
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return &prpost.Client{Token: "t", Owner: "o", Repo: "r", API: srv.URL}
}

// TestTheLaneShipsNoOutcomeAndNoTelemetry is the containment regression. There is no
// re-wake in this lane, so there is no fix to score and no second Stop to score it
// at; and /telemetry exists to make per-PROMPT analytics complete, which a CI job is
// not part of. An outcome shipped here would invent a remediation verdict for a turn
// nobody took.
func TestTheLaneShipsNoOutcomeAndNoTelemetry(t *testing.T) {
	dir := branchWith(t, map[string]string{"app.py": "import requests\nrequests.get(url)\n"})
	r := &fakeReviewer{findings: []wire.Finding{{Rule: "ssrf", Location: "app.py:2", Issue: "i", Fix: "f"}}}

	var out bytes.Buffer
	res, err := Run(r, Options{Cwd: dir, Base: "main", PR: 7, Out: &out})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Reviewed || res.Findings != 1 {
		t.Fatalf("Result = %+v, want a reviewed turn with 1 finding", res)
	}
	if r.outcomes != 0 || r.resolves != 0 || r.reasons != 0 || r.telemetry != 0 {
		t.Errorf("the lane called outcome=%d resolution=%d reasons=%d telemetry=%d; every one must be 0",
			r.outcomes, r.resolves, r.reasons, r.telemetry)
	}
}

// TestTheLaneNamesNoDeveloperAndNoAgent is the other half of the containment, and it
// is the one that keeps a bot off the leaderboard. `developer` is the attribution
// axis for every per-person figure in the product, so naming the pull request's
// author would file a branch's accumulated findings onto whoever opened it.
func TestTheLaneNamesNoDeveloperAndNoAgent(t *testing.T) {
	dir := branchWith(t, map[string]string{"app.py": "import requests\nrequests.get(url)\n"})
	r := &fakeReviewer{}

	var out bytes.Buffer
	if _, err := Run(r, Options{Cwd: dir, Base: "main", PR: 7, Environment: wire.EnvGitHubActions, Out: &out}); err != nil {
		t.Fatal(err)
	}
	m := r.sawMeta
	if m.Developer != "" || m.DeveloperSource != "" {
		t.Errorf("developer = %q (%q); a pull request's lines are the branch's, not one person's",
			m.Developer, m.DeveloperSource)
	}
	if m.Agent != "" || m.AgentModel != "" {
		t.Errorf("agent = %q model = %q; there is no coding agent in this loop", m.Agent, m.AgentModel)
	}
	if m.Prompt != "" {
		t.Errorf("prompt = %q; there is no prompt, so the honest value egresses nothing", m.Prompt)
	}
	if m.ReviewLane != wire.LanePullRequest {
		t.Errorf("ReviewLane = %q, want %q — this is what makes the server surface every finding",
			m.ReviewLane, wire.LanePullRequest)
	}
	if m.Environment != wire.EnvGitHubActions {
		t.Errorf("Environment = %q, want %q", m.Environment, wire.EnvGitHubActions)
	}
	if m.PullRequestNumber != 7 {
		t.Errorf("PullRequestNumber = %d, want 7", m.PullRequestNumber)
	}
}

// TestSecretsNeverReachTheReview: a .env committed to a branch is exactly the thing
// a pull request turns up, and the hook path's dropSecrets is private to engine — so
// the filter is applied here or not at all.
func TestSecretsNeverReachTheReview(t *testing.T) {
	dir := branchWith(t, map[string]string{
		"app.py": "import requests\nrequests.get(url)\n",
		// ⚠️ DELIBERATELY NOT CREDENTIAL-SHAPED. `gate.IsSecretPath` matches on the PATH, so
		// what is inside the file is irrelevant to what this test proves — and a fixture that
		// looks like a live key trips every secret scanner that reads this repository, ours
		// included. A test about not egressing secrets should not commit one.
		".env": "SOME_SETTING=placeholder\n",
	})
	r := &fakeReviewer{}

	var out bytes.Buffer
	if _, err := Run(r, Options{Cwd: dir, Base: "main", PR: 7, Out: &out}); err != nil {
		t.Fatal(err)
	}
	for _, c := range r.sawChanges {
		if strings.Contains(c.FilePath, ".env") {
			t.Fatalf("a secret file reached /review: %q", c.FilePath)
		}
	}
	// And it is NAMED in the summary rather than silently absent — a file that simply
	// is not there reads as a file with nothing wrong in it.
	if !strings.Contains(out.String(), ".env") {
		t.Error("the excluded secret must be named in the summary")
	}
}

// TestOnlyFindingsInsideTheDiffAreAttachedInline: GitHub refuses the ENTIRE comments
// array when any one line is outside the diff, so an unchecked pre-existing finding
// would take every other comment down with it.
func TestOnlyFindingsInsideTheDiffAreAttachedInline(t *testing.T) {
	dir := branchWith(t, map[string]string{"app.py": "one\ntwo\nimport requests\n"})
	r := &fakeReviewer{findings: []wire.Finding{
		{Rule: "ssrf", Location: "app.py:3", Issue: "in the diff", Fix: "f"},
		{Rule: "idor-object-level-authz", Location: "seed.py:1", Issue: "outside the diff", Fix: "f"},
		{Rule: "open-redirect", Location: "app.py:999", Issue: "past the end", Fix: "f"},
	}}
	gh := &fakeGitHub{}

	var out bytes.Buffer
	res, err := Run(r, Options{Cwd: dir, Base: "main", PR: 7, Post: gh.client(t), Out: &out})
	if err != nil {
		t.Fatal(err)
	}
	if res.Inline != 1 {
		t.Fatalf("Inline = %d, want 1 — only app.py:3 is a line of this diff", res.Inline)
	}
	if len(gh.posted) != 1 {
		t.Fatalf("posted %d reviews, want exactly 1", len(gh.posted))
	}
	p := gh.posted[0]
	if p.Event != "COMMENT" {
		t.Errorf("event = %q, want COMMENT: REQUEST_CHANGES is the merge-blocking review this lane exists not to be", p.Event)
	}
	if len(p.Comments) != 1 || p.Comments[0].Line != 3 || p.Comments[0].Side != "RIGHT" {
		t.Errorf("comments = %+v, want one on app.py:3 RIGHT", p.Comments)
	}
	// The two it could not anchor are stated IN FULL, not counted: a finding outside
	// the diff is often the one worth reading, and a reviewer must be able to reach it.
	for _, want := range []string{"outside the diff", "past the end"} {
		if !strings.Contains(p.Body, want) {
			t.Errorf("summary must state the unanchored finding %q in full; got:\n%s", want, p.Body)
		}
	}
}

// TestARepeatedFindingIsNotCommentedTwice: GitHub de-duplicates nothing, so without
// the marker every push to a branch would repeat the whole review.
func TestARepeatedFindingIsNotCommentedTwice(t *testing.T) {
	dir := branchWith(t, map[string]string{"app.py": "one\ntwo\nimport requests\n"})
	f := wire.Finding{Rule: "ssrf", Location: "app.py:3", Issue: "i", Fix: "f"}
	r := &fakeReviewer{findings: []wire.Finding{f}}
	gh := &fakeGitHub{existing: []string{"an earlier run said this\n" + prpost.Marker(f)}}

	var out bytes.Buffer
	res, err := Run(r, Options{Cwd: dir, Base: "main", PR: 7, Post: gh.client(t), Out: &out})
	if err != nil {
		t.Fatal(err)
	}
	if res.Inline != 0 {
		t.Errorf("Inline = %d, want 0 — this finding was already commented on", res.Inline)
	}
	// ⚠️ NOTHING IS POSTED AT ALL, AND THE EARLIER BEHAVIOUR — a summary-only review — IS WHAT
	// THIS REPLACES. That summary repeated on every push: the marker stopped the COMMENT
	// repeating and nothing stopped the block above it, so a pull request with ten pushes
	// carried ten identical-looking review summaries. Observed on the LEO-231 smoke test.
	if len(gh.posted) != 0 {
		t.Errorf("a re-run with nothing new must post nothing; got %+v", gh.posted)
	}
	if !strings.Contains(out.String(), "nothing new") {
		t.Errorf("the step log must say why it stayed quiet; got:\n%s", out.String())
	}
}

// A re-run that DOES find something new still posts, and the summary still explains the finding
// it is not repeating — the quiet path must not swallow a genuinely new comment.
func TestANewFindingOnARerunIsStillPosted(t *testing.T) {
	dir := branchWith(t, map[string]string{"app.py": "one\ntwo\nimport requests\n"})
	old := wire.Finding{Rule: "ssrf", Location: "app.py:3", Issue: "i", Fix: "f"}
	fresh := wire.Finding{Rule: "open-redirect", Location: "app.py:2", Issue: "i2", Fix: "f2"}
	r := &fakeReviewer{findings: []wire.Finding{old, fresh}}
	gh := &fakeGitHub{existing: []string{"an earlier run said this\n" + prpost.Marker(old)}}

	var out bytes.Buffer
	if _, err := Run(r, Options{Cwd: dir, Base: "main", PR: 7, Post: gh.client(t), Out: &out}); err != nil {
		t.Fatal(err)
	}
	if len(gh.posted) != 1 || len(gh.posted[0].Comments) != 1 {
		t.Fatalf("expected one review carrying the new finding; got %+v", gh.posted)
	}
	if !strings.Contains(gh.posted[0].Body, "already commented") {
		t.Errorf("the summary must still say why the other finding is not repeated; got:\n%s", gh.posted[0].Body)
	}
}

// ⚠️ A CLEAN FIRST RUN POSTS. `New` is zero on a pull request with no findings, so a rule of
// "post only when something is new" would silence exactly the result a reader most needs
// stated — and silence is what an unconfigured lane looks like.
func TestACleanPullRequestIsStillReportedOnTheFirstRun(t *testing.T) {
	dir := branchWith(t, map[string]string{"app.py": "one\ntwo\nimport requests\n"})
	r := &fakeReviewer{}
	gh := &fakeGitHub{}

	var out bytes.Buffer
	if _, err := Run(r, Options{Cwd: dir, Base: "main", PR: 7, Post: gh.client(t), Out: &out}); err != nil {
		t.Fatal(err)
	}
	if len(gh.posted) != 1 {
		t.Fatalf("a clean first run must say so; got %+v", gh.posted)
	}
	if !strings.Contains(gh.posted[0].Body, "No findings") {
		t.Errorf("expected the clean summary; got:\n%s", gh.posted[0].Body)
	}
}

// TestADifferentRuleAtACommentedLineIsStillPosted: the marker carries the RULE, so a
// genuinely different vulnerability at a line we commented on before is not read as
// already posted. Without it that is a missed detection wearing a duplicate's clothing.
func TestADifferentRuleAtACommentedLineIsStillPosted(t *testing.T) {
	dir := branchWith(t, map[string]string{"app.py": "one\ntwo\nimport requests\n"})
	old := wire.Finding{Rule: "ssrf", Location: "app.py:3"}
	fresh := wire.Finding{Rule: "open-redirect", Location: "app.py:3", Issue: "i", Fix: "f"}
	r := &fakeReviewer{findings: []wire.Finding{fresh}}
	gh := &fakeGitHub{existing: []string{"earlier\n" + prpost.Marker(old)}}

	var out bytes.Buffer
	res, err := Run(r, Options{Cwd: dir, Base: "main", PR: 7, Post: gh.client(t), Out: &out})
	if err != nil {
		t.Fatal(err)
	}
	if res.Inline != 1 {
		t.Errorf("Inline = %d, want 1 — a different rule at the same line is a different finding", res.Inline)
	}
}

// TestARefusedCommentArrayStillPostsTheFindings: the summary carries every finding's
// prose, so a single line GitHub disagrees with us about being in the diff must not
// silence the whole review.
func TestARefusedCommentArrayStillPostsTheFindings(t *testing.T) {
	dir := branchWith(t, map[string]string{"app.py": "one\ntwo\nimport requests\n"})
	r := &fakeReviewer{findings: []wire.Finding{{Rule: "ssrf", Location: "app.py:3", Issue: "i", Fix: "f"}}}
	gh := &fakeGitHub{postErr: 1}

	var out bytes.Buffer
	res, err := Run(r, Options{Cwd: dir, Base: "main", PR: 7, Post: gh.client(t), Out: &out})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Posted {
		t.Error("the retry with the summary alone must still get the findings onto the pull request")
	}
	if len(gh.posted) != 2 || len(gh.posted[1].Comments) != 0 {
		t.Errorf("expected a retry carrying the summary and no comments; got %+v", gh.posted)
	}
}

// TestAReviewErrorFailsOpenAndSaysSo: fail-open is the non-negotiable, but a CI step
// CAN say so out loud without interrupting anybody — and a security check that
// silently did nothing is the false assurance the skip notice exists to remove.
func TestAReviewErrorFailsOpenAndSaysSo(t *testing.T) {
	dir := branchWith(t, map[string]string{"app.py": "import requests\n"})
	r := &fakeReviewer{err: errBoom{}}
	gh := &fakeGitHub{}

	var out bytes.Buffer
	res, err := Run(r, Options{Cwd: dir, Base: "main", PR: 7, Post: gh.client(t), Out: &out})
	if err != nil {
		t.Fatalf("a review error must not be returned as an error: %v", err)
	}
	if res.Reviewed {
		t.Error("Reviewed must be false when the review could not run")
	}
	if len(gh.posted) != 1 || !strings.Contains(gh.posted[0].Body, "not reviewed") {
		t.Errorf("the pull request must be told it was not reviewed; got %+v", gh.posted)
	}
	if !strings.Contains(gh.posted[0].Body, "absence of review") {
		t.Errorf("the skip notice must distinguish no review from no findings; got:\n%s", gh.posted[0].Body)
	}
}

// TestAShallowCloneNamesItsOwnFix: it is the DEFAULT for actions/checkout, so it is
// the failure nearly every first installation hits, and it is one line to fix.
func TestAShallowCloneNamesItsOwnFix(t *testing.T) {
	dir := repo(t)
	put(t, dir, "seed.py", "seed = 1\n")
	gitc(t, dir, "add", "-A")
	gitc(t, dir, "commit", "-qm", "seed")
	gh := &fakeGitHub{}

	var out bytes.Buffer
	if _, err := Run(&fakeReviewer{}, Options{Cwd: dir, Base: "no-such-base", PR: 7, Post: gh.client(t), Out: &out}); err != nil {
		t.Fatal(err)
	}
	if len(gh.posted) != 1 || !strings.Contains(gh.posted[0].Body, "fetch-depth: 0") {
		t.Errorf("an unresolvable base must name the shallow-clone fix; got %+v", gh.posted)
	}
}

// TestNoCopyAttributesAuthorship: a pull request's added lines may be several
// people's over days, so a comment reading as an accusation against whoever opened
// it is both wrong and the fastest way to have the check switched off.
// TestNoDashesInPostedCopy: every string here is posted to a pull request, which is a
// user-facing surface — on a public repository, the most public one this product has. The
// house rule is a comma, a colon or a second sentence, never a dash used as punctuation.
// It is worth a test because a dash reads fine in review and this copy is edited often.
// TestNoSuggestionBlock: a ```suggestion fence renders a one-click Commit button, so
// a reviewer would be applying a model's proposed security fix without reading it —
// the opposite of this lane's advisory posture, and a change nobody authored.
type errBoom struct{}

func (errBoom) Error() string { return "boom" }

// TestTheTokenIsNeverSENTToAnUNVALIDATEDORIGIN. $GITHUB_API_URL is a value we did not
// choose, and every request built on it carries `Authorization: Bearer <GITHUB_TOKEN>` — a
// token with write access to the customer's pull requests. A base pointing anywhere would
// exfiltrate it, which is the one thing the header's whole purpose forbids.
// TestARefusedBaseDoesNotFallBackToGithub: falling back would silently send an Enterprise
// customer's code and findings to github.com, which is worse than the refusal.
// TestAForgedMarkerCannotSuppressAFinding. The judge's `issue` and `fix` are the one part of
// a comment we did not write, and the diff under review is attacker-influenced. A judge
// coaxed into emitting marker-shaped prose could otherwise make a DIFFERENT real finding read
// as already-commented and be silently dropped: detected, recorded, and never mentioned.
// TestTheProseGuardIsAppliedToEveryModelAuthoredSurface: the inline comment is not the only
// place the judge's words are composed into a body, and a guard applied to one of two call
// sites is the failure that reads as fixed.
// TestNoPathCanMoveTheRequestOffTheAPIOrigin. `do` takes a PATH and resolves the origin
// itself, so a caller cannot supply one — which means every request lands on the base that
// `api()` validated, whatever the path looks like.
//
// ⚠️ Note what this does NOT claim. Because the base already carries a scheme and a host,
// concatenating a path can never move the host: `//evil.example/x` becomes a PATH on the
// API host, and so does a path that looks like a whole URL. The origin re-check in `do` is
// belt-and-braces that should never fire, and an earlier version of this test asserted it
// would — which was wrong about the mechanism and would have gone green against a guard
// that refused everything. What is worth pinning is the property the shape provides: the
// request goes to the API origin, and a hostile-looking path does not reach the other host.
// TestTheClientDoesNotFollowRedirects. Validating the base is worthless against a 302: Go's
// default client follows up to ten and RE-SENDS the Authorization header on a same-host hop,
// so a validated origin answering `Location: http://169.254.169.254/...` would walk a token
// with write access to the customer's pull requests to a cloud metadata endpoint.
// TestTheSummarySentencesReadAsEnglish pins the two sentences whose subject and verb are
// assembled from separate helpers, in BOTH the singular and the plural.
//
// Nothing asserted the assembled string before, so a helper returning a VERB
// ("they cite") into a slot whose format string already supplied one ("cited") shipped
// "attached to the lines they cite cited, in the diff below" and the whole suite stayed
// green. Every part was individually correct; only the sentence was wrong. This is posted
// copy on a customer's pull request, so a reader who spots it has no way to tell a wording
// slip from a broken renderer.
// TestACitedLineThatDriftsIsStillTheSameFinding pins the de-duplication against the
// failure that was observed live rather than predicted: the judge's cited line is a
// judgement made afresh on every push, so keying equality on it exactly made a
// duplicate comment the normal outcome for any pull request with more than one push.
//
// The numbers are the real ones from the LEO-231 test pull request — the same SSRF
// cited at seeded_flaw.py:7 and then at :8 one push apart.
func TestACitedLineThatDriftsIsStillTheSameFinding(t *testing.T) {
	// Through Run, not through prpost.AlreadyPosted directly: the suppression happens at one
	// call site, and a test that only exercises the predicate goes green against a call
	// site reverted to exact equality (verified by mutation).
	dir := branchWith(t, map[string]string{"app.py": "one\ntwo\nimport requests\nresp = requests.get(u)\n"})
	earlier := wire.Finding{Rule: "ssrf", Location: "app.py:3", Issue: "i", Fix: "f"}
	drifted := wire.Finding{Rule: "ssrf", Location: "app.py:4", Issue: "i", Fix: "f"}
	r := &fakeReviewer{findings: []wire.Finding{drifted}}
	gh := &fakeGitHub{existing: []string{"an earlier run said this\n" + prpost.Marker(earlier)}}

	var out bytes.Buffer
	res, err := Run(r, Options{Cwd: dir, Base: "main", PR: 7, Post: gh.client(t), Out: &out})
	if err != nil {
		t.Fatal(err)
	}
	if res.Inline != 0 {
		t.Errorf("Inline = %d, want 0 — the cited line moved by one, so this is the same finding", res.Inline)
	}

	posted := map[string]bool{
		"<!-- leoprevent:ssrf:seeded_flaw.py:7 -->": true,
	}

	// Exact match still works, including for a marker an older build wrote.
	if !prpost.AlreadyPosted(posted, wire.Finding{Rule: "ssrf", Location: "seeded_flaw.py:7"}) {
		t.Error("failed to match a marker against its own finding")
	}
}

// The tolerance must not swallow a genuinely different finding. These three are the
// cases that would turn the de-dup into a missed detection, which is strictly worse
// than the duplicate it exists to prevent.
