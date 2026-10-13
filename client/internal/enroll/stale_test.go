package enroll

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/config"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

// isolate points the per-machine scratch AND the per-user config dir at temp dirs for one test,
// so these never touch real state and never leak between tests. It also clears the recorded
// active key, so a test cannot inherit the credential a previous one marked.
func isolate(t *testing.T) {
	t.Helper()
	isolateTempDir(t)
	t.Cleanup(config.SetUserConfigDirForTest(t.TempDir()))
	t.Cleanup(SetActiveKeyForTest(""))
}

// isolateTempDir redirects os.TempDir for one test.
//
// ⚠️ TMPDIR ALONE IS POSIX-ONLY: os.TempDir reads TMPDIR on Unix but TMP, then TEMP, on
// Windows. So every test in this package shared the machine's REAL temp dir there, one
// test's markers and cooldown stamp were still on disk for the next, and the two tests
// that assert on an EMPTY scratch dir failed — reading as a Windows path bug in the code
// under test rather than as cross-contamination in the harness. Set all three: the
// variable that is ignored on a platform costs nothing.
func isolateTempDir(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	for _, key := range []string{"TMPDIR", "TMP", "TEMP"} {
		t.Setenv(key, dir)
	}
}

// TestTheMarkerIsKeyedOnTheCredentialNotTheSession is the regression test for the version of
// this that shipped broken.
//
// The first implementation keyed the marker on the session id, so recovery only fired on a
// SECOND turn inside one session — and since `claude -p` is one turn per session, a headless
// fleet could never recover at all. "The server rejects this key" is a property of the key, so
// the marker has to be too: equally true in the next session, tomorrow, and headless.
func TestTheMarkerIsKeyedOnTheCredentialNotTheSession(t *testing.T) {
	isolate(t)

	const rejected = "lp_live_rejected"
	const other = "lp_live_different"

	if staleKeyMarked(rejected) {
		t.Fatal("a fresh machine must not have a marked key")
	}

	// Arrange: mark it the way the engine does, against the credential Ensure recorded.
	defer SetActiveKeyForTest(rejected)()
	MarkStaleKey()

	// Assert: the credential is marked, and only that one.
	if !staleKeyMarked(rejected) {
		t.Error("the rejected credential was not marked")
	}
	if staleKeyMarked(other) {
		t.Error("the marker leaked to a different credential")
	}

	// And it is still marked when nothing about the session is the same, which is the whole point.
	if !staleKeyMarked(rejected) {
		t.Error("the marker did not survive; recovery would never fire in a later session")
	}

	clearStaleKey(rejected)
	if staleKeyMarked(rejected) {
		t.Error("the marker survived being cleared")
	}
}

// TestMarkStaleKeyNeedsAKeyToMark: with no credential recorded there is nothing to blame, and
// inventing a marker would arm a recovery against a key that does not exist.
//
// This is also what makes a test binary safe by construction: nothing that skips Ensure has an
// active key, so it cannot mark one — least of all the developer's real one.
func TestMarkStaleKeyNeedsAKeyToMark(t *testing.T) {
	isolate(t)

	MarkStaleKey() // Ensure never ran, so no active key
	if entries, err := os.ReadDir(staleDir()); err == nil && len(entries) > 0 {
		t.Errorf("marked something with no key present (%d files)", len(entries))
	}
}

// TestEnsureLeavesAWorkingKeyAlone is the guard in the other direction, and the more important
// one: a licensed machine must not re-mint on every turn, or one machine's turn rotates the
// credential out from under the developer's other machines.
func TestEnsureLeavesAWorkingKeyAlone(t *testing.T) {
	isolate(t)

	cfg := &config.Config{
		ServerURL:   "http://127.0.0.1:1", // never dialled: Ensure must return before any call
		Tier:        config.TierCloud,
		LicenseKey:  "lp_live_working",
		EnrollToken: "lp_enroll_tok",
	}
	if !Ensure(cfg, t.TempDir(), "sess-1") {
		t.Error("a licensed machine should report itself licensed")
	}
	if cfg.LicenseKey != "lp_live_working" {
		t.Errorf("the working key was replaced with %q", cfg.LicenseKey)
	}
}

// TestEnsureStopsTrustingARejectedKey: the recovery decision itself. The mint cannot succeed here
// (the port is dead), so what is asserted is that Ensure DECIDED to re-enrol — visible in the
// cooldown stamp, which is the record of an attempt.
//
// ⚠️ It used to assert the decision by checking cfg.LicenseKey had been CLEARED, and that proxy
// was pinning a bug. A failed mint then left the reviewer with no credential at all, so the next
// request was a certain 401 rather than a possible one. The stamp is the honest observable: it
// says an attempt happened without requiring the key to have been thrown away first.
func TestEnsureStopsTrustingARejectedKey(t *testing.T) {
	isolate(t)

	cfg := &config.Config{
		ServerURL:   "http://127.0.0.1:1",
		Tier:        config.TierCloud,
		LicenseKey:  "lp_live_rejected",
		EnrollToken: "lp_enroll_tok",
	}
	defer SetActiveKeyForTest(cfg.LicenseKey)()
	MarkStaleKey()

	Ensure(cfg, t.TempDir(), "sess-1")

	if _, err := os.Stat(cooldownPath()); err != nil {
		t.Error("Ensure did not attempt a re-enrolment for a key it was told is rejected")
	}
	if cfg.LicenseKey != "lp_live_rejected" {
		t.Errorf("a failed re-enrolment discarded the only credential the machine had: %q", cfg.LicenseKey)
	}
}

// TestTheCooldownBoundsAPathologicalLoop. The digest marker already stops the common loop, since
// a successful mint has a different digest. This covers the case where even a freshly minted key
// is refused, which would otherwise be one mint per turn forever.
func TestTheCooldownBoundsAPathologicalLoop(t *testing.T) {
	isolate(t)

	newCfg := func() *config.Config {
		return &config.Config{
			ServerURL:   "http://127.0.0.1:1",
			Tier:        config.TierCloud,
			LicenseKey:  "lp_live_rejected",
			EnrollToken: "lp_enroll_tok",
		}
	}
	defer SetActiveKeyForTest("lp_live_rejected")()
	MarkStaleKey()

	// First attempt decides to re-enrol and stamps the cooldown.
	first := newCfg()
	Ensure(first, t.TempDir(), "sess-1")
	if _, err := os.Stat(cooldownPath()); err != nil {
		t.Fatal("the first attempt did not act on the rejection")
	}

	// The next turn, in a DIFFERENT session, must be held off by the cooldown rather than
	// minting again.
	second := newCfg()
	if !Ensure(second, t.TempDir(), "sess-2") {
		t.Error("a cooled-down machine should report early rather than mint again")
	}
	if second.LicenseKey != "lp_live_rejected" {
		t.Error("the cooldown did not hold; this machine would mint once per turn")
	}
}

// TestCleanupKeepsTheCooldownStamp: the sweep drops old markers but must not drop the cooldown,
// or the bound it provides disappears exactly when a machine is looping.
func TestCleanupKeepsTheCooldownStamp(t *testing.T) {
	isolate(t)

	noteReEnrolAttempt()
	cleanupStale()
	if _, err := os.Stat(cooldownPath()); err != nil {
		t.Error("the sweep removed the cooldown stamp")
	}
}

// TestCleanupStaleSurvivesAMissingDir: the sweep runs on a path that may never have existed.
func TestCleanupStaleSurvivesAMissingDir(t *testing.T) {
	isolate(t)
	_ = os.RemoveAll(filepath.Join(os.TempDir(), "leoprevent-stale-keys"))
	cleanupStale() // must not panic
}

// --- regressions for the recovery loop found live on 2026-08-25 -------------------------------

// repoWithIdentity returns a directory Ensure can mint from: a git repo carrying a LOCAL
// user.name/user.email.
//
// ⚠️ Ensure refuses to enrol a machine with no git identity, so a test that mints must supply
// one rather than inherit it. Passing a bare t.TempDir() inherits whatever the host's git config
// says: fine on a developer box, and empty on EVERY GitHub runner — actions/checkout configures
// the checkout LOCALLY and sets no global identity, and a temp dir is outside that repo. So a
// clean local run went red on all three platforms at once. Set locally here, so the test neither
// depends on nor disturbs whatever the machine has.
func repoWithIdentity(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, args := range [][]string{
		{"init"},
		{"config", "user.name", "Ada Lovelace"},
		{"config", "user.email", "ada@acme.com"},
	} {
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	return dir
}

// enrollServer stands in for the mint endpoint and counts the attempts that reach it. Returning
// a key lets a test assert the whole recovery, not only that a request went out.
func enrollServer(t *testing.T, key string) (url string, hits *int) {
	t.Helper()
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/enroll" {
			http.NotFound(w, r)
			return
		}
		n++
		_ = json.NewEncoder(w).Encode(wire.EnrollResponse{
			LicenseKey: key, LicenseID: "lic_test", AccountID: "acct_test",
		})
	}))
	t.Cleanup(srv.Close)
	return srv.URL, &n
}

// TestMarkStaleKeyIgnoresThePerUserFile is the guard on the bug that poisoned a real machine.
//
// MarkStaleKey used to resolve the credential itself out of the per-user license.json. In a test
// binary that is the DEVELOPER'S OWN key, so running the suite marked it rejected and armed a
// re-enrolment that rotated a working credential — silently, because everything here fails open.
// It marks only what Ensure recorded, so a binary that never calls Ensure marks nothing.
//
// The license file below is what the old code would have picked up; nothing may.
func TestMarkStaleKeyIgnoresThePerUserFile(t *testing.T) {
	isolate(t)

	if _, err := config.SaveLicense("lp_live_the_developers_real_key"); err != nil {
		t.Fatalf("save: %v", err)
	}
	MarkStaleKey() // no active key recorded: Ensure never ran

	if staleKeyMarked("lp_live_the_developers_real_key") {
		t.Fatal("marked a credential read straight from the per-user file; a test run would " +
			"rotate the developer's own key")
	}
	if entries, err := os.ReadDir(staleDir()); err == nil && len(entries) > 0 {
		t.Errorf("marked something with no active key (%d files)", len(entries))
	}
}

// TestEnsureRecordsTheResolvedKeyNotTheFile: the same root cause, in production rather than in a
// test binary. The key actually sent is the RESOLVED one (plugin json → per-user file → env,
// later wins), so a machine using $LEOPREVENT_LICENSE_KEY or a plugin-baked key had its rejection
// recorded against a digest staleKeyMarked would never look up, and could never recover.
func TestEnsureRecordsTheResolvedKeyNotTheFile(t *testing.T) {
	isolate(t)

	if _, err := config.SaveLicense("lp_live_from_the_file"); err != nil {
		t.Fatalf("save: %v", err)
	}
	cfg := &config.Config{
		ServerURL:  "http://127.0.0.1:1",
		Tier:       config.TierCloud,
		LicenseKey: "lp_live_resolved_from_env", // what the client will actually send
	}
	Ensure(cfg, t.TempDir(), "sess-1")
	MarkStaleKey()

	if !staleKeyMarked("lp_live_resolved_from_env") {
		t.Error("the rejection was not recorded against the credential the client sends, so the " +
			"next turn would find nothing marked and never recover")
	}
	if staleKeyMarked("lp_live_from_the_file") {
		t.Error("recorded the rejection against the per-user file instead of the resolved key")
	}
}

// TestASecondRejectionInOneSessionStillRecovers is the bug that stranded a live machine.
//
// The re-enrolment shared the FIRST-TIME enrolment's once-per-session budget, so a machine that
// recovered once in a session found it spent on every later rejection and returned without
// minting. A session is a working day on a long-running agent, which is exactly the window in
// which a seat is revoked and re-granted or a key is rotated elsewhere.
//
// The cooldown is cleared between the two, because this is about the SESSION throttle; the
// cooldown's own bound has its own test above.
func TestASecondRejectionInOneSessionStillRecovers(t *testing.T) {
	isolate(t)
	url, hits := enrollServer(t, "lp_live_minted_two")

	const sess = "one-long-session"

	// A first-time enrolment earlier in the session, which consumes the throttle.
	repo := repoWithIdentity(t)
	first := &config.Config{ServerURL: url, Tier: config.TierCloud, EnrollToken: "lp_enroll_tok"}
	if !Ensure(first, repo, sess) {
		t.Fatalf("first-time enrolment failed; hits=%d", *hits)
	}

	// Later in the SAME session the credential is refused.
	second := &config.Config{
		ServerURL: url, Tier: config.TierCloud,
		LicenseKey: first.LicenseKey, EnrollToken: "lp_enroll_tok",
	}
	MarkStaleKey() // Ensure recorded first.LicenseKey as active
	_ = os.Remove(cooldownPath())

	Ensure(second, repo, sess)

	if *hits < 2 {
		t.Fatalf("the re-enrolment never reached the server (hits=%d): a machine rejected twice "+
			"in one session cannot recover until the agent is restarted", *hits)
	}
	if second.LicenseKey != "lp_live_minted_two" {
		t.Errorf("recovered key = %q, want the freshly minted one", second.LicenseKey)
	}
}

// TestAThrottledReEnrolmentKeepsTheKeyItHas: clearing the credential on a path that then declines
// to mint was worse than doing nothing. It left the reviewer with NO key, so the next request was
// a certain 401 ("missing license") rather than a possible one — measured live at one lost review
// in every two while a machine sat in this state.
//
// Here the tier is local, so Ensure returns before minting. Whatever the reason, the machine must
// come out still holding the only credential it has.
func TestAThrottledReEnrolmentKeepsTheKeyItHas(t *testing.T) {
	isolate(t)

	cfg := &config.Config{
		ServerURL:   "http://127.0.0.1:1",
		Tier:        config.TierLocal,
		LicenseKey:  "lp_live_rejected",
		EnrollToken: "lp_enroll_tok",
	}
	defer SetActiveKeyForTest(cfg.LicenseKey)()
	MarkStaleKey()

	Ensure(cfg, t.TempDir(), "sess-1")

	if cfg.LicenseKey != "lp_live_rejected" {
		t.Errorf("LicenseKey = %q; a path that declined to mint discarded the key anyway, "+
			"guaranteeing a 401 on the next request", cfg.LicenseKey)
	}
}
