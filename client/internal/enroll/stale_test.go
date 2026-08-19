package enroll

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/config"
)

// isolate points the per-machine scratch AND the per-user config dir at temp dirs for one test,
// so these never touch real state and never leak between tests. The config dir matters because
// MarkStaleKey resolves the current key through config.Load.
func isolate(t *testing.T) {
	t.Helper()
	isolateTempDir(t)
	t.Cleanup(config.SetUserConfigDirForTest(t.TempDir()))
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

	// Arrange: mark it the way the engine does, by writing it to the per-user config first.
	if _, err := config.SaveLicense(rejected); err != nil {
		t.Fatalf("save: %v", err)
	}
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

// TestMarkStaleKeyNeedsAKeyToMark: with no credential resolvable there is nothing to blame, and
// inventing a marker would arm a recovery against a key that does not exist.
func TestMarkStaleKeyNeedsAKeyToMark(t *testing.T) {
	isolate(t)

	MarkStaleKey() // no license.json written
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
// (the port is dead), so what is asserted is that Ensure DECIDED to re-enrol, visible in it
// discarding the credential it was told is invalid.
func TestEnsureStopsTrustingARejectedKey(t *testing.T) {
	isolate(t)

	cfg := &config.Config{
		ServerURL:   "http://127.0.0.1:1",
		Tier:        config.TierCloud,
		LicenseKey:  "lp_live_rejected",
		EnrollToken: "lp_enroll_tok",
	}
	if _, err := config.SaveLicense(cfg.LicenseKey); err != nil {
		t.Fatalf("save: %v", err)
	}
	MarkStaleKey()

	Ensure(cfg, t.TempDir(), "sess-1")

	if cfg.LicenseKey != "" {
		t.Errorf("a rejected key was still trusted: %q", cfg.LicenseKey)
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
	if _, err := config.SaveLicense("lp_live_rejected"); err != nil {
		t.Fatalf("save: %v", err)
	}
	MarkStaleKey()

	// First attempt decides to re-enrol and stamps the cooldown.
	first := newCfg()
	Ensure(first, t.TempDir(), "sess-1")
	if first.LicenseKey != "" {
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
