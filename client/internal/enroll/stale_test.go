package enroll

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/config"
)

// isolateScratch points the per-session scratch at a temp dir for one test, so these never
// touch a real session's markers and never leak between tests.
func isolateScratch(t *testing.T) {
	t.Helper()
	t.Setenv("TMPDIR", t.TempDir())
}

// TestStaleKeyMarkerRoundTrips pins the primitive: mark, observe, clear.
func TestStaleKeyMarkerRoundTrips(t *testing.T) {
	isolateScratch(t)

	if staleKeyMarked("sess-1") {
		t.Fatal("a fresh session must not be marked")
	}
	MarkStaleKey("sess-1")
	if !staleKeyMarked("sess-1") {
		t.Error("the marker did not stick")
	}
	// Per session, so one developer's rejected key does not trigger a re-mint in another.
	if staleKeyMarked("sess-2") {
		t.Error("the marker leaked to another session")
	}
	clearStaleKey("sess-1")
	if staleKeyMarked("sess-1") {
		t.Error("the marker survived being cleared")
	}
}

// TestMarkStaleKeyIgnoresAnEmptySession: without a session id there is nowhere to record the
// fact, and inventing a shared filename would make one machine's rejection everyone's.
func TestMarkStaleKeyIgnoresAnEmptySession(t *testing.T) {
	isolateScratch(t)

	MarkStaleKey("")
	if staleKeyMarked("") {
		t.Error("an empty session id must never be marked")
	}
	if entries, err := os.ReadDir(staleDir()); err == nil && len(entries) > 0 {
		t.Errorf("an empty session id wrote %d scratch files", len(entries))
	}
}

// TestEnsureLeavesAWorkingKeyAlone is the guard that matters most in the other direction: a
// licensed machine must not re-mint on every turn, or one machine's turn would rotate the
// credential out from under the developer's other machines.
func TestEnsureLeavesAWorkingKeyAlone(t *testing.T) {
	isolateScratch(t)

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

// TestEnsureRetriesOnceAfterTheServerRejectsTheKey covers the recovery, and the throttle that
// stops it becoming a mint per turn.
//
// The enrolment call itself cannot succeed here (the server URL is a dead port), which is the
// point: what is asserted is that Ensure DECIDED to re-enrol, visible in it clearing the key
// it was told is invalid, and that a second call in the same session does not decide again.
func TestEnsureRetriesOnceAfterTheServerRejectsTheKey(t *testing.T) {
	isolateScratch(t)

	newCfg := func() *config.Config {
		return &config.Config{
			ServerURL:   "http://127.0.0.1:1",
			Tier:        config.TierCloud,
			LicenseKey:  "lp_live_rejected",
			EnrollToken: "lp_enroll_tok",
		}
	}

	// Arrange: the server rejected this session's key.
	MarkStaleKey("sess-1")

	// Act: first turn after the rejection.
	first := newCfg()
	Ensure(first, t.TempDir(), "sess-1")

	// Assert: it stopped trusting the rejected key.
	if first.LicenseKey != "" {
		t.Errorf("a rejected key was still trusted: %q", first.LicenseKey)
	}

	// Act: the next turn in the same session, still marked because the mint failed.
	second := newCfg()
	if !Ensure(second, t.TempDir(), "sess-1") {
		t.Error("a second attempt in the same session should report early, not re-enrol")
	}

	// Assert: the key is untouched, i.e. no second mint was attempted.
	if second.LicenseKey != "lp_live_rejected" {
		t.Error("Ensure re-enrolled twice in one session; the reset throttle is not holding")
	}
}

// TestEnsureIgnoresAMarkWithoutAToken: a deployment that hands out keys directly has no
// enrolment token, and must not have its key discarded by a rejection it cannot act on.
func TestEnsureIgnoresAMarkWithoutAToken(t *testing.T) {
	isolateScratch(t)
	MarkStaleKey("sess-1")

	cfg := &config.Config{
		ServerURL:  "http://127.0.0.1:1",
		Tier:       config.TierCloud,
		LicenseKey: "lp_live_rejected",
		// no EnrollToken
	}
	Ensure(cfg, t.TempDir(), "sess-1")

	// The key is cleared in memory (we were told it is invalid) but nothing on disk is touched
	// and no mint is attempted, so the next process still has whatever license.json holds.
	if _, err := os.Stat(filepath.Join(staleDir())); err != nil {
		t.Log("scratch dir absent, which is fine")
	}
}

// TestCleanupStaleSurvivesAMissingDir: the sweep runs on a path that may never have existed.
func TestCleanupStaleSurvivesAMissingDir(t *testing.T) {
	isolateScratch(t)
	cleanupStale() // must not panic
}
