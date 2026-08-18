package update

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseAndLess(t *testing.T) {
	cases := []struct {
		a, b       string
		aOK, aLess bool
	}{
		{"0.1.4", "0.1.5", true, true},
		{"0.1.5", "0.1.5", true, false},
		{"0.2.0", "0.1.9", true, false},
		{"1.0.0", "0.9.9", true, false},
		{"0.1.5-rc1", "0.1.5", true, false}, // suffix truncated → equal
		{"v0.1.4", "0.1.5", true, true},     // leading v tolerated
	}
	for _, c := range cases {
		av, ok := parse(c.a)
		if ok != c.aOK {
			t.Errorf("parse(%q) ok = %v, want %v", c.a, ok, c.aOK)
		}
		bv, _ := parse(c.b)
		if got := less(av, bv); got != c.aLess {
			t.Errorf("less(%q,%q) = %v, want %v", c.a, c.b, got, c.aLess)
		}
	}
	for _, bad := range []string{"", "dev", "unknown", "x.y.z"} {
		if _, ok := parse(bad); ok {
			t.Errorf("parse(%q) should be !ok", bad)
		}
	}
}

// TestPrereleaseNotNewerThanRelease pins the dev-channel safety property (LEO-57):
// a dev build's prerelease version ("X.Y.Z-dev.<sha>") must never be treated as
// NEWER than the base release "X.Y.Z", so a production install on the base version
// gets no update nag if it ever saw a dev version advertised. The suffix is truncated
// at the first non-digit, so the prerelease and its release compare EQUAL on the base.
func TestPrereleaseNotNewerThanRelease(t *testing.T) {
	pre, ok := parse("0.2.16-dev.a1b2c3d")
	if !ok {
		t.Fatal("a dev prerelease must still parse (it carries a numeric base)")
	}
	rel, _ := parse("0.2.16")
	if less(rel, pre) {
		t.Error("release must not be considered older than a same-base dev prerelease")
	}
	if less(pre, rel) {
		t.Error("a same-base dev prerelease must not be considered older than its release")
	}

	// End to end: a prod install exactly on the base release, told a dev version is
	// "latest", must not nag.
	restore := SetUserConfigDirForTest(t.TempDir())
	t.Cleanup(restore)
	RecordLatest("0.2.16-dev.a1b2c3d")
	if latest, ok := PendingNag("claude", "0.2.16"); ok {
		t.Errorf("prod install on the base release must not nag off a dev version: got (%q,%v)", latest, ok)
	}
}

func TestPendingNagFiresOncePerDay(t *testing.T) {
	restore := SetUserConfigDirForTest(t.TempDir())
	t.Cleanup(restore)
	clock := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	restoreNow := SetNowForTest(func() time.Time { return clock })
	t.Cleanup(restoreNow)

	// Nothing recorded yet → no nag.
	if _, ok := PendingNag("claude", "0.1.4"); ok {
		t.Fatal("no cached latest → should not nag")
	}

	// Server advertises a newer version → nag, then suppressed within the day.
	RecordLatest("0.1.5")
	latest, ok := PendingNag("claude", "0.1.4")
	if !ok || latest != "0.1.5" {
		t.Fatalf("first nag: got (%q,%v), want (0.1.5,true)", latest, ok)
	}
	if _, ok := PendingNag("claude", "0.1.4"); ok {
		t.Error("second call same day should be suppressed")
	}
	clock = clock.Add(renagInterval - time.Minute)
	if _, ok := PendingNag("claude", "0.1.4"); ok {
		t.Error("call just under the interval should be suppressed")
	}

	// A day later, still behind → nag again.
	clock = clock.Add(2 * time.Minute)
	if latest, ok := PendingNag("claude", "0.1.4"); !ok || latest != "0.1.5" {
		t.Errorf("still behind after the interval should re-nag: got (%q,%v)", latest, ok)
	}
	if _, ok := PendingNag("claude", "0.1.4"); ok {
		t.Error("re-nag should re-stamp the clock and suppress again")
	}

	// A yet-newer version re-arms the nag immediately.
	RecordLatest("0.1.6")
	if latest, ok := PendingNag("claude", "0.1.4"); !ok || latest != "0.1.6" {
		t.Errorf("newer version should re-nag immediately: got (%q,%v)", latest, ok)
	}
}

func TestPendingNagIsPerAgentAndPerVersion(t *testing.T) {
	restore := SetUserConfigDirForTest(t.TempDir())
	t.Cleanup(restore)
	clock := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	restoreNow := SetNowForTest(func() time.Time { return clock })
	t.Cleanup(restoreNow)

	RecordLatest("0.2.3")

	// claude consumes its nag → copilot at the same version still gets its own.
	if _, ok := PendingNag("claude", "0.2.1"); !ok {
		t.Fatal("claude first nag should fire")
	}
	if latest, ok := PendingNag("copilot", "0.2.1"); !ok || latest != "0.2.3" {
		t.Errorf("copilot must not be silenced by claude's nag: got (%q,%v)", latest, ok)
	}

	// The ghost bug: a STALE copilot install (0.2.1, just nagged above) must not
	// silence the real copilot install at 0.2.2.
	if latest, ok := PendingNag("copilot", "0.2.2"); !ok || latest != "0.2.3" {
		t.Errorf("a stale same-agent install must not silence a newer one: got (%q,%v)", latest, ok)
	}

	// Each keeps its own daily throttle.
	if _, ok := PendingNag("copilot", "0.2.1"); ok {
		t.Error("copilot@0.2.1 second call same day should be suppressed")
	}
	if _, ok := PendingNag("copilot", "0.2.2"); ok {
		t.Error("copilot@0.2.2 second call same day should be suppressed")
	}
}

func TestPendingNagLegacyFlatCacheIgnored(t *testing.T) {
	// A cache written by a pre-warned_by client has flat warned/warned_at fields;
	// they are deliberately not decoded → one re-nag, then self-heal on the new key.
	restore := SetUserConfigDirForTest(t.TempDir())
	t.Cleanup(restore)
	clock := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	restoreNow := SetNowForTest(func() time.Time { return clock })
	t.Cleanup(restoreNow)

	path, err := cachePath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	legacy := `{"latest":"0.1.5","warned":"0.1.5","warned_at":"2026-07-20T11:59:00Z"}`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	if latest, ok := PendingNag("claude", "0.1.4"); !ok || latest != "0.1.5" {
		t.Fatalf("legacy flat cache should re-nag once: got (%q,%v)", latest, ok)
	}
	if _, ok := PendingNag("claude", "0.1.4"); ok {
		t.Error("after self-heal the same day should be suppressed")
	}
}

func TestPruneStaleDropsOldEntries(t *testing.T) {
	restore := SetUserConfigDirForTest(t.TempDir())
	t.Cleanup(restore)
	clock := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	restoreNow := SetNowForTest(func() time.Time { return clock })
	t.Cleanup(restoreNow)

	RecordLatest("0.2.0")
	if _, ok := PendingNag("claude", "0.1.0"); !ok {
		t.Fatal("first nag should fire")
	}

	// 31 days later a new nag prunes the old entry.
	clock = clock.Add(31 * 24 * time.Hour)
	if _, ok := PendingNag("copilot", "0.1.0"); !ok {
		t.Fatal("copilot nag should fire")
	}
	s := load()
	if _, exists := s.WarnedBy["claude@0.1.0"]; exists {
		t.Error("entry older than pruneWindow should have been pruned")
	}
	if _, exists := s.WarnedBy["copilot@0.1.0"]; !exists {
		t.Error("fresh entry must survive the prune")
	}
}

func TestPendingNagSilentWhenCurrentIsDevOrAhead(t *testing.T) {
	restore := SetUserConfigDirForTest(t.TempDir())
	t.Cleanup(restore)

	RecordLatest("0.1.5")
	if _, ok := PendingNag("claude", "dev"); ok {
		t.Error("dev build should never nag")
	}
	if _, ok := PendingNag("claude", "0.2.0"); ok {
		t.Error("running ahead of latest should not nag")
	}
	if _, ok := PendingNag("claude", "0.1.5"); ok {
		t.Error("running exactly latest should not nag")
	}
}

func TestRecordLatestIgnoresGarbage(t *testing.T) {
	restore := SetUserConfigDirForTest(t.TempDir())
	t.Cleanup(restore)

	RecordLatest("") // no header
	RecordLatest("garbage")
	if _, ok := PendingNag("claude", "0.1.4"); ok {
		t.Error("garbage latest should not produce a nag")
	}
}

func TestMessagePerAgent(t *testing.T) {
	claude := Message("claude", "0.1.4", "0.1.5")
	if !strings.Contains(claude, "/plugin marketplace update leotrace") || !strings.Contains(claude, "0.1.5") {
		t.Errorf("claude message missing update command or version: %q", claude)
	}
	codex := Message("codex", "0.1.4", "0.1.5")
	if !strings.Contains(codex, "codex plugin marketplace upgrade") {
		t.Errorf("codex message missing codex command: %q", codex)
	}
}

// ContextMessage is what makes the nag visible on surfaces that never receive a
// systemMessage (desktop app / web UI). It must (a) open with the relay instruction —
// an earlier draft that buried it produced silence from a live agent — (b) name both
// versions, (c) carry the agent's own update command, and (d) mark itself as plugin
// chrome so it doesn't read as part of the answer. Without any of these the injected
// context is either ignored or indistinguishable from the agent's own prose.
func TestContextMessageInstructsRelay(t *testing.T) {
	got := ContextMessage("claude", "0.2.11", "0.2.12")
	if !strings.HasPrefix(got, "Begin your reply") {
		t.Errorf("ContextMessage must OPEN with the relay instruction (a buried one gets ignored); got %q", got)
	}
	for _, want := range []string{
		"0.2.12", "0.2.11",
		"LeoPrevent",
		"not part of your request",            // labels it as plugin chrome
		"/plugin marketplace update leotrace", // the agent's own update command
	} {
		if !strings.Contains(got, want) {
			t.Errorf("ContextMessage missing %q; got %q", want, got)
		}
	}
	// The codex variant must carry codex's command, not Claude's.
	if cx := ContextMessage("codex", "0.2.11", "0.2.12"); !strings.Contains(cx, "codex plugin marketplace upgrade") {
		t.Errorf("codex ContextMessage missing codex command: %q", cx)
	}
}

// TestPendingLicenseNagThrottles pins the missing-license nag's throttle: it fires
// once, then stays quiet until renagInterval has passed. It shares the update
// cache's warned_by map, so this also guards against the two nags evicting each
// other.
func TestPendingLicenseNagThrottles(t *testing.T) {
	defer SetUserConfigDirForTest(t.TempDir())()
	base := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	restore := SetNowForTest(func() time.Time { return base })
	defer restore()

	if !PendingLicenseNag("claude") {
		t.Fatal("first call must nag (no license set, never warned)")
	}
	if PendingLicenseNag("claude") {
		t.Error("second call within the interval must stay quiet")
	}

	// Past the re-nag interval it fires again.
	restore()
	defer SetNowForTest(func() time.Time { return base.Add(renagInterval + time.Minute) })()
	if !PendingLicenseNag("claude") {
		t.Error("must re-nag once the interval has elapsed")
	}
}

// TestLicenseNagDoesNotEvictUpdateNag guards the shared warned_by map: the two
// nags are keyed separately, so consuming one must not re-arm or silence the other.
func TestLicenseNagDoesNotEvictUpdateNag(t *testing.T) {
	defer SetUserConfigDirForTest(t.TempDir())()
	defer SetNowForTest(func() time.Time { return time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC) })()

	RecordLatest("9.9.9")
	if _, ok := PendingNag("claude", "0.1.0"); !ok {
		t.Fatal("update nag should fire")
	}
	if !PendingLicenseNag("claude") {
		t.Error("license nag must still fire — it has its own key")
	}
	if _, ok := PendingNag("claude", "0.1.0"); ok {
		t.Error("update nag must stay throttled after the license nag wrote the cache")
	}
}
