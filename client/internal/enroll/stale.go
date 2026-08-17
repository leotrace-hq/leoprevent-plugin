package enroll

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"time"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/config"
)

// A KEY THE SERVER REJECTS IS A DEAD END, AND THIS IS HOW WE GET OUT OF IT.
//
// Ensure deliberately returns early when a key is already present: enrolment exists to give a
// machine its FIRST key, and re-minting every turn would rotate a working credential out from
// under a developer's other machines. But that early return had a failure mode with no way
// back. A machine holding a key the server does not recognise gets 401 on every call, fails
// open, reports nothing, and never enrols, because from its own point of view it is licensed.
// The plugin installed and firing and completely useless, with the only signal a skip notice
// the desktop app does not even render.
//
// Not hypothetical. Found live: a developer pasted a PROD key into the DEV plugin, and since
// license.json is one per-user file shared by both channels the key was real, just not real on
// that server. The same shape covers a key rotated on another machine, a developer revoked and
// later re-invited, and a mistyped paste.
//
// ⚠️ THE MARKER IS KEYED ON THE CREDENTIAL, NOT ON THE SESSION, and the first version of this
// got that wrong in a way that made the whole feature almost useless. "The server rejects this
// key" is a property of the KEY: it is equally true in the next session, on the next day, and
// in a headless run. A per-session marker meant recovery only fired on a SECOND turn inside one
// session, so `claude -p` — one turn per session — could never recover at all, which is exactly
// how it failed when first tested.
//
// Keying on the digest also gives loop safety for free: a successful mint produces a different
// key, whose digest is unmarked, so the recovery cannot re-trigger on its own result. The
// cooldown below bounds the pathological case where even a freshly minted key is refused.
//
// Same scratch pattern as vcs/notify/outcome, because the hook is a fresh process every turn and
// there is nowhere else to keep it. Best-effort throughout: a scratch error costs a recovery we
// would not otherwise have had, never a working turn.

// staleDir holds one marker per rejected credential, named by its digest.
func staleDir() string { return filepath.Join(os.TempDir(), "leoprevent-stale-keys") }

// cooldownPath is the machine-wide timestamp of the last re-enrolment attempt.
func cooldownPath() string { return filepath.Join(staleDir(), "last-attempt") }

// reEnrolCooldown bounds how often a machine may re-mint. The digest marker already stops the
// common loop; this covers the pathological one where the server refuses even the key it just
// issued, which would otherwise be one mint per turn forever.
const reEnrolCooldown = 5 * time.Minute

// keyMarker is the filename for a credential's marker: a truncated digest, so the file name
// leaks nothing usable even to someone reading the temp directory. Never the key itself.
func keyMarker(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])[:32]
}

// MarkStaleKey records that the server rejected the key this machine is currently using.
//
// It resolves the key itself rather than taking one as an argument, so the engine can call it
// without threading the credential through, and so the value marked is exactly the one the
// client actually sent.
//
// Deliberately only called for an UNAUTHORIZED reply. A timeout, an unreachable server or a 5xx
// say nothing about whether the key is valid, and discarding a good credential because the
// server was briefly down would rotate a whole fleet's keys over an outage that fixed itself.
func MarkStaleKey() {
	// The per-user file, NOT config.Load: Load fails on a missing server_url, so building this on
	// it made the recovery silently no-op in a test binary and would do the same on any machine
	// with a broken plugin config. See config.UserLicenseKey for the env-override caveat.
	key := config.UserLicenseKey()
	if key == "" {
		return
	}
	cleanupStale()
	if err := os.MkdirAll(staleDir(), 0o700); err != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(staleDir(), keyMarker(key)), []byte("1"), 0o600)
}

// staleKeyMarked reports whether this exact credential has been refused.
func staleKeyMarked(key string) bool {
	if key == "" {
		return false
	}
	_, err := os.Stat(filepath.Join(staleDir(), keyMarker(key)))
	return err == nil
}

// clearStaleKey forgets a credential's marker, called after a successful re-enrolment so the
// old key's record does not linger and so a later refusal of the NEW key is its own event.
func clearStaleKey(key string) {
	if key == "" {
		return
	}
	_ = os.Remove(filepath.Join(staleDir(), keyMarker(key)))
}

// coolingDown reports whether a re-enrolment was attempted too recently to try again.
func coolingDown() bool {
	info, err := os.Stat(cooldownPath())
	if err != nil {
		return false
	}
	return time.Since(info.ModTime()) < reEnrolCooldown
}

// noteReEnrolAttempt stamps the cooldown. Called before the attempt, not after, so a mint that
// hangs or crashes still counts and cannot become a hot loop.
func noteReEnrolAttempt() {
	if err := os.MkdirAll(staleDir(), 0o700); err != nil {
		return
	}
	_ = os.WriteFile(cooldownPath(), []byte(time.Now().UTC().Format(time.RFC3339)), 0o600)
}

// cleanupStale sweeps markers older than the vcs/notify TTL, so a key rejected weeks ago does
// not keep a file forever. A swept marker costs one missed recovery, which the next rejection
// re-arms immediately.
func cleanupStale() {
	entries, err := os.ReadDir(staleDir())
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-6 * time.Hour)
	for _, e := range entries {
		if e.Name() == filepath.Base(cooldownPath()) {
			continue // the cooldown stamp ages out on its own terms
		}
		info, err := e.Info()
		if err != nil || info.ModTime().After(cutoff) {
			continue
		}
		_ = os.Remove(filepath.Join(staleDir(), e.Name()))
	}
}
