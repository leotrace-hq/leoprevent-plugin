package enroll

import (
	"os"
	"path/filepath"
	"strings"
	"time"
)

// A KEY THE SERVER REJECTS IS A DEAD END, AND THIS IS HOW WE GET OUT OF IT.
//
// Ensure deliberately returns early when a key is already present: enrolment exists to give
// a machine its FIRST key, and re-minting on every turn would rotate a working credential
// out from under a developer's other machines. But that early return had a failure mode with
// no way back. A machine holding a key the server does not recognise gets 401 on every call,
// fails open, reports nothing, and never enrols — because from its own point of view it is
// licensed. The plugin is installed and firing and completely useless, and the only signal
// is a skip notice the desktop app does not even render.
//
// It is not a rare state. Observed live: a developer pasted a PROD key into the DEV plugin,
// and since license.json is one per-user file shared by both channels the key was real, just
// not real on that server. The same shape covers a key rotated on another machine, a
// developer revoked and later re-invited, and a mistyped paste.
//
// So an unauthorized reply now leaves a per-session marker, and the NEXT turn's Ensure treats
// the stored key as invalid and re-enrols. Recovery lands one turn late by design: the
// alternative is retrying inside the failing turn, which would mean rebuilding the reviewer
// mid-flight and paying a second round trip on a path that is already failing.
//
// The same scratch pattern as vcs/notify/outcome, because the hook is a fresh process every
// turn and there is nowhere else to keep it. Best-effort throughout: a scratch error costs a
// recovery we would not otherwise have had, never a working turn.

// staleDir holds one marker file per session whose key the server rejected.
func staleDir() string { return filepath.Join(os.TempDir(), "leoprevent-stale-keys") }

func stalePath(sessionID string) string {
	return filepath.Join(staleDir(), sanitize(sessionID))
}

// sanitize keeps a session id usable as a filename, matching notify's rule.
func sanitize(sessionID string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		default:
			return '_'
		}
	}, sessionID)
}

// MarkStaleKey records that the server rejected this session's license key.
//
// Called from the engine's skip-notice path on an unauthorized reply. Deliberately NOT called
// on a timeout, an unreachable server or a 5xx: those say nothing about whether the key is
// valid, and discarding a good credential because the server was briefly down would turn a
// blip into a re-mint that invalidates the developer's other machines.
func MarkStaleKey(sessionID string) {
	if sessionID == "" {
		return
	}
	cleanupStale()
	if err := os.MkdirAll(staleDir(), 0o700); err != nil {
		return
	}
	_ = os.WriteFile(stalePath(sessionID), []byte("1"), 0o600)
}

// staleKeyMarked reports whether this session has seen its key rejected.
func staleKeyMarked(sessionID string) bool {
	if sessionID == "" {
		return false
	}
	_, err := os.Stat(stalePath(sessionID))
	return err == nil
}

// clearStaleKey forgets the marker after a successful re-enrolment, so a later genuine
// rejection of the NEW key is treated as its own event rather than being suppressed.
func clearStaleKey(sessionID string) {
	if sessionID == "" {
		return
	}
	_ = os.Remove(stalePath(sessionID))
}

// cleanupStale sweeps markers from dead sessions, same 6h TTL as the vcs/notify sweeps. A
// swept marker costs one missed recovery, which the next rejection re-arms.
func cleanupStale() {
	entries, err := os.ReadDir(staleDir())
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-6 * time.Hour)
	for _, e := range entries {
		info, err := e.Info()
		if err != nil || info.ModTime().After(cutoff) {
			continue
		}
		_ = os.Remove(filepath.Join(staleDir(), e.Name()))
	}
}
