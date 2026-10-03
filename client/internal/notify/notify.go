// Package notify throttles leoprevent's developer-facing "this turn was NOT
// reviewed" skip notices. A sustained outage (server down for many turns, or a
// bad license used all session) should surface ONCE per session per reason, not
// on every Stop — otherwise the notice becomes noise and gets ignored.
//
// The hook runs as a fresh process each turn, so the "already shown" set is kept
// in a per-session scratch file (the same pattern vcs/outcome use). Best-effort
// throughout: any scratch error fails TOWARD showing the notice — a rare duplicate
// is better than silently suppressing the one warning that a turn was unprotected.
package notify

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// FirstThisSession reports whether a skip notice with reasonKey has NOT yet been
// shown for sessionID this session, recording it so the next call returns false.
// true → show the notice now. An empty sessionID, or any scratch read/write
// error, returns true: we never suppress a notice we can't prove was already shown.
func FirstThisSession(sessionID, reasonKey string) bool {
	cleanupStale()
	if sessionID == "" {
		return true
	}
	path := scratchPath(sessionID)
	seen := load(path)
	if seen[reasonKey] {
		return false
	}
	seen[reasonKey] = true
	save(path, seen) // best-effort: a write failure just risks a future duplicate
	return true
}

// Clear removes a session's shown-notices record (used by tests).
func Clear(sessionID string) { _ = os.Remove(scratchPath(sessionID)) }

// load reads the set of already-shown reason keys; any error yields an empty set
// (so the notice shows — fail toward informing the developer).
func load(path string) map[string]bool {
	seen := map[string]bool{}
	data, err := os.ReadFile(path)
	if err != nil {
		return seen
	}
	_ = json.Unmarshal(data, &seen) // garbled file → empty set, notice shows
	return seen
}

// save persists the shown-notices set; errors are intentionally ignored.
func save(path string, seen map[string]bool) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return
	}
	if data, err := json.Marshal(seen); err == nil {
		_ = os.WriteFile(path, data, 0o600)
	}
}

// scratchPath is the per-session shown-notices file under the OS temp dir,
// separate from the vcs baseline and outcome dirs.
func scratchPath(sessionID string) string {
	return filepath.Join(os.TempDir(), "leoprevent-notices", sanitize(sessionID))
}

// cleanupStale best-effort removes shown-notices files older than a few hours
// (same TTL as the vcs/outcome sweeps) so dead sessions don't accumulate. A swept
// file only risks one duplicate notice — fail toward informing the developer.
func cleanupStale() {
	dir := filepath.Join(os.TempDir(), "leoprevent-notices")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-6 * time.Hour)
	for _, e := range entries {
		info, err := e.Info()
		if err == nil && info.ModTime().Before(cutoff) {
			_ = os.Remove(filepath.Join(dir, e.Name()))
		}
	}
}

// sanitize maps a session ID to a safe filename (same rule vcs/outcome use).
func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			return r
		default:
			return '_'
		}
	}, s)
}
