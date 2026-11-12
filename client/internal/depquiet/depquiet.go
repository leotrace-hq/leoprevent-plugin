// Package depquiet keeps a developer's answers to the session scan's offer (LEO-673 follow-up,
// decided 23 Oct 2026), so a new session doesn't ask again about what they've just answered.
//
// The offer asks whether to fix the dependencies that were already there. Starting the session
// that fixes them, or saying "Not now", is an answer, and it quietens everything in that scan's
// notice for this developer: each package at its version, in its file, with the serious advisory
// IDs it had then. The scan sends that list back (wire.DependenciesRequest.Quiet) and the server
// leaves those packages out of the notice and the offer, so a new session shows a one-line
// reminder instead of the full list. A new advisory, a different version, or anything else new is
// raised again with an offer of its own.
//
// ⚠️ ONE TIMER PER REPOSITORY, NOT ONE PER PACKAGE. The first answer starts a 24-hour timer for
// the repository; anything answered while it runs joins it and goes quiet until the same time, so
// everything comes back together and is decided again in one offer.
//
// ⚠️ THE QUIET IS THIS DEVELOPER'S. It lives in the per-user scratch dir, on their machine. A
// colleague working on the same repository is told as before, and the server still checks and
// records every package. Server-side waivers for the whole account are a later milestone.
//
// ⚠️ BEST-EFFORT, FAILING TOWARD REPORTING. A store that can't be read or written means nothing
// is quiet, so the developer is told again: one repeat is better than a hidden issue.
package depquiet

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/scratch"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

// Window is how long an answer keeps the scan quiet. Only high, critical and malicious issues
// are reported, so a day, whatever the severity (decided 23 Oct 2026).
const Window = 24 * time.Hour

// Entry is one answered package: the dependency file it's in (its path as sent to the server),
// its name and version, and the IDs of the serious advisories it had when it was answered.
type Entry struct {
	Path       string   `json:"path"`
	Name       string   `json:"name"`
	Version    string   `json:"version"`
	Advisories []string `json:"advisories,omitempty"`
}

// Timer is a repository's quiet: until when, and what it covers. The zero Timer is no quiet.
type Timer struct {
	Until   time.Time `json:"until"`
	Entries []Entry   `json:"entries"`
}

// Active reports a timer still running at now.
func (t Timer) Active(now time.Time) bool { return now.Before(t.Until) }

// For is the timer's entries in one file, as the request's quiet list.
func (t Timer) For(path string) []wire.QuietDependency {
	var out []wire.QuietDependency
	for _, e := range t.Entries {
		if e.Path == path {
			out = append(out, wire.QuietDependency{Name: e.Name, Version: e.Version, Advisories: e.Advisories})
		}
	}
	return out
}

// Load is the repository's running timer, or the zero Timer when it has none, it has run out, or
// it can't be read.
func Load(repo string, now time.Time) Timer {
	if repo == "" {
		return Timer{}
	}
	var t Timer
	path := timerPath(repo)
	data, err := os.ReadFile(path)
	if err != nil {
		return Timer{}
	}
	if json.Unmarshal(data, &t) != nil || !t.Active(now) {
		_ = os.Remove(path) // run out, or unreadable: nothing is quiet either way
		return Timer{}
	}
	return t
}

// Answer records that the developer answered about entries: they join the repository's running
// timer, or start a new one of Window. An entry already held is replaced, so its advisories are
// the latest answered. It returns the timer as saved.
func Answer(repo string, entries []Entry, now time.Time) Timer {
	if repo == "" || len(entries) == 0 {
		return Load(repo, now)
	}
	t := Load(repo, now)
	if !t.Active(now) {
		t = Timer{Until: now.Add(Window)}
	}
	for _, e := range entries {
		e.Advisories = slices.Clone(e.Advisories)
		slices.Sort(e.Advisories)
		i := slices.IndexFunc(t.Entries, func(h Entry) bool { return h.Path == e.Path && h.Name == e.Name && h.Version == e.Version })
		if i >= 0 {
			t.Entries[i] = e
		} else {
			t.Entries = append(t.Entries, e)
		}
	}
	save(timerPath(repo), t)
	return t
}

// Pending is what one session's scan offered, kept until the developer answers it: the
// repository and the packages its notice listed.
type Pending struct {
	Repo    string  `json:"repo"`
	Entries []Entry `json:"entries"`
}

// SetPending keeps what a session's scan put in front of the developer, for TakePending.
func SetPending(sessionID string, p Pending) {
	if sessionID == "" || p.Repo == "" || len(p.Entries) == 0 {
		return
	}
	sweepPending()
	save(pendingPath(sessionID), p)
}

// sweepPending removes offers older than Window that were never answered (a plain question, a
// fix session never started, a session closed): past it, an answer couldn't quieten anything for
// longer anyway. Best-effort.
func sweepPending() {
	dir := scratch.Dir("dep-quiet-pending")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-Window)
	for _, e := range entries {
		if info, err := e.Info(); err == nil && info.ModTime().Before(cutoff) {
			_ = os.Remove(filepath.Join(dir, e.Name()))
		}
	}
}

// PeekPending reports whether a session has an offer waiting for an answer.
func PeekPending(sessionID string) bool {
	if sessionID == "" {
		return false
	}
	_, err := os.Stat(pendingPath(sessionID))
	return err == nil
}

// TakePending returns and removes a session's waiting offer.
func TakePending(sessionID string) (Pending, bool) {
	if sessionID == "" {
		return Pending{}, false
	}
	path := pendingPath(sessionID)
	data, err := os.ReadFile(path)
	if err != nil {
		return Pending{}, false
	}
	_ = os.Remove(path)
	var p Pending
	if json.Unmarshal(data, &p) != nil {
		return Pending{}, false
	}
	return p, true
}

// timerPath is a repository's timer file, named by a hash of the repository's identity: the
// identity can be a local path, which never belongs in a file name.
func timerPath(repo string) string {
	sum := sha256.Sum256([]byte(repo))
	return filepath.Join(scratch.Dir("dep-quiet"), hex.EncodeToString(sum[:16])+".json")
}

func pendingPath(sessionID string) string {
	return filepath.Join(scratch.Dir("dep-quiet-pending"), sanitize(sessionID)+".json")
}

func save(path string, v any) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return
	}
	if data, err := json.Marshal(v); err == nil {
		_ = os.WriteFile(path, data, 0o600)
	}
}

// sanitize maps a session ID to a safe file name (the rule notify, vcs and outcome use).
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
