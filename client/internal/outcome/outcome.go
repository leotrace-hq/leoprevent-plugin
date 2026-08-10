// Package outcome persists the "pending outcome" of a triggered review across the
// two Stop-hook invocations of a single turn.
//
// The hook runs as a fresh process each time, so state is kept in a per-session
// scratch file (the same pattern vcs uses for the git baseline):
//
//   - At the FIRST Stop, when leoprevent blocks and re-wakes the agent, Remember
//     stashes the review_id, the findings, and the "before" (vulnerable) code.
//   - At the SECOND Stop (after the agent has maybe fixed it), Take loads-and-
//     deletes that record so the cloud reviewer can ship the agent's fix to
//     /outcome for a synchronous, bounded re-judge (the dev is warned in-turn if
//     the introduced fix is still vulnerable).
//
// Best-effort throughout: a missing/garbled scratch file just means no outcome is
// reported — never a broken hook.
package outcome

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

// ErrUnscored reports that the server ACCEPTED an /outcome post but produced NO
// re-judge verdict (wire.OutcomeResponse.Scored=false): the 202 capacity skip, a
// server without a model, rules missing from the corpus, or a re-judge failure —
// and, conservatively, an old server that predates the flag. The response's empty
// still-firing lists then mean "not judged", never "everything resolved", so callers
// must not warn the developer, credit fixes, or touch the cross-turn ledger.
// Returned (wrapped) by apiclient.Outcome; check with errors.Is.
var ErrUnscored = errors.New("outcome accepted but not scored (no re-judge verdict)")

// Pending is what we must remember from the FIRST Stop to score the outcome at the
// SECOND Stop. Before is the vulnerable code we sent to /review; the attribution
// fields ride along so the outcome event is self-contained.
type Pending struct {
	ReviewID   string             `json:"review_id"`
	Repo       string             `json:"repo,omitempty"`
	Developer  string             `json:"developer,omitempty"`
	AgentModel string             `json:"agent_model,omitempty"`
	Findings   []wire.Finding     `json:"findings,omitempty"`
	Before     []wire.ChangedFile `json:"before,omitempty"`
	// ReviewBlockMs is how long the FIRST Stop hook blocked the agent (changed-file
	// detection + the /review wait) before it re-woke. The final Stop subtracts it from
	// the full-turn wall-clock so the recorded agent latency excludes the time the agent
	// sat idle waiting on LeoPrevent — keeping blocked turns on the same agent-only
	// baseline as clean turns (which never block).
	ReviewBlockMs int64 `json:"review_block_ms,omitempty"`
}

// Remember persists p for sessionID. Overwrites any prior pending for the session
// (only the most recent triggered review matters). Errors are returned for logging
// only — the caller proceeds regardless.
func Remember(sessionID string, p Pending) error {
	cleanupStale()
	if sessionID == "" {
		return nil
	}
	path := scratchPath(sessionID)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// Take loads the pending outcome for sessionID and DELETES the scratch file (so an
// outcome is reported at most once). ok=false when there is nothing pending (the
// common case: the prior turn was clean, so it never blocked).
func Take(sessionID string) (Pending, bool) {
	cleanupStale()
	if sessionID == "" {
		return Pending{}, false
	}
	path := scratchPath(sessionID)
	data, err := os.ReadFile(path)
	if err != nil {
		return Pending{}, false
	}
	_ = os.Remove(path)
	var p Pending
	if err := json.Unmarshal(data, &p); err != nil || p.ReviewID == "" {
		return Pending{}, false
	}
	return p, true
}

// Clear removes a session's pending record (used by tests).
func Clear(sessionID string) { _ = os.Remove(scratchPath(sessionID)) }

// ── Cross-turn pre-existing ledger ───────────────────────────────────────────
//
// A block surfaces pre-existing findings the re-wake does NOT force-fix; the dev
// often fixes them a turn or two later (e.g. "yes, fix those too"). That later fix
// lands on a SEPARATE /review (clean), so the original outcome — sealed when the
// blocked turn yielded — never sees it and the dashboards undercount pre-existing
// fixes. The ledger carries the still-open pre-existing findings forward across
// Stops (each entry = one origin review_id + its open findings + the before-code),
// so a later turn touching those files can re-judge JUST those rules and credit any
// now resolved. Unlike Pending, the ledger is NOT consumed on read — it persists
// (and shrinks) until every carried finding clears. Same per-session scratch + TTL.

// LoadLedger returns the open cross-turn entries for sessionID (nil when none).
// Non-consuming: the caller saves the updated set back via SaveLedger.
func LoadLedger(sessionID string) []Pending {
	cleanupStale()
	if sessionID == "" {
		return nil
	}
	data, err := os.ReadFile(ledgerPath(sessionID))
	if err != nil {
		return nil
	}
	var entries []Pending
	if json.Unmarshal(data, &entries) != nil {
		return nil
	}
	return entries
}

// SaveLedger persists the cross-turn entries for sessionID, dropping any with no
// open findings. An empty/nil set removes the file (nothing left to track). Errors
// are returned for logging only — the caller proceeds regardless.
func SaveLedger(sessionID string, entries []Pending) error {
	if sessionID == "" {
		return nil
	}
	kept := entries[:0]
	for _, e := range entries {
		if e.ReviewID != "" && len(e.Findings) > 0 {
			kept = append(kept, e)
		}
	}
	path := ledgerPath(sessionID)
	if len(kept) == 0 {
		_ = os.Remove(path)
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(kept)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// ClearLedger removes a session's ledger (used by tests).
func ClearLedger(sessionID string) { _ = os.Remove(ledgerPath(sessionID)) }

// ledgerPath is the per-session cross-turn ledger file, a sibling of the pending dir.
func ledgerPath(sessionID string) string {
	return filepath.Join(os.TempDir(), "leoprevent-ledger", sanitize(sessionID))
}

// scratchPath is the per-session pending file under the OS temp dir, separate from
// the vcs baseline dir.
func scratchPath(sessionID string) string {
	return filepath.Join(os.TempDir(), "leoprevent-outcomes", sanitize(sessionID))
}

// cleanupStale best-effort removes pending files older than a few hours (same TTL
// as vcs's baseline sweep) so an abandoned session — blocked, then interrupted
// before its second Stop — doesn't leave the "before" code sitting in the temp dir
// indefinitely. A swept record just means that one outcome goes unreported.
func cleanupStale() {
	for _, dir := range []string{
		filepath.Join(os.TempDir(), "leoprevent-outcomes"),
		filepath.Join(os.TempDir(), "leoprevent-ledger"),
	} {
		sweepStale(dir)
	}
}

// sweepStale removes files older than the TTL in one scratch dir (best-effort).
func sweepStale(dir string) {
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

// sanitize maps a session ID to a safe filename (same rule vcs uses).
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
