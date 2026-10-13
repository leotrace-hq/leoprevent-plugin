// Package outcome persists the "pending outcome" of a triggered review across the
// two Stop-hook invocations of a single turn.
//
// The hook runs as a fresh process each time, so state is kept in a per-session
// scratch file (the same pattern vcs uses for the git baseline):
//
//   - At the FIRST Stop, when leoprevent blocks and re-wakes the agent, Remember
//     stashes the review_id, the findings, and the "before" (vulnerable) code.
//   - At the SECOND Stop (after the agent has maybe fixed it), Take atomically
//     claims-and-deletes that record so the cloud reviewer can ship the agent's fix to
//     /outcome for a synchronous, bounded re-judge (the dev is warned in-turn if
//     the introduced fix is still vulnerable).
//
// Best-effort throughout: a missing/garbled scratch file just means no outcome is
// reported — never a broken hook.
package outcome

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
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

type Source struct {
	Path     string `json:"path"`
	Root     string `json:"root"`
	Relative string `json:"relative"`
}

type Recovery struct {
	After []wire.ChangedFile `json:"after"`
}

// Pending is what we must remember from the FIRST Stop to score the outcome at the
// SECOND Stop. Before is the vulnerable code we sent to /review; the attribution
// fields ride along so the outcome event is self-contained.
type Pending struct {
	Sources      []Source           `json:"sources,omitempty"`
	OriginalMeta wire.TurnMeta      `json:"original_meta,omitempty"`
	Recovery     *Recovery          `json:"recovery,omitempty"`
	ReviewID     string             `json:"review_id"`
	Repo         string             `json:"repo,omitempty"`
	Developer    string             `json:"developer,omitempty"`
	AgentModel   string             `json:"agent_model,omitempty"`
	Findings     []wire.Finding     `json:"findings,omitempty"`
	Before       []wire.ChangedFile `json:"before,omitempty"`
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
	root, name, err := openScratch(sessionID, true)
	if err != nil {
		return err
	}
	defer root.Close()
	tmp, err := writeTemp(root, name, p)
	if err != nil {
		return err
	}
	// Rename, not WriteFile in place: a concurrent Take claims the record by renaming
	// it, and must never claim a half-written file it would then discard as garbled.
	if err := root.Rename(tmp, name); err != nil {
		_ = root.Remove(tmp)
		return err
	}
	return nil
}

// Take claims the pending outcome for sessionID and DELETES it (so an outcome is
// reported at most once). ok=false when there is nothing pending (the common case:
// the prior turn was clean, so it never blocked) or when a concurrent hook process
// claimed it first.
//
// The claim is a rename of the scratch file to a unique sibling path: of several
// processes racing on one session, exactly one rename succeeds, and only that
// process reads the record. A Load before Take is therefore only ever a hint.
func Take(sessionID string) (Pending, bool) {
	return TakeIf(sessionID, nil)
}

// TakeIf is Take for a caller that only wants the record in a certain state. The
// record is claimed atomically, then checked with want while no other process can
// see it: a match is consumed and returned; a mismatch is put back (unless a newer
// record was written in the meantime, which wins) and ok=false. want=nil takes any
// valid record. A garbled record is consumed and dropped either way.
func TakeIf(sessionID string, want func(Pending) bool) (Pending, bool) {
	cleanupStale()
	if sessionID == "" {
		return Pending{}, false
	}
	root, name, err := openScratch(sessionID, false)
	if err != nil {
		return Pending{}, false
	}
	defer root.Close()
	claimed := name + ".claimed-" + uniqueSuffix()
	if err := root.Rename(name, claimed); err != nil {
		return Pending{}, false
	}
	defer root.Remove(claimed)
	data, err := root.ReadFile(claimed)
	if err != nil {
		return Pending{}, false
	}
	var p Pending
	if err := json.Unmarshal(data, &p); err != nil || p.ReviewID == "" {
		return Pending{}, false
	}
	if want != nil && !want(p) {
		putBackFile(root, claimed, name)
		return Pending{}, false
	}
	return p, true
}

// PutBack persists p for sessionID like Remember, except that it never overwrites
// a record already there: a caller that took a record and is returning it (updated
// or not) must not clobber a newer one written while it held the claim. Errors are
// returned for logging only.
func PutBack(sessionID string, p Pending) error {
	if sessionID == "" {
		return nil
	}
	root, name, err := openScratch(sessionID, true)
	if err != nil {
		return err
	}
	defer root.Close()
	tmp, err := writeTemp(root, name, p)
	if err != nil {
		return err
	}
	defer root.Remove(tmp)
	putBackFile(root, tmp, name)
	return nil
}

// openScratch opens the pending-outcome dir as an os.Root and returns the record's
// file name within it. Every claim, write and read of a record goes through that
// root, so none of them can reach outside the dir whatever the session id holds
// (sanitize already maps it to one path component; the root enforces it). create
// makes the dir first, for writers.
func openScratch(sessionID string, create bool) (*os.Root, string, error) {
	path := scratchPath(sessionID)
	dir := filepath.Dir(path)
	if create {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, "", err
		}
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, "", err
	}
	return root, filepath.Base(path), nil
}

// putBackFile publishes src as dst in root unless dst already exists. A hard link is
// the no-clobber primitive (it fails with EEXIST); a filesystem without links falls
// back to a check-then-rename, which only reopens a window that is already tiny. The
// caller still owns (and removes) src.
func putBackFile(root *os.Root, src, dst string) {
	err := root.Link(src, dst)
	if err == nil || errors.Is(err, fs.ErrExist) {
		return
	}
	if _, statErr := root.Lstat(dst); errors.Is(statErr, fs.ErrNotExist) {
		_ = root.Rename(src, dst)
	}
}

// writeTemp marshals p into a fresh sibling of name in root and returns the
// sibling's name, for the caller to publish with a rename or link.
func writeTemp(root *os.Root, name string, p Pending) (string, error) {
	data, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	tmp := name + ".tmp-" + uniqueSuffix()
	if err := root.WriteFile(tmp, data, 0o600); err != nil {
		_ = root.Remove(tmp)
		return "", err
	}
	return tmp, nil
}

// uniqueSuffix names a per-call scratch sibling. Random so that two processes (or
// goroutines) never pick the same claimed/temp path; pid+time if the RNG fails.
func uniqueSuffix() string {
	if id := NewReviewID(); id != "" {
		return id
	}
	return fmt.Sprintf("%d-%d", os.Getpid(), time.Now().UnixNano())
}

// Load reads the pending outcome for sessionID WITHOUT consuming it. The answer can
// be stale the moment it returns (another hook process may take or replace the
// record), so it is only a cheap fast path; anything that acts on the record must
// claim it with Take or TakeIf.
func Load(
	sessionID string,
) (Pending, bool) {
	cleanupStale()
	if sessionID == "" {
		return Pending{}, false
	}
	root, name, err := openScratch(sessionID, false)
	if err != nil {
		return Pending{}, false
	}
	defer root.Close()
	data, err := root.ReadFile(name)
	if err != nil {
		return Pending{}, false
	}
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
		filepath.Join(os.TempDir(), "leoprevent-inflight"),
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

// ── In-flight review marker ──────────────────────────────────────────────────
//
// Remember runs only AFTER /review returns, so a turn killed while that call is in
// flight leaves NOTHING on disk, while the server has already judged the code and
// recorded its findings. The next Stop finds no pending record, ships no /outcome,
// and those findings sit in the dashboards' Unconfirmed bucket permanently: the
// server was told and we never came back.
//
// The damage is that this is INDISTINGUISHABLE from a turn that never asked at all.
// Both leave an empty scratch dir. MarkInFlight is written BEFORE the post, so the
// two cases become separable: a marker still present on a later Stop means we asked
// and never heard back, and names the review we lost.
//
// It is NOT the pending record and never becomes one, it carries no findings and no
// before-code, because at write time neither exists yet. Same per-session scratch +
// TTL as Pending and the ledger, and the same best-effort contract: a failed write
// costs the detection, never the review.

// InFlight is the marker written immediately before a /review post. ReviewID is
// unset: the server mints it and we are, by construction, recording the case where
// that reply never arrived. The fields are what is needed to report the loss later.
type InFlight struct {
	At time.Time `json:"at"`
	// ReviewID is the id proposed on the request (wire.ReviewRequest.ReviewID). It is what
	// makes the marker actionable rather than merely diagnostic: a lost reply can still be
	// named, so its findings can be re-judged later instead of stranded. Advisory, the
	// server validates it and the response is authoritative, but a turn that never got a
	// response has nothing better, and the server adopts a well-formed id.
	ReviewID     string `json:"review_id,omitempty"`
	Repo         string `json:"repo,omitempty"`
	Developer    string `json:"developer,omitempty"`
	AgentModel   string `json:"agent_model,omitempty"`
	ChangedFiles int    `json:"changed_files,omitempty"`
}

// MarkInFlight records that a /review is about to be posted for sessionID. Errors
// are returned for logging only, the caller proceeds regardless.
func MarkInFlight(sessionID string, m InFlight) error {
	cleanupStale()
	if sessionID == "" {
		return nil
	}
	if m.At.IsZero() {
		m.At = time.Now()
	}
	path := inFlightPath(sessionID)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// ClearInFlight removes the marker. Called once /review has returned, on ANY
// result, including an error: a request that came back, even as a failure, is one
// the client knows the fate of, and failOpen already accounts for it. Only a reply
// that never arrived should survive to the next Stop.
func ClearInFlight(sessionID string) {
	if sessionID == "" {
		return
	}
	_ = os.Remove(inFlightPath(sessionID))
}

// TakeInFlight loads-and-deletes a marker left by an earlier Stop. ok=true means a
// /review was posted for this session and its reply was never consumed, the turn
// died while waiting. Consumed on read so one lost review is reported once.
func TakeInFlight(sessionID string) (InFlight, bool) {
	if sessionID == "" {
		return InFlight{}, false
	}
	path := inFlightPath(sessionID)
	data, err := os.ReadFile(path)
	if err != nil {
		return InFlight{}, false
	}
	_ = os.Remove(path)
	var m InFlight
	if json.Unmarshal(data, &m) != nil {
		return InFlight{}, false
	}
	return m, true
}

// NewReviewID mints an id for the client to propose on a /review. Same shape as the
// server's own mintID (12 random bytes, hex), so nothing downstream can tell the two
// apart and the charset already satisfies the server's token rule. An empty return (the
// RNG failed) just means this review goes un-named and the server mints as before.
func NewReviewID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ""
	}
	return hex.EncodeToString(b[:])
}

// inFlightPath is the per-session in-flight marker, a sibling of the pending dir.
func inFlightPath(sessionID string) string {
	return filepath.Join(os.TempDir(), "leoprevent-inflight", sanitize(sessionID))
}
