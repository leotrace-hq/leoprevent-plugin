package engine

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/agent"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/enroll"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/review"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

// noticeAgent is the smallest agent that lets notifyReviewSkipped run to completion. Only
// DeliverNotice is reached; the rest exist to satisfy the interface.
type noticeAgent struct{}

func (noticeAgent) Name() string                                          { return "test" }
func (noticeAgent) Environment(agent.Event) agent.Environment             { return agent.Environment{} }
func (noticeAgent) ParseEvent([]byte) (agent.Event, error)                { return agent.Event{}, nil }
func (noticeAgent) ChangedFiles(agent.Event) ([]transcript.Change, error) { return nil, nil }
func (noticeAgent) TurnMeta(agent.Event) (agent.TurnMeta, error)          { return agent.TurnMeta{}, nil }
func (noticeAgent) AgentReply(agent.Event) (string, error)                { return "", nil }
func (noticeAgent) DeliverReview(string, string, int, []wire.Finding) ([]byte, error) {
	return nil, nil
}
func (noticeAgent) DeliverNotice(string) ([]byte, error)               { return []byte("{}"), nil }
func (noticeAgent) DeliverPromptNotice(string, string) ([]byte, error) { return []byte("{}"), nil }

// withKey gives MarkStaleKey a credential to mark, as enroll.Ensure does in production.
//
// ⚠️ IT NO LONGER WRITES A LICENSE FILE, AND THAT IS THE POINT. MarkStaleKey used to resolve the
// key itself out of the per-user license.json, so a test that did not redirect the config dir
// marked the DEVELOPER'S REAL key and wrote into their real scratch — arming a spurious
// re-enrolment that rotated a working credential. This helper guarded against that by
// redirecting, and the sibling test in this same package did not, so it happened: measured live
// on 2026-08-25, half the turns on this machine lost their review.
//
// A convention that has to be remembered at every call site is not a boundary. MarkStaleKey now
// marks only what Ensure recorded, so a binary that never calls Ensure has nothing to mark and
// cannot reach real state at all — whether or not it remembered to isolate.
func withKey(t *testing.T, key string) {
	t.Helper()
	t.Cleanup(enroll.SetActiveKeyForTest(key))
}

// isolateTempDir redirects os.TempDir for one test, so the markers these tests count are
// only ever their own.
//
// ⚠️ TMPDIR ALONE IS POSIX-ONLY: os.TempDir reads TMPDIR on Unix but TMP, then TEMP, on
// Windows, where these tests were therefore counting markers in the machine's REAL scratch
// dir — shared with the enroll package's tests, which `go test ./...` runs at the same time.
// They pass there today by luck: markerCount is an exact assertion, so a marker written by
// another package is a failure in this one. Set all three; the variable that is ignored on a
// platform costs nothing.
func isolateTempDir(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	for _, key := range []string{"TMPDIR", "TMP", "TEMP"} {
		t.Setenv(key, dir)
	}
}

// markerCount counts the stale-key markers on disk.
func markerCount(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(os.TempDir(), "leoprevent-stale-keys"))
	if err != nil {
		return 0
	}
	return len(entries)
}

// TestOnlyAnUnauthorizedSkipMarksTheKeyStale is the guard that stops a transient fault from
// throwing away a working credential.
//
// A rejected key must be recorded so the next turn can re-mint (see enroll/stale.go). But a
// timeout, an unreachable server and a 5xx say nothing whatsoever about whether the key is
// valid, and treating them the same way would mean a brief Atlas blip or a slow judge causes
// every machine in a fleet to rotate its credential, invalidating each developer's other
// machines over an outage that fixed itself.
//
// Written because a mutation that recovered on EVERY skip reason passed the whole suite.
func TestOnlyAnUnauthorizedSkipMarksTheKeyStale(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ev := agent.Event{SessionID: "sess-stale"}

	for _, reason := range []review.SkipReason{
		review.SkipUnreachable,
		review.SkipServerError,
		review.SkipTimedOut,
		review.SkipMisconfigured,
	} {
		isolateTempDir(t)
		withKey(t, "lp_live_forthistest")
		notifyReviewSkipped(noticeAgent{}, ev, &review.SkipError{Reason: reason}, log, io.Discard)
		if n := markerCount(t); n != 0 {
			t.Errorf("%s marked the key stale (%d markers); only an unauthorized reply may", reason, n)
		}
	}

	// And the one that must: a refused credential.
	isolateTempDir(t)
	withKey(t, "lp_live_forthistest")
	notifyReviewSkipped(noticeAgent{}, ev, &review.SkipError{Reason: review.SkipUnauthorized}, log, io.Discard)
	if markerCount(t) != 1 {
		t.Error("an unauthorized reply did not mark the key stale, so the machine can never recover")
	}
}

// TestTheMarkSurvivesTheNoticeThrottle. The notice is shown once per session per reason, but the
// FACT of a refusal has to be recorded every time: the recovery reads the marker on a later turn,
// and if the record were suppressed alongside the notice a machine would stay stuck forever.
func TestTheMarkSurvivesTheNoticeThrottle(t *testing.T) {
	isolateTempDir(t)
	withKey(t, "lp_live_forthistest")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ev := agent.Event{SessionID: "sess-throttle"}

	// First call shows the notice and marks.
	notifyReviewSkipped(noticeAgent{}, ev, &review.SkipError{Reason: review.SkipUnauthorized}, log, io.Discard)
	// Clear the marker as a successful re-enrolment would, then fail again in the same session:
	// the notice is now throttled, but the mark must still be written.
	_ = os.RemoveAll(filepath.Join(os.TempDir(), "leoprevent-stale-keys"))

	notifyReviewSkipped(noticeAgent{}, ev, &review.SkipError{Reason: review.SkipUnauthorized}, log, io.Discard)
	if markerCount(t) != 1 {
		t.Error("the mark was suppressed along with the throttled notice; recovery would never fire again")
	}
}

// TestAnUnauthorizedSkipWithNoActiveKeyMarksNothing pins the property that made this safe.
//
// The damage was done by a test in this very package (TestReviewSkipEmitsNonBlockingNoticeAndThrottles)
// which drives the unauthorized path and isolates neither the temp dir nor the per-user config.
// It did not need fixing: no active key is recorded unless enroll.Ensure ran, and no test runs
// Ensure, so there is nothing to resolve and nothing to write.
//
// Deliberately asserted WITHOUT withKey and WITHOUT isolateTempDir, i.e. under exactly the
// conditions that caused the incident. If MarkStaleKey ever learns to resolve a credential on its
// own again, this fails — and it fails here rather than on somebody's laptop a week later.
func TestAnUnauthorizedSkipWithNoActiveKeyMarksNothing(t *testing.T) {
	t.Cleanup(enroll.SetActiveKeyForTest("")) // as a fresh process starts: nothing recorded

	before := markerCount(t)
	notifyReviewSkipped(noticeAgent{}, agent.Event{SessionID: "sess-no-active-key"},
		&review.SkipError{Reason: review.SkipUnauthorized},
		slog.New(slog.NewTextHandler(io.Discard, nil)), io.Discard)

	if after := markerCount(t); after != before {
		t.Errorf("markers %d → %d: the unauthorized path reached real state with no key recorded, "+
			"so running the suite marks the developer's own credential rejected", before, after)
	}
}
