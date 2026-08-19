package engine

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/agent"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/config"
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

// withKey isolates the per-user config dir and puts a license key in it, so MarkStaleKey has a
// credential to mark. Without this the test would read the DEVELOPER'S REAL key and write a
// marker into their real scratch dir — which the first version of this test did, and which would
// have armed a spurious re-enrolment on this machine.
func withKey(t *testing.T, key string) {
	t.Helper()
	t.Cleanup(config.SetUserConfigDirForTest(t.TempDir()))
	if _, err := config.SaveLicense(key); err != nil {
		t.Fatalf("seed license: %v", err)
	}
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
