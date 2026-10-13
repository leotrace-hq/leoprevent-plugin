package outcome

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

func TestRememberTakeRoundTrip(t *testing.T) {
	session := sanitize(t.Name())
	t.Cleanup(func() { Clear(session) })

	p := Pending{
		ReviewID:   "abc123",
		Repo:       "github.com/acme/app",
		Developer:  "Ada <ada@acme.com>",
		AgentModel: "claude-opus-4-8",
		Findings:   []wire.Finding{{Rule: "ssrf", Location: "a.py:1", Preexisting: true}},
		Before:     []wire.ChangedFile{{Path: "a.py", AddedText: "requests.get(u)"}},
	}
	if err := Remember(session, p); err != nil {
		t.Fatalf("Remember: %v", err)
	}

	got, ok := Take(session)
	if !ok {
		t.Fatal("Take should find the pending record")
	}
	if got.ReviewID != "abc123" || got.Repo != "github.com/acme/app" || len(got.Findings) != 1 ||
		got.Findings[0].Rule != "ssrf" || !got.Findings[0].Preexisting || len(got.Before) != 1 {
		t.Errorf("round-trip mismatch: %+v", got)
	}

	// Take is one-shot: the record is deleted, so a second Take finds nothing.
	if _, ok := Take(session); ok {
		t.Error("Take must delete the record (one outcome per block)")
	}
}

func TestTakeMissingIsNotOk(t *testing.T) {
	if _, ok := Take(sanitize(t.Name() + "-never-written")); ok {
		t.Error("Take on a missing session must return ok=false")
	}
}

func TestEmptySessionIsNoop(t *testing.T) {
	if err := Remember("", Pending{ReviewID: "x"}); err != nil {
		t.Errorf("empty session Remember should no-op, got %v", err)
	}
	if _, ok := Take(""); ok {
		t.Error("empty session Take must be ok=false")
	}
}

func TestLedgerRoundTripAndShrink(t *testing.T) {
	session := sanitize(t.Name())
	t.Cleanup(func() { ClearLedger(session) })

	// Empty load → nil.
	if got := LoadLedger(session); got != nil {
		t.Fatalf("empty ledger should load nil, got %+v", got)
	}

	entries := []Pending{{
		ReviewID: "r1",
		Findings: []wire.Finding{{Rule: "idor-object-level-authz", Location: "main.py:44", Preexisting: true}},
		Before:   []wire.ChangedFile{{Path: "main.py", AddedText: "..."}},
	}}
	if err := SaveLedger(session, entries); err != nil {
		t.Fatalf("SaveLedger: %v", err)
	}
	// Non-consuming: two loads both return the entry.
	for i := 0; i < 2; i++ {
		got := LoadLedger(session)
		if len(got) != 1 || got[0].ReviewID != "r1" || len(got[0].Findings) != 1 {
			t.Fatalf("load %d mismatch: %+v", i, got)
		}
	}

	// An entry with no open findings is dropped; an empty set removes the file.
	if err := SaveLedger(session, []Pending{{ReviewID: "r1", Findings: nil}}); err != nil {
		t.Fatalf("SaveLedger shrink: %v", err)
	}
	if got := LoadLedger(session); got != nil {
		t.Errorf("ledger with no open findings should be empty, got %+v", got)
	}
}

func TestLedgerEmptySessionIsNoop(t *testing.T) {
	if err := SaveLedger("", []Pending{{ReviewID: "x", Findings: []wire.Finding{{Rule: "a"}}}}); err != nil {
		t.Errorf("empty session SaveLedger should no-op, got %v", err)
	}
	if got := LoadLedger(""); got != nil {
		t.Error("empty session LoadLedger must be nil")
	}
}

// The whole point of the marker is that "we asked and never heard back" stops looking
// like "we never asked". These cover the three states that distinction rests on.

func TestInFlightSurvivesWhenTheReplyNeverArrives(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	const sid = "sess-lost"
	if err := MarkInFlight(sid, InFlight{Repo: "acme/api", ChangedFiles: 3}); err != nil {
		t.Fatalf("MarkInFlight: %v", err)
	}
	// No ClearInFlight, this is the turn dying mid-call.
	m, ok := TakeInFlight(sid)
	if !ok {
		t.Fatal("marker lost: a review posted but never answered must still be findable")
	}
	if m.Repo != "acme/api" || m.ChangedFiles != 3 {
		t.Fatalf("marker did not round-trip: %+v", m)
	}
	if m.At.IsZero() {
		t.Error("At should default to now so the loss can be dated")
	}
	if _, again := TakeInFlight(sid); again {
		t.Error("marker must be consumed on read, or one lost review is reported forever")
	}
}

func TestInFlightClearedOnceTheReviewReturns(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	const sid = "sess-ok"
	if err := MarkInFlight(sid, InFlight{Repo: "acme/api"}); err != nil {
		t.Fatalf("MarkInFlight: %v", err)
	}
	ClearInFlight(sid)
	if _, ok := TakeInFlight(sid); ok {
		t.Fatal("a review that came back must leave no marker, otherwise every normal turn reports a loss")
	}
}

func TestInFlightIsSeparateFromPending(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	const sid = "sess-both"
	if err := MarkInFlight(sid, InFlight{Repo: "acme/api"}); err != nil {
		t.Fatalf("MarkInFlight: %v", err)
	}
	if err := Remember(sid, Pending{ReviewID: "rev-1"}); err != nil {
		t.Fatalf("Remember: %v", err)
	}
	// Taking the pending record must not consume the marker, and vice versa: they
	// answer different questions and are written at different points in the turn.
	if p, ok := Take(sid); !ok || p.ReviewID != "rev-1" {
		t.Fatalf("pending record clobbered by the marker: %+v ok=%v", p, ok)
	}
	if _, ok := TakeInFlight(sid); !ok {
		t.Error("marker clobbered by the pending record")
	}
}

func TestInFlightEmptySessionIsANoOp(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	if err := MarkInFlight("", InFlight{Repo: "acme/api"}); err != nil {
		t.Fatalf("empty session must not error: %v", err)
	}
	if _, ok := TakeInFlight(""); ok {
		t.Error("empty session must never produce a marker")
	}
	ClearInFlight("") // must not panic
}

// Two Stop hooks for one session can run at once. Take must hand the record to
// exactly one of them, however many race: a Load-then-Remove would let several read
// it before any deletes it, and each would ship the same outcome.
func TestConcurrentTakeHasExactlyOneWinner(t *testing.T) {
	session := sanitize(t.Name())
	t.Cleanup(func() { Clear(session) })

	const racers = 16
	for round := 0; round < 50; round++ {
		if err := Remember(session, Pending{ReviewID: "race"}); err != nil {
			t.Fatalf("Remember: %v", err)
		}
		start := make(chan struct{})
		var wg sync.WaitGroup
		var wins atomic.Int32
		for i := 0; i < racers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				if p, ok := Take(session); ok && p.ReviewID == "race" {
					wins.Add(1)
				}
			}()
		}
		close(start)
		wg.Wait()
		if got := wins.Load(); got != 1 {
			t.Fatalf("round %d: %d Takes succeeded, want exactly 1", round, got)
		}
		if _, ok := Load(session); ok {
			t.Fatalf("round %d: record survived a successful Take", round)
		}
	}
}

// A record that does not match is put back untouched, not consumed: TakeIf is how a
// caller claims only the state it can act on without destroying the rest.
func TestTakeIfMismatchPutsTheRecordBack(t *testing.T) {
	session := sanitize(t.Name())
	t.Cleanup(func() { Clear(session) })

	if err := Remember(session, Pending{ReviewID: "keep"}); err != nil {
		t.Fatalf("Remember: %v", err)
	}
	if _, ok := TakeIf(session, func(p Pending) bool { return p.Recovery != nil }); ok {
		t.Fatal("TakeIf must refuse a record that does not match")
	}
	got, ok := Take(session)
	if !ok || got.ReviewID != "keep" {
		t.Fatalf("mismatched record must be put back, got %+v ok=%v", got, ok)
	}
}

// PutBack returns a record a caller held, but a newer record written meanwhile wins.
func TestPutBackNeverClobbersANewerRecord(t *testing.T) {
	session := sanitize(t.Name())
	t.Cleanup(func() { Clear(session) })

	if err := Remember(session, Pending{ReviewID: "newer"}); err != nil {
		t.Fatalf("Remember: %v", err)
	}
	if err := PutBack(session, Pending{ReviewID: "older"}); err != nil {
		t.Fatalf("PutBack: %v", err)
	}
	if got, _ := Load(session); got.ReviewID != "newer" {
		t.Fatalf("PutBack overwrote a newer record: %+v", got)
	}

	Clear(session)
	if err := PutBack(session, Pending{ReviewID: "returned"}); err != nil {
		t.Fatalf("PutBack: %v", err)
	}
	if got, ok := Load(session); !ok || got.ReviewID != "returned" {
		t.Fatalf("PutBack into an empty slot must persist, got %+v ok=%v", got, ok)
	}
}
