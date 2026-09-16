package outcome

import (
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
