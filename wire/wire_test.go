package wire

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestChangedFileWireContract locks the JSON tags both the client (apiclient) and
// server (api) marshal/unmarshal against. wire exists "so the two sides cannot
// drift" — a typo'd tag here would silently break the cloud contract with nothing
// else failing, so pin it.
func TestChangedFileWireContract(t *testing.T) {
	in := ReviewRequest{Changes: []ChangedFile{{Path: "a.py", AddedText: "x=1", FullContent: "x=1\n"}}}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, tag := range []string{`"path"`, `"added_text"`, `"full_content"`} {
		if !strings.Contains(string(b), tag) {
			t.Errorf("wire JSON missing expected tag %s:\n%s", tag, b)
		}
	}

	var out ReviewRequest
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	got := out.Changes[0]
	if got.Path != "a.py" || got.AddedText != "x=1" || got.FullContent != "x=1\n" {
		t.Errorf("round-trip mismatch: %+v", got)
	}

	// FullContent is omitempty (legacy snippet-only requests omit it).
	b2, _ := json.Marshal(ChangedFile{Path: "a", AddedText: "x"})
	if strings.Contains(string(b2), "full_content") {
		t.Errorf("empty FullContent must be omitted from the wire: %s", b2)
	}
}

// TestFindingWireContract pins the Finding JSON tags the server fills and the
// client reads — including the server-filled human `name` — so they can't drift.
func TestFindingWireContract(t *testing.T) {
	b, err := json.Marshal(Finding{Rule: "ssrf", Name: "Server-Side Request Forgery", Location: "a.py:1", Issue: "i", Fix: "f"})
	if err != nil {
		t.Fatal(err)
	}
	for _, tag := range []string{`"rule"`, `"name"`, `"location"`, `"issue"`, `"fix"`} {
		if !strings.Contains(string(b), tag) {
			t.Errorf("Finding JSON missing tag %s: %s", tag, b)
		}
	}
	var out Finding
	if err := json.Unmarshal(b, &out); err != nil || out.Name != "Server-Side Request Forgery" {
		t.Errorf("round-trip lost name: %+v err=%v", out, err)
	}
	// name is omitempty (the local tier / legacy responses omit it).
	if nb, _ := json.Marshal(Finding{Rule: "x", Location: "y"}); strings.Contains(string(nb), `"name"`) {
		t.Errorf("empty Name must be omitted: %s", nb)
	}
}
