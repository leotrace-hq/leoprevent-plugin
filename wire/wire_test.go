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

// TestRemovedLinesWireContract pins the removed-lines tags (LEO-483) and that a client
// sending none adds nothing to the body: an older server ignores unknown fields, and an
// unchanged payload for files with no removals keeps request sizes where they were.
func TestRemovedLinesWireContract(t *testing.T) {
	b, err := json.Marshal(ChangedFile{Path: "a.py", RemovedText: "guard()\n", RemovedAt: []int{3}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tag := range []string{`"removed_text":"guard()\n"`, `"removed_at":[3]`} {
		if !strings.Contains(string(b), tag) {
			t.Errorf("wire JSON missing %s:\n%s", tag, b)
		}
	}
	b2, _ := json.Marshal(ChangedFile{Path: "a", AddedText: "x"})
	if strings.Contains(string(b2), "removed_") {
		t.Errorf("empty removed fields must be omitted from the wire: %s", b2)
	}
}

// TestAddedLinesKeepsEmptyDistinctFromAbsent (LEO-501): [] ("positionally known, nothing
// added": a pure deletion) and absent ("no positional basis") must survive a round trip as
// different values. omitempty on added_lines would collapse them, and the server would then
// never anchor a deleted guard on its removal point.
func TestAddedLinesKeepsEmptyDistinctFromAbsent(t *testing.T) {
	for _, tc := range []struct {
		in      []int
		wantNil bool
	}{{[]int{}, false}, {nil, true}, {[]int{4}, false}} {
		b, err := json.Marshal(ChangedFile{Path: "a", AddedLines: tc.in})
		if err != nil {
			t.Fatal(err)
		}
		var out ChangedFile
		if err := json.Unmarshal(b, &out); err != nil {
			t.Fatal(err)
		}
		if (out.AddedLines == nil) != tc.wantNil || len(out.AddedLines) != len(tc.in) {
			t.Errorf("AddedLines %#v round-tripped to %#v via %s", tc.in, out.AddedLines, b)
		}
	}
}

// TestFormatRemoved: one block per removal point, headed by the current line it sat
// above; unpaired anchors fall back to unanchored lines rather than invented ones.
func TestFormatRemoved(t *testing.T) {
	got := FormatRemoved("  a()\n  b()\n  c()\n", []int{4, 4, 9})
	want := "(removed just above current line 4)\n-  a()\n-  b()\n\n(removed just above current line 9)\n-  c()"
	if got != want {
		t.Errorf("paired:\n got %q\nwant %q", got, want)
	}
	if got := FormatRemoved("a()\nb()\n", []int{1}); got != "-a()\n-b()" {
		t.Errorf("unpaired must render without anchors, got %q", got)
	}
	if got := FormatRemoved(" \n", nil); got != "" {
		t.Errorf("nothing removed must render empty, got %q", got)
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

// The finding carries the judge's observed credential literals so the SERVER can strip them
// from outbound prose. Serialising them would hand the client the very values the redaction
// exists to withhold, so the absence of this field from the JSON is a security property, not
// a formatting detail.
func TestFindingNeverSerialisesSecretValues(t *testing.T) {
	b, err := json.Marshal(Finding{
		Rule: "hardcoded-secrets", Location: "a.ts:1",
		Issue: "a secret is hardcoded", SecretValues: []string{"hunter2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"hunter2", "SecretValues", "secret_values"} {
		if strings.Contains(string(b), bad) {
			t.Fatalf("%q reached the wire: %s", bad, b)
		}
	}
	// And it must not be settable FROM the wire either: a client cannot inject candidates.
	var f Finding
	if err := json.Unmarshal([]byte(`{"rule":"r","secret_values":["x"],"SecretValues":["y"]}`), &f); err != nil {
		t.Fatal(err)
	}
	if len(f.SecretValues) != 0 {
		t.Fatalf("client-supplied values were accepted: %v", f.SecretValues)
	}
}
