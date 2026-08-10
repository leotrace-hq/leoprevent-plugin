package vcs

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
)

// TestAddedLineNumbers verifies new-file line numbers are parsed from hunk headers,
// advancing on context/added lines and NOT on removed lines — across multiple hunks.
func TestAddedLineNumbers(t *testing.T) {
	diff := `diff --git a/main.py b/main.py
--- a/main.py
+++ b/main.py
@@ -4,3 +4,6 @@ context
 def edit():
-    old = 1
+    a = 1
+    b = 2
     keep()
@@ -20,2 +23,3 @@ more
 tail()
+    c = 3
`
	// hunk1: new starts at 4. " def edit():"=4, "+ a=1"=5, "+ b=2"=6, " keep()"=7
	// hunk2: new starts at 23. " tail()"=23, "+ c=3"=24
	got := addedLineNumbers(diff)
	want := []int{5, 6, 24}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("addedLineNumbers = %v, want %v", got, want)
	}
}

// TestAddedLineNumbersNewFile: a brand-new file's diff hunk is "@@ -0,0 +1,N @@" —
// every line is added, numbered 1..N.
func TestAddedLineNumbersNewFile(t *testing.T) {
	diff := `diff --git a/new.py b/new.py
new file mode 100644
--- /dev/null
+++ b/new.py
@@ -0,0 +1,3 @@
+a = 1
+b = 2
+c = 3
`
	got := addedLineNumbers(diff)
	want := []int{1, 2, 3}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("addedLineNumbers(new-file diff) = %v, want %v", got, want)
	}
}

// TestAddedLineNumbersCountOmittedHunk: a single-line hunk omits the ",count"
// ("@@ -3 +4 @@", e.g. under -U0) — the parser must still read the start line.
func TestAddedLineNumbersCountOmittedHunk(t *testing.T) {
	diff := `diff --git a/f.py b/f.py
--- a/f.py
+++ b/f.py
@@ -3 +4 @@ def handler():
-old = 1
+new = 1
`
	got := addedLineNumbers(diff)
	want := []int{4}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("addedLineNumbers(count-omitted hunk) = %v, want %v", got, want)
	}
}

// TestAddedLineNumbersNoNewlineMarker: "\ No newline at end of file" lines must
// be ignored — they are diff metadata, not file lines, so they must not advance
// (or record) the new-file counter.
func TestAddedLineNumbersNoNewlineMarker(t *testing.T) {
	diff := `diff --git a/f.txt b/f.txt
--- a/f.txt
+++ b/f.txt
@@ -1,2 +1,3 @@
 line1
-line2
\ No newline at end of file
+line2
+line3
\ No newline at end of file
`
	// " line1"=1, "-line2" (no advance), marker ignored, "+line2"=2, "+line3"=3.
	got := addedLineNumbers(diff)
	want := []int{2, 3}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("addedLineNumbers(no-newline markers) = %v, want %v", got, want)
	}
}

// TestAddedLinesAlignWithAddedTextRealRepo pins the CROSS-FIELD CONTRACT the server
// relies on to number the diff extract: AddedText's line i is the file line at
// AddedLines[i]. addedLines and addedLineNumbers walk the same diff independently, so
// nothing but this test stops them drifting apart — and a drift is SILENT: the server
// would keep emitting numbers, just wrong ones, and the judge's cited locations would
// quietly stop matching the code. The server's length-mismatch guard only catches a
// COUNT difference, not an off-by-one or a reordering, which is exactly what a change
// to either walker would produce.
//
// Verified against a REAL git repo (not a hand-written diff) with several hunks and a
// pre-existing blank line, then checked against the true file content: every added
// line must appear at its claimed position in the after-image.
func TestAddedLinesAlignWithAddedTextRealRepo(t *testing.T) {
	dir, session := initRepo(t)
	// A base file with gaps, so the diff below produces MULTIPLE hunks — a single-hunk
	// file would pass even if hunk-header walking were broken.
	base := "import os\n" + // 1
		"\n" + // 2 (blank — the line the judge kept mis-citing in production)
		"def a():\n" + // 3
		"    pass\n" + // 4
		"\n" + // 5
		"def b():\n" + // 6
		"    pass\n" + // 7
		"\n" + // 8
		"def c():\n" + // 9
		"    pass\n" // 10
	if err := os.WriteFile(filepath.Join(dir, "m.py"), []byte(base), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("git", "-C", dir, "add", "m.py").CombinedOutput(); err != nil {
		t.Fatalf("git add: %v %s", err, out)
	}
	if out, err := exec.Command("git", "-C", dir, "commit", "-m", "base").CombinedOutput(); err != nil {
		t.Fatalf("git commit: %v %s", err, out)
	}
	if err := CaptureBaseline(dir, session); err != nil {
		t.Fatalf("CaptureBaseline: %v", err)
	}

	// Two separate insertions, far apart -> two hunks, second one shifted by the first.
	after := "import os\n" +
		"\n" +
		"def a():\n" +
		"    run(cmd)\n" + // inserted
		"    pass\n" +
		"\n" +
		"def b():\n" +
		"    pass\n" +
		"\n" +
		"def c():\n" +
		"\n" + // inserted BLANK line — must be paired, not silently dropped
		"    eval(z)\n" + // inserted
		"    pass\n"
	if err := os.WriteFile(filepath.Join(dir, "m.py"), []byte(after), 0o644); err != nil {
		t.Fatal(err)
	}

	got, ok, _, err := ChangedFiles(dir, session)
	if err != nil || !ok {
		t.Fatalf("ChangedFiles ok=%v err=%v", ok, err)
	}
	var ch *transcript.Change
	for i := range got {
		if strings.HasSuffix(got[i].FilePath, "m.py") {
			ch = &got[i]
		}
	}
	if ch == nil {
		t.Fatal("m.py not captured")
	}

	addedText := strings.Split(strings.TrimRight(ch.AddedText, "\n"), "\n")
	if len(addedText) != len(ch.AddedLines) {
		t.Fatalf("CONTRACT BROKEN: %d added text lines vs %d line numbers\ntext=%q\nnums=%v",
			len(addedText), len(ch.AddedLines), ch.AddedText, ch.AddedLines)
	}
	if len(ch.AddedLines) != 3 {
		t.Fatalf("expected 3 added lines (incl. the blank one), got %d: %v", len(ch.AddedLines), ch.AddedLines)
	}

	// The real check: each number must index the matching text in the AFTER file.
	full := strings.Split(strings.TrimRight(ch.FullContent, "\n"), "\n")
	for i, n := range ch.AddedLines {
		if n < 1 || n > len(full) {
			t.Errorf("added line %d: number %d out of range (file has %d lines)", i, n, len(full))
			continue
		}
		if full[n-1] != addedText[i] {
			t.Errorf("MISALIGNED at index %d: AddedLines says line %d = %q, but the file has %q",
				i, n, addedText[i], full[n-1])
		}
	}

	// And the numbers must be the ones a reader would expect from the two hunks —
	// pinning the values catches a uniform off-by-one that the self-consistent check
	// above could not (both sides would shift together only if FullContent shifted too).
	want := []int{4, 11, 12}
	for i := range want {
		if ch.AddedLines[i] != want[i] {
			t.Errorf("AddedLines = %v, want %v (line 4 = inserted run(cmd); 11 = inserted blank; 12 = eval)",
				ch.AddedLines, want)
			break
		}
	}
}
