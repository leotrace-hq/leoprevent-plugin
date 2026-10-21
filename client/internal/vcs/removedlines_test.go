package vcs

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
)

// TestRemovedLines pins the removed text and the anchor each removed line gets: the
// new-file line it sat above. A rewrite anchors on its replacement; a pure-deletion
// hunk ("+N,0") anchors on the line AFTER git's reported start, because git reports
// the line before an empty new side.
func TestRemovedLines(t *testing.T) {
	cases := []struct {
		name     string
		diff     string
		wantText string
		wantAt   []int
	}{
		{
			name: "rewrite anchors on the replacement line",
			diff: `--- a/a.ts
+++ b/a.ts
@@ -100,3 +100,3 @@ refresh()
     const user = await find(id);
-    if (!user || user.archivedAt) {
+    if (!user) {
       throw new Unauthorized();
`,
			wantText: "    if (!user || user.archivedAt) {\n",
			wantAt:   []int{101},
		},
		{
			name: "pure deletion mid-file sits above the next line",
			diff: `--- a/c.ts
+++ b/c.ts
@@ -4,2 +3,0 @@ class C {
-  @Throttle(5)
-  @UseGuards(Origin)
`,
			wantText: "  @Throttle(5)\n  @UseGuards(Origin)\n",
			wantAt:   []int{4, 4},
		},
		{
			name: "deletion at the top of the file",
			diff: `--- a/t.py
+++ b/t.py
@@ -1 +0,0 @@
-import guard
`,
			wantText: "import guard\n",
			wantAt:   []int{1},
		},
		{
			name: "two hunks, the second shifted by the first",
			diff: `--- a/m.py
+++ b/m.py
@@ -2,3 +2,2 @@ def a():
     x = 1
-    check(x)
     run(x)
@@ -10,2 +9,3 @@ def b():
     y = 2
+    z = 3
-    verify(y)
+    use(y)
`,
			wantText: "    check(x)\n    verify(y)\n",
			wantAt:   []int{3, 11},
		},
		{
			name:     "header lines are not removed lines",
			diff:     "--- a/f.go\n+++ b/f.go\n@@ -1,1 +1,1 @@\n-a\n+b\n",
			wantText: "a\n",
			wantAt:   []int{1},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			text, at := removedLines(tc.diff, 1<<20)
			if text != tc.wantText {
				t.Errorf("text = %q, want %q", text, tc.wantText)
			}
			if !reflect.DeepEqual(at, tc.wantAt) {
				t.Errorf("at = %v, want %v", at, tc.wantAt)
			}
		})
	}
}

// TestRemovedLinesCapKeepsPairing: over the byte cap, whole lines are dropped from the
// end so text and anchors stay index-aligned (the renderer pairs them by count).
func TestRemovedLinesCapKeepsPairing(t *testing.T) {
	diff := "--- a/f\n+++ b/f\n@@ -1,3 +0,0 @@\n-aaaa\n-bbbb\n-cccc\n"
	text, at := removedLines(diff, 12)
	if text != "aaaa\nbbbb\n" {
		t.Errorf("text = %q, want the first two whole lines", text)
	}
	if len(at) != 2 {
		t.Errorf("at = %v, want 2 anchors paired with 2 lines", at)
	}
}

// TestRemovedLinesRealRepo runs the git path end to end on the two shapes CodeTribe's
// replays had: a check REWRITTEN into a weaker one (the added line looks harmless on
// its own) and a guard DELETED outright (no added line at all). Before LEO-483 both
// reached the judge with the removed code nowhere in the payload.
func TestRemovedLinesRealRepo(t *testing.T) {
	dir, session := initRepo(t)
	base := "def refresh(user):\n" + // 1
		"    if not user or user.archived:\n" + // 2
		"        raise Unauthorized()\n" + // 3
		"    return issue(user)\n" + // 4
		"\n" + // 5
		"@throttle(5)\n" + // 6
		"def login(req):\n" + // 7
		"    return auth(req)\n" // 8
	if err := os.WriteFile(filepath.Join(dir, "auth.py"), []byte(base), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, dir, "add", "auth.py")
	gitRun(t, dir, "commit", "-q", "-m", "base")
	if err := CaptureBaseline(dir, session); err != nil {
		t.Fatalf("CaptureBaseline: %v", err)
	}

	after := "def refresh(user):\n" + // 1
		"    if not user:\n" + // 2 (rewritten: the archived check is gone)
		"        raise Unauthorized()\n" + // 3
		"    return issue(user)\n" + // 4
		"\n" + // 5
		"def login(req):\n" + // 6 (the @throttle above it was deleted)
		"    return auth(req)\n" // 7
	if err := os.WriteFile(filepath.Join(dir, "auth.py"), []byte(after), 0o644); err != nil {
		t.Fatal(err)
	}

	got, ok, _, err := ChangedFiles(dir, session)
	if err != nil || !ok {
		t.Fatalf("ChangedFiles ok=%v err=%v", ok, err)
	}
	var ch *transcript.Change
	for i := range got {
		if strings.HasSuffix(got[i].FilePath, "auth.py") {
			ch = &got[i]
		}
	}
	if ch == nil {
		t.Fatal("auth.py not captured")
	}
	if want := "    if not user or user.archived:\n@throttle(5)\n"; ch.RemovedText != want {
		t.Errorf("RemovedText = %q, want %q", ch.RemovedText, want)
	}
	// Each anchor must be a real line of the after-image: the replacement for the
	// rewrite (2), and the def the deleted decorator sat on (6).
	if want := []int{2, 6}; !reflect.DeepEqual(ch.RemovedAt, want) {
		t.Errorf("RemovedAt = %v, want %v", ch.RemovedAt, want)
	}
	if want := []int{2}; !reflect.DeepEqual(ch.AddedLines, want) {
		t.Errorf("AddedLines = %v, want %v (removed lines must not disturb added numbering)", ch.AddedLines, want)
	}
}

// TestPureDeletionCarriesEmptyAddedLines (LEO-501): a file the agent only deleted from
// has a git diff but no '+' line. Its AddedLines must be EMPTY and non-nil, and must cross
// the wire as [], because nil means "no positional basis" and the server then refuses to
// anchor a finding on the removal point. This is the C3 shape: @throttle deleted, nothing
// added.
func TestPureDeletionCarriesEmptyAddedLines(t *testing.T) {
	dir, session := initRepo(t)
	base := "@throttle(5)\n" + // 1
		"def login(req):\n" + // 2
		"    return auth(req)\n" // 3
	if err := os.WriteFile(filepath.Join(dir, "auth.py"), []byte(base), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, dir, "add", "auth.py")
	gitRun(t, dir, "commit", "-q", "-m", "base")
	if err := CaptureBaseline(dir, session); err != nil {
		t.Fatalf("CaptureBaseline: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "auth.py"), []byte("def login(req):\n    return auth(req)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, ok, _, err := ChangedFiles(dir, session)
	if err != nil || !ok || len(got) != 1 {
		t.Fatalf("ChangedFiles ok=%v err=%v files=%d", ok, err, len(got))
	}
	ch := got[0]
	if ch.AddedLines == nil || len(ch.AddedLines) != 0 {
		t.Fatalf("AddedLines = %#v, want an empty non-nil slice", ch.AddedLines)
	}
	if want := []int{1}; !reflect.DeepEqual(ch.RemovedAt, want) {
		t.Errorf("RemovedAt = %v, want %v", ch.RemovedAt, want)
	}
	if addedLineNumbers("") != nil {
		t.Error("no diff at all must stay nil: there is no positional basis")
	}
}

// TestRemovedLinesNotSentForNewFile: a brand-new (untracked) file has nothing removed.
func TestRemovedLinesNotSentForNewFile(t *testing.T) {
	dir, session := initRepo(t)
	if err := CaptureBaseline(dir, session); err != nil {
		t.Fatalf("CaptureBaseline: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "new.py"), []byte("x = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, _, _, err := ChangedFiles(dir, session)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range got {
		if c.RemovedText != "" || c.RemovedAt != nil {
			t.Errorf("%s: new file carries removed lines %q %v", c.FilePath, c.RemovedText, c.RemovedAt)
		}
	}
}

// TestDeletedFileCarriesFormerContent: a file the turn removed ENTIRELY is reviewed from
// its baseline content (LEO-483), but every refusal the on-disk path makes still holds: a
// secret path is never read, and a symlink is not file content.
func TestDeletedFileCarriesFormerContent(t *testing.T) {
	dir, session := initRepo(t)
	if err := os.MkdirAll(filepath.Join(dir, "mw"), 0o755); err != nil {
		t.Fatal(err)
	}
	guard := "export function csrfGuard(req) {\n  if (req.headers.origin !== APP_ORIGIN) throw new Forbidden();\n}\n"
	for name, body := range map[string]string{"mw/csrf.ts": guard, ".env": "API_KEY=sk-live-123\n"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("mw/csrf.ts", filepath.Join(dir, "link.ts")); err != nil {
		t.Fatal(err)
	}
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-q", "-m", "base")
	if err := CaptureBaseline(dir, session); err != nil {
		t.Fatalf("CaptureBaseline: %v", err)
	}
	for _, name := range []string{"mw/csrf.ts", ".env", "link.ts"} {
		if err := os.Remove(filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}

	got, ok, _, err := ChangedFiles(dir, session)
	if err != nil || !ok {
		t.Fatalf("ChangedFiles ok=%v err=%v", ok, err)
	}
	if len(got) != 1 {
		t.Fatalf("want only mw/csrf.ts (no secret, no symlink), got %d: %+v", len(got), got)
	}
	c := got[0]
	if c.FilePath != "mw/csrf.ts" || !c.Deleted || c.RemovedText != guard {
		t.Errorf("deleted file = %+v, want mw/csrf.ts Deleted with its former content", c)
	}
	if c.AddedText != "" || c.FullContent != "" || c.AddedLines != nil || c.RemovedAt != nil {
		t.Errorf("a deleted file has no after-image, no added lines and no anchors: %+v", c)
	}
}
