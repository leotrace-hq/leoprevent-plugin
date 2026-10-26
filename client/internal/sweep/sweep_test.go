package sweep

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/leotrace-hq/leoprevent-plugin/limits"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

func write(t *testing.T,
	root string,
	rel string,
	body string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestReadSendsOnlySafeTextInsideTheRepository(t *testing.T) {
	// Arrange
	root := t.TempDir()
	outside := t.TempDir()
	write(t, root, "src/app.py", "print(1)\n")
	write(t, root, ".env", "KEY=1\n")
	write(t, root, "bin.dat", "a\x00b")
	write(t, root, "huge.py", strings.Repeat("x", limits.MaxChangedFileBytes+1))
	write(t, outside, "secret.py", "x\n")
	if err := os.Symlink(filepath.Join(outside, "secret.py"), filepath.Join(root, "link.py")); err != nil {
		t.Skip("symlinks unavailable")
	}
	if err := os.Symlink(outside, filepath.Join(root, "linkdir")); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"src/app.py":        "",
		"/src/app.py":       "",
		".env":              SkipSecret,
		"bin.dat":           SkipBinary,
		"huge.py":           SkipTooLarge,
		"link.py":           SkipSymlink,
		"linkdir/secret.py": SkipSymlink,
		"../outside.py":     SkipUnsafePath,
		"gone.py":           SkipMissing,
	}

	for path, want := range cases {
		// Act
		content, skip := Read(root, path)

		// Assert
		if skip != want {
			t.Fatalf("%s: skip = %q, want %q", path, skip, want)
		}
		if want == "" && content != "print(1)\n" {
			t.Fatalf("%s: content = %q", path, content)
		}
		if want != "" && content != "" {
			t.Fatalf("%s: a skipped file must carry no content", path)
		}
	}
}

func TestBatchesRespectBytesFilesAndIssues(t *testing.T) {
	// Arrange
	files := []File{
		{Path: "a", Issues: 1, Content: "1234"},
		{Path: "b", Issues: 1, Content: "1234"},
		{Path: "c", Issues: 5, Content: "1"},
		{Path: "d", Issues: 1, Content: "1"},
		{Path: "e", Issues: 1, Content: "1"},
	}

	// Act
	got := Batches(files, 8, 3, 6)

	// Assert
	var shape []string
	for _, b := range got {
		var names []string
		for _, f := range b {
			names = append(names, f.Path)
		}
		shape = append(shape, strings.Join(names, ""))
	}
	if strings.Join(shape, "|") != "ab|cd|e" {
		t.Fatalf("batches = %v", shape)
	}
}

func TestBatchesKeepAnOversizedFileAlone(t *testing.T) {
	// Arrange
	files := []File{{Path: "a", Content: "1"}, {Path: "big", Content: "123456789"}, {Path: "b", Content: "1"}}

	// Act
	got := Batches(files, 4, 10, 10)

	// Assert
	if len(got) != 3 || got[1][0].Path != "big" {
		t.Fatalf("batches = %+v", got)
	}
}

func TestStateRoundTripsAndTakesABatchOnce(t *testing.T) {
	// Arrange
	defer SetUserConfigDirForTest(t.TempDir())()
	st := State{Repo: "github.com/acme/api", Pending: []Pending{
		{ReviewID: "r1", Findings: []wire.Finding{{Rule: "aikido-fp:x", Location: "a.py:1"}}},
		{ReviewID: "r2"},
	}}

	// Act
	if err := Save(st); err != nil {
		t.Fatal(err)
	}
	got, err := Load("github.com/acme/api")
	if err != nil {
		t.Fatal(err)
	}
	other, _ := Load("github.com/acme/web")
	p, ok := got.Take("r1")
	_, again := got.Take("r1")

	// Assert
	if !ok || again || p.Findings[0].Location != "a.py:1" || got.Repo != st.Repo || len(got.Pending) != 1 || len(other.Pending) != 0 {
		t.Fatalf("take = %+v %v %v, state = %+v", p, ok, again, got)
	}
}

func TestLoadWithNoSavedSweepIsEmpty(t *testing.T) {
	// Arrange
	defer SetUserConfigDirForTest(t.TempDir())()

	// Act
	st, err := Load("github.com/acme/api")

	// Assert
	if err != nil || len(st.Pending) != 0 {
		t.Fatalf("st = %+v err = %v", st, err)
	}
}

func TestDropExpiredKeepsRecentOpenFindings(t *testing.T) {
	// Arrange
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	st := State{Open: []Open{
		{ReviewID: "fresh", At: now.Add(-time.Hour), Findings: []wire.Finding{{Location: "a.py:1"}}},
		{ReviewID: "stale", At: now.Add(-OpenTTL - time.Hour), Findings: []wire.Finding{{Location: "a.py:1"}}},
		{ReviewID: "empty", At: now},
	}}

	// Act
	st.DropExpired(now)

	// Assert
	if len(st.Open) != 1 || st.Open[0].ReviewID != "fresh" {
		t.Fatalf("open = %+v", st.Open)
	}
}

func TestChangedSendsOnlyFilesThatDifferFromTheSweptCommit(t *testing.T) {
	// Arrange
	committed := map[string]string{"a.py": "old a", "b.py": "same b", "gone.py": "old gone"}
	current := map[string]string{"a.py": "new a", "b.py": "same b"}
	before := func(_, rev, path string) (string, bool) {
		v, ok := committed[path]
		return v, ok && rev == "abc"
	}
	read := func(_, path string) (string, string) {
		if v, ok := current[path]; ok {
			return v, ""
		}
		return "", SkipMissing
	}
	o := Open{ReviewID: "r1", Commit: "abc", Findings: []wire.Finding{
		{Rule: "x", Location: "a.py:3"}, {Rule: "y", Location: "a.py:9"}, {Rule: "x", Location: "b.py:1"}, {Rule: "x", Location: "gone.py:1"},
	}}

	// Act
	touched, untouched, b, a := Changed("/repo", o, before, read)

	// Assert
	if len(touched) != 2 || touched[0].Location != "a.py:3" || touched[1].Location != "a.py:9" {
		t.Fatalf("touched = %+v", touched)
	}
	if len(untouched) != 2 {
		t.Fatalf("an unchanged or deleted file is never sent for re-checking: %+v", untouched)
	}
	if len(b) != 1 || b[0].Path != "a.py" || b[0].FullContent != "old a" || len(a) != 1 || a[0].FullContent != "new a" {
		t.Fatalf("before = %+v after = %+v", b, a)
	}
}
