package vcs

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func withHashCap(t *testing.T,
	n int) {
	t.Helper()
	prev := maxUntrackedHashed
	maxUntrackedHashed = n
	t.Cleanup(func() { maxUntrackedHashed = prev })
}

func writeAged(t *testing.T,
	path string,
	body string,
	age time.Duration) time.Time {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	mt := time.Now().Add(-age)
	if err := os.Chtimes(path, mt, mt); err != nil {
		t.Fatal(err)
	}
	return mt
}

func changedSet(t *testing.T,
	dir string,
	session string) map[string]bool {
	t.Helper()
	got, ok, _, err := ChangedFiles(dir, session)
	if err != nil || !ok {
		t.Fatalf("ChangedFiles ok=%v err=%v", ok, err)
	}
	set := map[string]bool{}
	for _, c := range got {
		set[c.FilePath] = true
	}
	return set
}

func TestPreexistingUntrackedPastHashCapNotReviewed(t *testing.T) {
	// Arrange
	withHashCap(t, 2)
	dir, session := initRepo(t)
	for i := 0; i < 50; i++ {
		writeAged(t, filepath.Join(dir, "data", "pg", fmt.Sprintf("f%02d", i)), "", time.Hour)
	}
	if err := CaptureBaseline(dir, session); err != nil {
		t.Fatal(err)
	}

	// Act
	got := changedSet(t, dir, session)

	// Assert
	for p := range got {
		t.Errorf("pre-existing untracked file past the hash cap was reviewed: %s", p)
	}
}

func TestNewUntrackedFileReviewedWhenSnapshotOverflows(t *testing.T) {
	// Arrange
	withHashCap(t, 2)
	dir, session := initRepo(t)
	for i := 0; i < 10; i++ {
		writeAged(t, filepath.Join(dir, "data", fmt.Sprintf("f%02d", i)), "", time.Hour)
	}
	if err := CaptureBaseline(dir, session); err != nil {
		t.Fatal(err)
	}

	// Act
	if err := os.WriteFile(filepath.Join(dir, "zz_new.py"), []byte("y = eval(z)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := changedSet(t, dir, session)

	// Assert
	if !got["zz_new.py"] {
		t.Error("a file created this turn must be reviewed even when the snapshot is past the hash cap")
	}
	if len(got) != 1 {
		t.Errorf("only the new file should be reviewed, got %v", got)
	}
}

func TestEditedUntrackedFilePastHashCapReviewed(t *testing.T) {
	// Arrange
	withHashCap(t, 1)
	dir, session := initRepo(t)
	writeAged(t, filepath.Join(dir, "a.py"), "x = 1\n", time.Hour)
	writeAged(t, filepath.Join(dir, "b.py"), "x = 1\n", time.Hour)
	mt := writeAged(t, filepath.Join(dir, "c.py"), "x = 1\n", time.Hour)
	if err := CaptureBaseline(dir, session); err != nil {
		t.Fatal(err)
	}

	// Act
	writeAged(t, filepath.Join(dir, "b.py"), "x = requests.get(url)\n", 0)
	if err := os.WriteFile(filepath.Join(dir, "c.py"), []byte("y = 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	later := mt.Add(time.Minute)
	if err := os.Chtimes(filepath.Join(dir, "c.py"), later, later); err != nil {
		t.Fatal(err)
	}
	got := changedSet(t, dir, session)

	// Assert
	if !got["b.py"] {
		t.Error("a stat-fingerprinted file whose size changed must be reviewed")
	}
	if !got["c.py"] {
		t.Error("a stat-fingerprinted file rewritten at the same size but a new mtime must be reviewed")
	}
	if got["a.py"] {
		t.Error("the untouched hashed file must not be reviewed")
	}
}

func TestRacyUntrackedFilePastHashCapIsHashed(t *testing.T) {
	// Arrange
	withHashCap(t, 1)
	dir, session := initRepo(t)
	writeAged(t, filepath.Join(dir, "a.py"), "x = 1\n", time.Hour)
	fresh := writeAged(t, filepath.Join(dir, "b.py"), "x = 1\n", 0)
	if err := CaptureBaseline(dir, session); err != nil {
		t.Fatal(err)
	}

	// Act
	if err := os.WriteFile(filepath.Join(dir, "b.py"), []byte("y = 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(filepath.Join(dir, "b.py"), fresh, fresh); err != nil {
		t.Fatal(err)
	}
	got := changedSet(t, dir, session)

	// Assert
	if !got["b.py"] {
		t.Error("a file modified within the racy window must be content-hashed, so a same-size same-mtime edit is still caught")
	}
}
