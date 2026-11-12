package vcs

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

func changeFor(t *testing.T,
	dir string,
	session string,
	rel string) transcript.Change {
	t.Helper()
	changes, ok, skip, err := ChangedFiles(dir, session)
	if err != nil || !ok {
		t.Fatalf("ChangedFiles: ok=%v skip=%q err=%v", ok, skip, err)
	}
	for _, c := range changes {
		if c.FilePath == rel {
			return c
		}
	}
	t.Fatalf("%s not among the changes %+v", rel, changes)
	return transcript.Change{}
}

func TestEditHunksDescribeTheEditBetweenBaseAndAfter(t *testing.T) {
	// Arrange
	diff := "diff --git a/f b/f\n--- a/f\n+++ b/f\n" +
		"@@ -2,3 +2,4 @@\n a\n-b\n+B\n+B2\n c\n" +
		"@@ -9,0 +11,2 @@\n+x\n+y\n" +
		"@@ -20,2 +22,0 @@\n-p\n-q\n"

	// Act
	got := editHunks(diff)

	// Assert
	want := []wire.Hunk{{3, 1, 3, 2}, {10, 0, 11, 2}, {20, 2, 23, 0}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("editHunks = %v, want %v", got, want)
	}
}

func TestEditHunksIsNilWithoutAHunk(t *testing.T) {
	// Arrange
	diff := "diff --git a/f b/f\nsimilarity index 100%\n"

	// Act
	got := editHunks(diff)

	// Assert
	if got != nil {
		t.Errorf("editHunks = %v, want nil", got)
	}
}

func TestNextTurnBaseIsTheBlobThePreviousTurnReviewed(t *testing.T) {
	// Arrange
	dir, session := initRepo(t)
	path := filepath.Join(dir, "app.py")
	if err := CaptureBaseline(dir, session); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("import os\nos.system(input())\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	first := changeFor(t, dir, session, "app.py")
	if err := CaptureBaseline(dir, session); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("import os\nimport sys\nos.system(input())\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Act
	second := changeFor(t, dir, session, "app.py")

	// Assert
	if first.BlobSHA == "" || second.BaseBlobSHA != first.BlobSHA {
		t.Errorf("second turn base %q, first turn blob %q", second.BaseBlobSHA, first.BlobSHA)
	}
	if want := []wire.Hunk{{2, 0, 2, 1}}; !reflect.DeepEqual(second.Hunks, want) {
		t.Errorf("hunks = %v, want %v", second.Hunks, want)
	}
}

func TestANewFileHasNoBase(t *testing.T) {
	// Arrange
	dir, session := initRepo(t)
	if err := CaptureBaseline(dir, session); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "new.py"), []byte("x = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Act
	got := changeFor(t, dir, session, "new.py")

	// Assert
	if got.BaseBlobSHA != "" || got.Hunks != nil {
		t.Errorf("new file base %q hunks %v, want none", got.BaseBlobSHA, got.Hunks)
	}
}
