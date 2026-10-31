package vcs

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/gate"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
)

const preexistingUntracked = "import os\n\ndef run(cmd):\n    os.system(cmd)\n"

func editPreexistingUntracked(t *testing.T,
	after string) transcript.Change {
	t.Helper()
	dir, session := initRepo(t)
	path := filepath.Join(dir, "scratch.py")
	if err := os.WriteFile(path, []byte(preexistingUntracked), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := CaptureBaseline(dir, session); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(after), 0o644); err != nil {
		t.Fatal(err)
	}
	got, ok, _, err := ChangedFiles(dir, session)
	if err != nil || !ok {
		t.Fatalf("ChangedFiles ok=%v err=%v", ok, err)
	}
	for _, c := range got {
		if c.FilePath == "scratch.py" {
			return c
		}
	}
	t.Fatal("the edited untracked file was not reported")
	return transcript.Change{}
}

func TestEditingAPreexistingUntrackedFileAddsOnlyTheEditedLine(t *testing.T) {
	// Arrange
	after := "import os\n\ndef run(cmd):\n    os.system(cmd)\n    return eval(cmd)\n"

	// Act
	c := editPreexistingUntracked(t, after)

	// Assert
	if !reflect.DeepEqual(c.AddedLines, []int{5}) {
		t.Errorf("AddedLines = %v, want [5]: lines that were already there at turn start are not this turn's work", c.AddedLines)
	}
	if c.AddedText != "    return eval(cmd)\n" {
		t.Errorf("AddedText = %q, want only the new line", c.AddedText)
	}
	if c.FullContent != after {
		t.Errorf("FullContent = %q, want the whole file as context", c.FullContent)
	}
}

func TestCommentOnlyEditToAPreexistingUntrackedFileIsInert(t *testing.T) {
	// Arrange
	after := "import os\n\n# runs a shell command\ndef run(cmd):\n    os.system(cmd)\n"

	// Act
	c := editPreexistingUntracked(t, after)
	reviewable := gate.Run([]transcript.Change{c})

	// Assert
	if !reflect.DeepEqual(c.AddedLines, []int{3}) {
		t.Errorf("AddedLines = %v, want [3]", c.AddedLines)
	}
	if len(reviewable) != 0 {
		t.Errorf("a comment-only edit must be inert, got %d reviewable change(s)", len(reviewable))
	}
}

func TestRemovedLinesOfAPreexistingUntrackedFileAreReported(t *testing.T) {
	// Arrange
	after := "import os\n\ndef run(cmd):\n    pass\n"

	// Act
	c := editPreexistingUntracked(t, after)

	// Assert
	if !strings.Contains(c.RemovedText, "os.system(cmd)") {
		t.Errorf("RemovedText = %q, want the replaced line", c.RemovedText)
	}
}

func TestUntrackedFileOverTheBlobBudgetFallsBackToWholeFile(t *testing.T) {
	// Arrange
	prev := maxUntrackedBlobTotal
	maxUntrackedBlobTotal = 1
	t.Cleanup(func() { maxUntrackedBlobTotal = prev })
	after := preexistingUntracked + "x = 1\n"

	// Act
	c := editPreexistingUntracked(t, after)

	// Assert
	if !reflect.DeepEqual(c.AddedLines, []int{1, 2, 3, 4, 5}) {
		t.Errorf("AddedLines = %v, want every line when no turn-start content was kept", c.AddedLines)
	}
}

func TestNewUntrackedFileStillCountsEveryLineAsAdded(t *testing.T) {
	// Arrange
	dir, session := initRepo(t)
	if err := CaptureBaseline(dir, session); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "new.py"), []byte("a = 1\nb = 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Act
	got, ok, _, err := ChangedFiles(dir, session)

	// Assert
	if err != nil || !ok {
		t.Fatalf("ChangedFiles ok=%v err=%v", ok, err)
	}
	if len(got) != 1 || !reflect.DeepEqual(got[0].AddedLines, []int{1, 2}) {
		t.Errorf("got %+v, want new.py with AddedLines [1 2]", got)
	}
}

func TestBlobHeaderParsesPathsWithSpaces(t *testing.T) {
	// Arrange
	data := []byte("abc123\n#blob deadbeef dir/my file.py\nh1\tdir/my file.py\n")

	// Act
	got := parseBaselines(data)

	// Assert
	if len(got) != 1 || got[0].blobs["dir/my file.py"] != "deadbeef" || got[0].untracked["dir/my file.py"] != "h1" {
		t.Errorf("parseBaselines = %+v", got)
	}
}

func TestUntrackedSecretFileContentIsNeverSnapshotted(t *testing.T) {
	// Arrange
	dir, _ := initRepo(t)
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("TOKEN=x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "scratch.py"), []byte("a = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Act
	got := snapshotUntrackedBlobs(dir)

	// Assert
	if strings.Contains(got, ".env") {
		t.Errorf("a secret file's content must not be written to the object store: %q", got)
	}
	if !strings.Contains(got, " scratch.py\n") {
		t.Errorf("an ordinary untracked file must still be snapshotted: %q", got)
	}
}
