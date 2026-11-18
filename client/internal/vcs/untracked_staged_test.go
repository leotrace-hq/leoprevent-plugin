package vcs

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
)

func stageAfterBaseline(t *testing.T,
	before string,
	after string) ([]transcript.Change, bool) {
	t.Helper()
	dir, session := initRepo(t)
	path := filepath.Join(dir, "scratch.py")
	if before != "" {
		if err := os.WriteFile(path, []byte(before), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := CaptureBaseline(dir, session); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(after), 0o644); err != nil {
		t.Fatal(err)
	}
	mustGit(t, dir, "add", "scratch.py")
	got, ok, _, err := ChangedFiles(dir, session)
	if err != nil || !ok {
		t.Fatalf("ChangedFiles ok=%v err=%v", ok, err)
	}
	for _, c := range got {
		if c.FilePath == "scratch.py" {
			return got, true
		}
	}
	return got, false
}

func scratchChange(t *testing.T,
	got []transcript.Change) transcript.Change {
	t.Helper()
	for _, c := range got {
		if c.FilePath == "scratch.py" {
			return c
		}
	}
	t.Fatal("scratch.py was not reported")
	return transcript.Change{}
}

func TestStagingAnUnchangedPreexistingUntrackedFileIsNotReviewedAgain(t *testing.T) {
	// Arrange
	content := preexistingUntracked

	// Act
	got, reported := stageAfterBaseline(t, content, content)

	// Assert
	if reported {
		t.Errorf("a file untracked at turn start and only staged this turn was re-sent as new: %+v", got)
	}
}

func TestStagingAnEditedPreexistingUntrackedFileAddsOnlyTheEditedLine(t *testing.T) {
	// Arrange
	after := preexistingUntracked + "    return eval(cmd)\n"

	// Act
	got, _ := stageAfterBaseline(t, preexistingUntracked, after)
	c := scratchChange(t, got)

	// Assert
	if !reflect.DeepEqual(c.AddedLines, []int{5}) {
		t.Errorf("AddedLines = %v, want [5]: staging must not turn lines already there at turn start into this turn's work", c.AddedLines)
	}
	if c.BaseBlobSHA == "" {
		t.Error("BaseBlobSHA is empty, want the turn-start content's blob")
	}
}

func TestStagingAFileCreatedThisTurnIsReviewedWhole(t *testing.T) {
	// Arrange
	after := preexistingUntracked

	// Act
	got, _ := stageAfterBaseline(t, "", after)
	c := scratchChange(t, got)

	// Assert
	if !reflect.DeepEqual(c.AddedLines, []int{1, 2, 3, 4}) {
		t.Errorf("AddedLines = %v, want every line of a file created this turn", c.AddedLines)
	}
}
