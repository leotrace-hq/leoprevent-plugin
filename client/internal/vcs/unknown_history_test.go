package vcs

import (
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/scratch"
)

func TestUnobservedIncomingHistoryStaysReviewedWithoutAuthorshipClaims(t *testing.T) {
	for _, mode := range []string{"colleague-merge", "own-shell-worktree", "fast-forward", "later-edit", "later-rename", "uncommitted-rename"} {
		t.Run(mode, func(t *testing.T) {
			t.Cleanup(scratch.SetUserCacheDirForTest(t.TempDir()))
			dir, session := initRepo(t)
			other := filepath.Join(t.TempDir(), "other")
			gitRun(t, dir, "worktree", "add", "-q", "-b", "other", other)
			if err := CaptureBaseline(dir, session); err != nil {
				t.Fatal(err)
			}
			if mode != "fast-forward" {
				writeHistoryFixture(t, dir, "own.py", "own = 1\n")
				gitRun(t, dir, "add", "own.py")
				gitRun(t, dir, "commit", "-q", "-m", "observed own work")
				remote := filepath.Join(t.TempDir(), "remote.git")
				gitRun(t, dir, "init", "-q", "--bare", remote)
				gitRun(t, dir, "remote", "add", "origin", remote)
				gitRun(t, dir, "push", "-q", "origin", "HEAD:agent")
			}
			// Colleague work and the agent's shell-only second worktree intentionally
			// have identical Git evidence, including author/committer identity.
			writeHistoryFixture(t, other, "unobserved.py", "unobserved = 1\n")
			gitRun(t, other, "add", "unobserved.py")
			gitRun(t, other, "commit", "-q", "-m", "work outside this checkout")
			gitRun(t, dir, "merge", "-q", "--no-edit", "other")
			path := "unobserved.py"
			switch mode {
			case "later-edit":
				writeHistoryFixture(t, dir, path, "unobserved = 1\nown_edit = 2\n")
			case "later-rename":
				gitRun(t, dir, "mv", path, "renamed.py")
				gitRun(t, dir, "commit", "-q", "-m", "rename incoming file")
				path = "renamed.py"
			case "uncommitted-rename":
				if err := os.Rename(filepath.Join(dir, path), filepath.Join(dir, "renamed.py")); err != nil {
					t.Fatal(err)
				}
				path = "renamed.py"
			}
			changes, ok, _, info, err := ChangedFilesWithInfo(dir, session)
			if err != nil || !ok || info.ImportedDropped != 0 {
				t.Fatalf("review lost: ok=%v dropped=%d err=%v", ok, info.ImportedDropped, err)
			}
			found, own := false, mode == "fast-forward"
			for _, c := range changes {
				if c.FilePath == path {
					found = true
					if c.AddedText == "" || c.FullContent == "" || c.BlobSHA == "" {
						t.Fatal("uncertain code no longer reaches review")
					}
					if c.AddedLines != nil {
						t.Errorf("unobserved work claimed as agent-written: %v", c.AddedLines)
					}
				}
				if c.FilePath == "own.py" {
					own = c.AddedText != ""
					if mode != "later-rename" && mode != "uncommitted-rename" && len(c.AddedLines) != 1 {
						t.Errorf("observed own pushed commit lost attribution: %v", c.AddedLines)
					}
				}
			}
			if !found || !own {
				t.Fatalf("code omitted: incoming=%v own=%v", found, own)
			}
		})
	}
}

func TestObservedOwnFeatureMergeKeepsAuthorship(t *testing.T) {
	t.Cleanup(scratch.SetUserCacheDirForTest(t.TempDir()))
	dir, session := initRepo(t)
	if err := CaptureBaseline(dir, session); err != nil {
		t.Fatal(err)
	}
	gitRun(t, dir, "checkout", "-q", "-b", "own-feature")
	writeHistoryFixture(t, dir, "own.py", "own = 1\n")
	gitRun(t, dir, "add", "own.py")
	gitRun(t, dir, "commit", "-q", "-m", "own feature")
	gitRun(t, dir, "checkout", "-q", "master")
	gitRun(t, dir, "merge", "-q", "--no-ff", "--no-edit", "own-feature")
	changes, ok, _, err := ChangedFiles(dir, session)
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	for _, c := range changes {
		if c.FilePath == "own.py" && len(c.AddedLines) == 1 {
			return
		}
	}
	t.Fatal("observed own feature commit lost")
}

func writeHistoryFixture(t *testing.T, dir, path, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, path), []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestUnobservedFastForwardLeftOffCheckoutStaysReviewedUnknown(t *testing.T) {
	t.Cleanup(scratch.SetUserCacheDirForTest(t.TempDir()))
	dir, session := initRepo(t)
	withRemote(t, dir)
	other := filepath.Join(t.TempDir(), "other")
	gitRun(t, dir, "worktree", "add", "-q", "-b", "other", other)
	if err := CaptureBaseline(dir, session); err != nil {
		t.Fatal(err)
	}
	gitRun(t, dir, "checkout", "-q", "-b", "feature")
	commitFile(t, other, "incoming.py", "incoming = 1\n")
	gitRun(t, dir, "merge", "-q", "--ff-only", "other")
	gitRun(t, dir, "checkout", "-q", "master")
	changes, ok, _, err := ChangedFiles(dir, session)
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	for _, c := range changes {
		if c.FilePath == "incoming.py" {
			if c.AddedText == "" || c.FullContent == "" || c.BlobSHA == "" || c.AddedLines != nil {
				t.Fatalf("review/unknown contract lost: %+v", c)
			}
			return
		}
	}
	t.Fatal("off-checkout incoming code disappeared")
}

func TestHistoryUncertaintyNeverDropsReviewBodies(t *testing.T) {
	for _, mode := range []string{"over-limit", "bad-base", "missing-reflog"} {
		t.Run(mode, func(t *testing.T) {
			dir, _ := initRepo(t)
			base := Head(dir)
			at := time.Now().Unix()
			count := 1
			if mode == "over-limit" {
				count = maxAuthorshipCommits + 1
			}
			for i := 0; i < count; i++ {
				gitRun(t, dir, "commit", "-q", "--allow-empty", "-m", "bounded history")
			}
			dirs := []string{dir}
			if mode == "bad-base" {
				base = "missing-baseline"
			}
			if mode == "missing-reflog" {
				dirs = []string{t.TempDir()}
			}
			changes := []transcript.Change{{FilePath: "own.py", AddedLines: []int{1}, AddedText: "own = 1\n", FullContent: "own = 1\n", BlobSHA: "blob"}}
			keepUnprovenHistoryUnattributed(dir, base, "HEAD", at, dirs, changes)
			if changes[0].AddedLines != nil || changes[0].AddedText == "" || changes[0].FullContent == "" || changes[0].BlobSHA != "blob" {
				t.Fatalf("uncertainty lost review or claimed authorship: %+v", changes)
			}
		})
	}
}
