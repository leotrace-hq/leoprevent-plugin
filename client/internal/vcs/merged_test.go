package vcs

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/scratch"
)

func TestOwnUnrecordedWorktreeCommitMergedBackStaysInReview(t *testing.T) {
	t.Cleanup(scratch.SetUserCacheDirForTest(t.TempDir()))
	dir, session := initRepo(t)
	if err := CaptureBaseline(dir, session); err != nil {
		t.Fatal(err)
	}
	// A shell-only agent creates and edits its own worktree. No separate Edit hook
	// records it, but its commit is merged back before Stop.
	own := filepath.Join(t.TempDir(), "own-shell-worktree")
	gitRun(t, dir, "worktree", "add", "-q", "-b", "own-shell", own)
	if err := os.WriteFile(filepath.Join(own, "agent_work.py"), []byte("agent_work = 1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, own, "add", "agent_work.py")
	gitRun(t, own, "commit", "-q", "-m", "agent own shell work")
	gitRun(t, dir, "merge", "-q", "--no-ff", "--no-edit", "own-shell")
	changes, ok, _, _, err := ChangedFilesWithInfo(dir, session)
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	for _, c := range changes {
		// Review coverage is the invariant. Authorship may remain unknown when
		// this checkout did not observe the commit being created.
		if c.FilePath == "agent_work.py" && c.AddedText != "" && c.FullContent != "" {
			return
		}
	}
	t.Fatal("agent's own shell worktree commit was excluded")
}
