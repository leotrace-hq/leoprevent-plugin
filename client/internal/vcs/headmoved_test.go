package vcs

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

const teammateDate = "2020-01-01T00:00:00Z"

type remoteFixture struct {
	bare    string
	work    string
	other   string
	session string
}

func newRemoteFixture(t *testing.T) remoteFixture {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	root := t.TempDir()
	seed := filepath.Join(root, "seed")
	bare := filepath.Join(root, "remote.git")
	if err := os.MkdirAll(seed, 0o755); err != nil {
		t.Fatal(err)
	}
	gitRun(t, seed, "init", "-q", "-b", "main")
	writeFile(t, filepath.Join(seed, "app.py"), "import os\n")
	gitRun(t, seed, "add", "-A")
	gitAt(t, seed, teammateDate, "commit", "-q", "-m", "init")
	gitRun(t, root, "clone", "-q", "--bare", seed, bare)
	work := filepath.Join(root, "work")
	other := filepath.Join(root, "other")
	gitRun(t, root, "clone", "-q", bare, work)
	gitRun(t, root, "clone", "-q", bare, other)
	session := sanitize(t.Name())
	t.Cleanup(func() {
		_ = os.Remove(scratchPath(scopedSession(work, session)))
		clearTouched(session)
	})
	return remoteFixture{bare: bare, work: work, other: other, session: session}
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func (f remoteFixture) pushTeammateCommits(t *testing.T, commits, filesPerCommit int) {
	t.Helper()
	n := 0
	for c := 0; c < commits; c++ {
		for i := 0; i < filesPerCommit; i++ {
			writeFile(t, filepath.Join(f.other, "pkg", fmt.Sprintf("f%03d.py", n)), fmt.Sprintf("value_%d = %d\n", n, n))
			n++
		}
		gitRun(t, f.other, "add", "-A")
		gitAt(t, f.other, teammateDate, "commit", "-q", "-m", fmt.Sprintf("teammate %d", c))
	}
	gitRun(t, f.other, "push", "-q", "origin", "main")
}

func reviewedPaths(t *testing.T, f remoteFixture) ([]string, SkipReason, BaselineInfo) {
	t.Helper()
	changes, ok, skip, info, err := ChangedFilesWithInfo(f.work, f.session)
	if err != nil || !ok {
		t.Fatalf("ChangedFilesWithInfo: ok=%v skip=%q err=%v", ok, skip, err)
	}
	var paths []string
	for _, c := range changes {
		paths = append(paths, c.FilePath)
	}
	return paths, skip, info
}

func TestHeadMovedWithNoAgentEditsReviewsNothing(t *testing.T) {
	// Arrange
	f := newRemoteFixture(t)
	if err := CaptureBaseline(f.work, f.session); err != nil {
		t.Fatal(err)
	}
	f.pushTeammateCommits(t, 50, 4)
	RecordTouchedPaths(nil, f.work, f.session)
	gitRun(t, f.work, "pull", "-q", "--ff-only")

	// Act
	paths, skip, info := reviewedPaths(t, f)

	// Assert
	if len(paths) != 0 {
		t.Fatalf("reviewed %d files the agent never edited: %v", len(paths), paths[:min(len(paths), 5)])
	}
	if skip != SkipHeadMovedNoAgentEdits {
		t.Fatalf("skip = %q, want %q", skip, SkipHeadMovedNoAgentEdits)
	}
	if got := info.FileDecisions.Counts["discovery:"+headMovedNotAgent]; got != 200 {
		t.Fatalf("head_moved_not_agent decisions = %d, want 200", got)
	}
	if wire.ValidFileDecisions(info.FileDecisions) == nil {
		t.Fatal("file decisions failed validation")
	}
}

func TestHeadMovedKeepsOnlyTheAgentsEdit(t *testing.T) {
	// Arrange
	f := newRemoteFixture(t)
	if err := CaptureBaseline(f.work, f.session); err != nil {
		t.Fatal(err)
	}
	f.pushTeammateCommits(t, 50, 4)
	RecordTouchedPaths(nil, f.work, f.session)
	gitRun(t, f.work, "pull", "-q", "--ff-only")
	RecordTouchedPaths([]string{"app.py"}, f.work, f.session)
	writeFile(t, filepath.Join(f.work, "app.py"), "import os\neval(user_input)\n")

	// Act
	paths, skip, _ := reviewedPaths(t, f)

	// Assert
	if len(paths) != 1 || paths[0] != "app.py" {
		t.Fatalf("reviewed %v, want exactly [app.py]", paths)
	}
	if skip != "" {
		t.Fatalf("skip = %q, want none", skip)
	}
}

func TestTheTranscriptAloneAttributesAnEdit(t *testing.T) {
	// Arrange
	f := newRemoteFixture(t)
	if err := CaptureBaseline(f.work, f.session); err != nil {
		t.Fatal(err)
	}
	f.pushTeammateCommits(t, 5, 4)
	gitRun(t, f.work, "pull", "-q", "--ff-only")
	writeFile(t, filepath.Join(f.work, "app.py"), "import os\neval(user_input)\n")
	transcript := func() []string { return []string{filepath.Join(f.work, "app.py")} }

	// Act
	changes, ok, _, _, err := ChangedFilesAttributed(f.work, f.session, transcript)

	// Assert
	if err != nil || !ok || len(changes) != 1 || changes[0].FilePath != "app.py" {
		t.Fatalf("got ok=%v err=%v changes=%d, want exactly app.py", ok, err, len(changes))
	}
}

func TestFetchedMidTurnHistoryIsSubtractedWithoutAttribution(t *testing.T) {
	// Arrange
	f := newRemoteFixture(t)
	if err := CaptureBaseline(f.work, f.session); err != nil {
		t.Fatal(err)
	}
	f.pushTeammateCommits(t, 10, 4)
	gitRun(t, f.work, "pull", "-q", "--ff-only")

	// Act
	paths, _, info := reviewedPaths(t, f)

	// Assert
	if len(paths) != 0 {
		t.Fatalf("reviewed %d already-published files: %v", len(paths), paths[:min(len(paths), 5)])
	}
	if got := info.ImportedDropped; got != 40 {
		t.Fatalf("ImportedDropped = %d, want 40", got)
	}
}

func TestDefaultBranchTipSurvivesTheTipCap(t *testing.T) {
	// Arrange
	f := newRemoteFixture(t)
	gitRun(t, f.other, "checkout", "-q", "-b", "side")
	for i := 0; i < 100; i++ {
		gitAt(t, f.other, teammateDate, "commit", "-q", "--allow-empty", "-m", fmt.Sprintf("side %d", i))
		gitRun(t, f.other, "branch", "-q", fmt.Sprintf("a%03d", i))
	}
	gitRun(t, f.other, "push", "-q", "origin", "refs/heads/a*:refs/heads/a*")
	gitRun(t, f.other, "checkout", "-q", "main")
	writeFile(t, filepath.Join(f.other, "main.py"), "x = 1\n")
	gitRun(t, f.other, "add", "-A")
	gitAt(t, f.other, teammateDate, "commit", "-q", "-m", "main moves")
	gitRun(t, f.other, "push", "-q", "origin", "main")
	gitRun(t, f.work, "fetch", "-q", "origin")
	gitRun(t, f.work, "remote", "set-head", "origin", "-d")
	mainTip := strings.TrimSpace(mustGit(t, f.work, "rev-parse", "refs/remotes/origin/main"))
	firstSorted := strings.TrimSpace(mustGit(t, f.work, "for-each-ref", "--count=64", "--format=%(objectname)", "refs/remotes/"))
	if strings.Contains(firstSorted, mainTip) {
		t.Fatal("fixture invalid: origin/main already sorts within the first 64 refs")
	}

	// Act
	history := snapshotHistory(f.work)

	// Assert
	tips := parseBaselines([]byte("ref\n" + history))[0].tips
	if len(tips) != maxPublishedTips {
		t.Fatalf("recorded %d tips, want the cap of %d", len(tips), maxPublishedTips)
	}
	if tips[0] != mainTip {
		t.Fatalf("first recorded tip = %s, want origin/main %s", tips[0], mainTip)
	}
}

func TestAgentPushingItsOwnBranchIsStillReviewed(t *testing.T) {
	for _, attributed := range []bool{true, false} {
		t.Run(fmt.Sprintf("attributed=%v", attributed), func(t *testing.T) {
			// Arrange
			f := newRemoteFixture(t)
			if err := CaptureBaseline(f.work, f.session); err != nil {
				t.Fatal(err)
			}
			if attributed {
				RecordTouchedPaths([]string{filepath.Join(f.work, "app.py")}, f.work, f.session)
			}
			writeFile(t, filepath.Join(f.work, "app.py"), "import os\neval(user_input)\n")
			gitRun(t, f.work, "commit", "-q", "-am", "agent: eval")
			gitRun(t, f.work, "push", "-q", "origin", "HEAD:refs/heads/agent-branch")

			// Act
			paths, skip, _ := reviewedPaths(t, f)

			// Assert
			if len(paths) != 1 || paths[0] != "app.py" || skip != "" {
				t.Fatalf("reviewed %v skip=%q, want exactly [app.py]", paths, skip)
			}
		})
	}
}

func TestAgentPushAfterPullKeepsItsEdit(t *testing.T) {
	// Arrange
	f := newRemoteFixture(t)
	if err := CaptureBaseline(f.work, f.session); err != nil {
		t.Fatal(err)
	}
	f.pushTeammateCommits(t, 5, 4)
	RecordTouchedPaths(nil, f.work, f.session)
	gitRun(t, f.work, "pull", "-q", "--ff-only")
	RecordTouchedPaths([]string{"app.py"}, f.work, f.session)
	writeFile(t, filepath.Join(f.work, "app.py"), "import os\neval(user_input)\n")
	gitRun(t, f.work, "commit", "-q", "-am", "agent: eval")
	gitRun(t, f.work, "push", "-q", "origin", "HEAD:main")
	gitRun(t, f.work, "fetch", "-q", "origin")

	// Act
	paths, _, _ := reviewedPaths(t, f)

	// Assert
	if len(paths) != 1 || paths[0] != "app.py" {
		t.Fatalf("reviewed %v, want exactly [app.py]", paths)
	}
}

func TestOwnCommitsAloneDoNotCountAsHistoryMoving(t *testing.T) {
	// Arrange
	f := newRemoteFixture(t)
	if err := CaptureBaseline(f.work, f.session); err != nil {
		t.Fatal(err)
	}
	RecordTouchedPaths(nil, f.work, f.session)
	writeFile(t, filepath.Join(f.work, "made_by_shell.py"), "eval(x)\n")
	gitRun(t, f.work, "add", "-A")
	gitRun(t, f.work, "commit", "-q", "-m", "agent commit")

	// Act
	paths, skip, _ := reviewedPaths(t, f)

	// Assert
	if len(paths) != 1 || paths[0] != "made_by_shell.py" || skip != "" {
		t.Fatalf("reviewed %v skip=%q, want the turn's own committed file", paths, skip)
	}
}

func TestOlderScratchTipsStillParse(t *testing.T) {
	// Arrange
	scratch := "abc123\n#head h1\n#at 100\n#tip t1\n#tip t2\n#root /r\n"

	// Act
	sections := parseBaselines([]byte(scratch))

	// Assert
	if len(sections) != 1 || strings.Join(sections[0].tips, ",") != "t1,t2" || sections[0].head != "h1" {
		t.Fatalf("parsed %+v", sections)
	}
}

func mustGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).Output()
	if err != nil {
		t.Fatalf("git %s: %v", strings.Join(args, " "), err)
	}
	return string(out)
}
