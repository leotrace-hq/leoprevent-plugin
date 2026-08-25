package vcs

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
)

// seedRepoAt makes dir a git repo with one committed file and returns dir.
func seedRepoAt(t *testing.T, dir, name, body string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) {
		c := exec.Command("git", append([]string{"-C", dir}, args...)...)
		c.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("git %v in %s: %v\n%s", args, dir, err, out)
		}
	}
	run("init", "-q")
	fp := filepath.Join(dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(fp), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fp, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", "-A")
	run("commit", "-q", "-m", "init")
	return dir
}

func needGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
}

// session returns a session id whose scratch file is cleaned up after the test.
func session(t *testing.T, name string) string {
	t.Helper()
	t.Cleanup(func() { ClearBaseline(name) })
	return name
}

// ⚠️ THE NO-REGRESSION GUARD. When cwd IS a repository, nothing about the emitted
// paths or the scratch format may change: no prefix, and a file that earlier versions
// wrote must still parse.
func TestSingleRepoBehaviourIsUnchanged(t *testing.T) {
	needGit(t)
	repo := seedRepoAt(t, filepath.Join(t.TempDir(), "solo"), "app.py", "x = 1\n")
	s := session(t, "vcs-ws-solo")

	if err := CaptureBaseline(repo, s); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(scratchPath(s))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), repoSectionPrefix) {
		t.Errorf("a single-repo capture must write no %q header; got:\n%s", repoSectionPrefix, raw)
	}
	appendTo(t, filepath.Join(repo, "app.py"), "y = 2\n")

	changes, ok, _, _, _ := ChangedFilesWithInfo(repo, s)
	if !ok {
		t.Fatal("expected the git path")
	}
	if got := paths(changes); len(got) != 1 || got[0] != "app.py" {
		t.Errorf("single-repo paths must stay repo-root-relative and unprefixed, got %v", got)
	}
}

// A scratch file written by an earlier version (ref, headers, untracked snapshot,
// no #repo header) must still parse — a session can span a plugin update.
func TestOriginalScratchFormatStillParses(t *testing.T) {
	old := "abc123\n" + baselineHeadPrefix + "deadbeef\n" + publishedTipPrefix + "cafe\n" + "hash1\tsome/file.py\n"
	got := parseBaselines([]byte(old))
	if len(got) != 1 {
		t.Fatalf("expected one section, got %d", len(got))
	}
	s := got[0]
	if s.label != "" || s.ref != "abc123" || s.head != "deadbeef" {
		t.Errorf("mis-parsed legacy scratch: %+v", s)
	}
	if len(s.tips) != 1 || s.tips[0] != "cafe" {
		t.Errorf("tips lost: %+v", s.tips)
	}
	if s.untracked["some/file.py"] != "hash1" {
		t.Errorf("untracked snapshot lost: %+v", s.untracked)
	}
}

// An unrecognised header from a future client must never be read as a baseline ref:
// diffing against a nonsense revision is worse than having no section.
func TestUnknownHeaderIsNotMistakenForARef(t *testing.T) {
	got := parseBaselines([]byte("#future something\n"))
	if len(got) != 0 {
		t.Errorf("an unknown header alone must yield no usable section, got %+v", got)
	}
}

func appendTo(t *testing.T, path, extra string) {
	t.Helper()
	old, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(old, []byte(extra)...), 0o644); err != nil {
		t.Fatal(err)
	}
}

// paths lists the emitted FilePaths, sorted so a test asserts on content rather
// than on the order git happened to walk the repositories in.
func paths(cs []transcript.Change) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.FilePath)
	}
	sort.Strings(out)
	return out
}

// ⚠️ A COMMITTED SYMLINK MUST NEVER BE READ, AND ITS TARGET MUST NEVER TRAVEL.
// A repository can commit `config.yaml -> /etc/passwd`; following it would egress an
// out-of-repo file to the server as "changed code". Two guards stand behind this:
// Lstat drops symlinks outright (including ones pointing INSIDE the repo), and
// os.OpenInRoot refuses anything resolving outside the repository even if the path is
// swapped between the check and the read.
func TestACommittedSymlinkIsNeverReadOrEgressed(t *testing.T) {
	needGit(t)
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privilege on Windows")
	}
	secret := filepath.Join(t.TempDir(), "outside-secret.txt")
	if err := os.WriteFile(secret, []byte("TOP_SECRET_OUT_OF_REPO\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	repo := seedRepoAt(t, filepath.Join(t.TempDir(), "repo"), "app.py", "x = 1\n")
	s := session(t, "vcs-symlink-guard")
	if err := CaptureBaseline(repo, s); err != nil {
		t.Fatal(err)
	}
	// The agent adds a symlink pointing out of the repository.
	if err := os.Symlink(secret, filepath.Join(repo, "config.yaml")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	changes, ok, _, _, _ := ChangedFilesWithInfo(repo, s)
	if !ok {
		t.Fatal("expected the git path")
	}
	for _, c := range changes {
		if strings.Contains(c.AddedText, "TOP_SECRET") || strings.Contains(c.FullContent, "TOP_SECRET") {
			t.Fatalf("EGRESS: a symlink target's content was captured for %q", c.FilePath)
		}
		if c.FilePath == "config.yaml" {
			t.Errorf("the symlink itself must be skipped, got a change for %q", c.FilePath)
		}
	}
}

// ⚠️ AND THE Lstat IS WHAT COVERS AN IN-REPO SYMLINK, WHICH OpenInRoot FOLLOWS.
// `notes.py -> ./secrets.py` resolves INSIDE the repository, so the root containment
// check has no objection to it; only the no-follow Lstat drops it. Without this case
// the pairing of the two guards is an untested claim — os.OpenInRoot alone already
// handles the out-of-repo link in the test above.
func TestAnInRepoSymlinkIsAlsoSkipped(t *testing.T) {
	needGit(t)
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privilege on Windows")
	}
	repo := seedRepoAt(t, filepath.Join(t.TempDir(), "repo"), "app.py", "x = 1\n")
	if err := os.WriteFile(filepath.Join(repo, "secrets.py"), []byte("KEY = 'in-repo-secret'\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := session(t, "vcs-symlink-inrepo")
	if err := CaptureBaseline(repo, s); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("./secrets.py", filepath.Join(repo, "notes.py")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	changes, ok, _, _, _ := ChangedFilesWithInfo(repo, s)
	if !ok {
		t.Fatal("expected the git path")
	}
	for _, c := range changes {
		if c.FilePath == "notes.py" {
			t.Errorf("an in-repo symlink must be skipped, not read through; got a change for %q", c.FilePath)
		}
	}
	// secrets.py itself is a real new file and IS legitimately reviewed — the point is
	// that it is reported once, under its own name, never a second time via the link.
	var seen int
	for _, c := range changes {
		if strings.Contains(c.AddedText, "in-repo-secret") {
			seen++
		}
	}
	if seen > 1 {
		t.Errorf("the same content was captured %d times (the symlink was followed)", seen)
	}
}

// --- PreToolUse repo discovery (LEO-154) ----------------------------------------------

// edits records a repo the way the PreToolUse hook does, by naming a file inside it.
func edits(t *testing.T, repo, name, sessionID, cwd string) {
	t.Helper()
	if err := RecordEditedRepo(filepath.Join(repo, filepath.FromSlash(name)), cwd, sessionID); err != nil {
		t.Fatalf("RecordEditedRepo: %v", err)
	}
}

// ⚠️ THE HEADLINE CASE, AND IT IS STRICTLY WIDER THAN THE ONE ENUMERATION COULD REACH.
// The repositories here are SIBLINGS of the working directory, not children of it, so
// walking down from cwd would not have found either. Naming the file the agent is about
// to write is what makes them knowable.
func TestReposOutsideCwdAreDiscoveredFromTheEditedPath(t *testing.T) {
	needGit(t)
	base := t.TempDir()
	// cwd is somewhere else entirely and is not a repository at all.
	cwd := filepath.Join(base, "workspace")
	if err := os.MkdirAll(cwd, 0o755); err != nil {
		t.Fatal(err)
	}
	a := seedRepoAt(t, filepath.Join(base, "elsewhere", "alpha"), "app.py", "x = 1\n")
	b := seedRepoAt(t, filepath.Join(base, "further", "beta"), "handler.py", "y = 1\n")
	s := session(t, "vcs-ptu-scattered")

	if err := CaptureBaseline(cwd, s); err != nil { // no repo at cwd: captures nothing
		t.Fatal(err)
	}
	edits(t, a, "app.py", s, cwd)
	edits(t, b, "handler.py", s, cwd)
	appendTo(t, filepath.Join(a, "app.py"), "import requests\n")
	appendTo(t, filepath.Join(b, "handler.py"), "import os\n")

	changes, ok, skip, _, err := ChangedFilesWithInfo(cwd, s)
	if err != nil || !ok {
		t.Fatalf("expected the git path, got ok=%v skip=%q err=%v", ok, skip, err)
	}
	got := paths(changes)
	sort.Strings(got)
	want := []string{"alpha/app.py", "beta/handler.py"}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("paths = %v, want %v (each labelled by its repo's basename)", got, want)
	}
}

// ⚠️ TWO REPOS CAN SHARE A BASENAME, and the label QUALIFIES the path — so a collision
// would merge two projects into one namespace and a finding would cite a path matching
// two files. Disambiguation happens at Stop, which is single-process; each PreToolUse
// races the others and could not agree on a suffix.
func TestTwoReposWithTheSameBasenameGetDistinctLabels(t *testing.T) {
	needGit(t)
	base := t.TempDir()
	cwd := filepath.Join(base, "ws")
	if err := os.MkdirAll(cwd, 0o755); err != nil {
		t.Fatal(err)
	}
	one := seedRepoAt(t, filepath.Join(base, "projA", "api"), "m.py", "x = 1\n")
	two := seedRepoAt(t, filepath.Join(base, "projB", "api"), "m.py", "y = 1\n")
	s := session(t, "vcs-ptu-collide")

	_ = CaptureBaseline(cwd, s)
	edits(t, one, "m.py", s, cwd)
	edits(t, two, "m.py", s, cwd)
	appendTo(t, filepath.Join(one, "m.py"), "import requests\n")
	appendTo(t, filepath.Join(two, "m.py"), "import os\n")

	changes, ok, _, _, _ := ChangedFilesWithInfo(cwd, s)
	if !ok {
		t.Fatal("expected the git path")
	}
	got := paths(changes)
	sort.Strings(got)
	if len(got) != 2 {
		t.Fatalf("both repos' files must survive, got %v", got)
	}
	if got[0] == got[1] {
		t.Fatalf("two repos named `api` collapsed onto one path %q: a finding citing it "+
			"would match two different files", got[0])
	}
	for _, p := range got {
		if !strings.HasPrefix(p, "api") {
			t.Errorf("label should stay derived from the basename, got %q", p)
		}
	}
}

// The cwd repository is captured at UserPromptSubmit and must NOT be recorded a second
// time when the agent edits it: that would emit two sections for one repo, so every
// changed file would appear twice, once bare and once under a basename label.
func TestEditingTheCwdRepoAddsNoSecondSection(t *testing.T) {
	needGit(t)
	repo := seedRepoAt(t, filepath.Join(t.TempDir(), "solo"), "app.py", "x = 1\n")
	s := session(t, "vcs-ptu-cwd")

	if err := CaptureBaseline(repo, s); err != nil {
		t.Fatal(err)
	}
	edits(t, repo, "app.py", s, repo)
	appendTo(t, filepath.Join(repo, "app.py"), "import requests\n")

	changes, ok, _, _, _ := ChangedFilesWithInfo(repo, s)
	if !ok {
		t.Fatal("expected the git path")
	}
	got := paths(changes)
	if len(got) != 1 || got[0] != "app.py" {
		t.Errorf("the cwd repo must stay a single unprefixed section, got %v", got)
	}
}

// Recording is idempotent: an agent editing one repo fifty times must snapshot it once,
// and the later calls must not re-snapshot over the top of a tree it has since modified
// (which would hide its own earlier edits).
func TestRecordingARepoTwiceKeepsTheFirstBaseline(t *testing.T) {
	needGit(t)
	base := t.TempDir()
	cwd := filepath.Join(base, "ws")
	if err := os.MkdirAll(cwd, 0o755); err != nil {
		t.Fatal(err)
	}
	repo := seedRepoAt(t, filepath.Join(base, "proj"), "app.py", "x = 1\n")
	s := session(t, "vcs-ptu-idem")

	_ = CaptureBaseline(cwd, s)
	edits(t, repo, "app.py", s, cwd)
	appendTo(t, filepath.Join(repo, "app.py"), "import requests\n")
	edits(t, repo, "app.py", s, cwd) // second tool call, tree already dirty

	changes, ok, _, _, _ := ChangedFilesWithInfo(cwd, s)
	if !ok {
		t.Fatal("expected the git path")
	}
	if got := paths(changes); len(got) != 1 || got[0] != "proj/app.py" {
		t.Fatalf("expected the edit to still be visible, got %v", got)
	}
	if !strings.Contains(changes[0].AddedText, "requests") {
		t.Errorf("re-recording overwrote the baseline, hiding the agent's own edit: %q",
			changes[0].AddedText)
	}
}

// A tool that names no file (Bash above all) cannot be attributed to a repository. It
// must decline quietly rather than guess — guessing means snapshotting the wrong repo.
func TestAToolWithNoPathRecordsNothing(t *testing.T) {
	needGit(t)
	s := session(t, "vcs-ptu-nopath")
	if err := RecordEditedRepo("", t.TempDir(), s); err != nil {
		t.Fatalf("must be a quiet no-op, got %v", err)
	}
	if entries, err := os.ReadDir(discoveredDir(s)); err == nil && len(entries) > 0 {
		t.Errorf("recorded %d repo(s) for a tool that named no file", len(entries))
	}
}

// A path outside any repository records nothing: the agent is writing to /tmp or a
// scratch dir, and inventing a section for it would diff a non-repo.
func TestAPathOutsideAnyRepoRecordsNothing(t *testing.T) {
	needGit(t)
	base := t.TempDir() // deliberately not a repo
	s := session(t, "vcs-ptu-norepo")
	if err := RecordEditedRepo(filepath.Join(base, "notes.txt"), base, s); err != nil {
		t.Fatal(err)
	}
	if entries, err := os.ReadDir(discoveredDir(s)); err == nil && len(entries) > 0 {
		t.Errorf("recorded %d repo(s) for a path in no repository", len(entries))
	}
}

// ⚠️ PARALLEL TOOL CALLS. Agents run tools concurrently, so two hook processes can
// record at the same instant. Appending sections to one shared file interleaves them
// into a scratch that parses as nonsense — silently, because a mangled ref only makes
// the diff fail and the turn fall back. One file per repo is what makes this safe.
func TestConcurrentRecordingIsSafe(t *testing.T) {
	needGit(t)
	base := t.TempDir()
	cwd := filepath.Join(base, "ws")
	if err := os.MkdirAll(cwd, 0o755); err != nil {
		t.Fatal(err)
	}
	const n = 8
	repos := make([]string, n)
	for i := range repos {
		repos[i] = seedRepoAt(t, filepath.Join(base, "r"+string(rune('a'+i))), "app.py", "x = 1\n")
	}
	s := session(t, "vcs-ptu-conc")
	_ = CaptureBaseline(cwd, s)

	var wg sync.WaitGroup
	for _, r := range repos {
		wg.Add(1)
		go func(repo string) {
			defer wg.Done()
			_ = RecordEditedRepo(filepath.Join(repo, "app.py"), cwd, s)
		}(r)
	}
	wg.Wait()

	for _, r := range repos {
		appendTo(t, filepath.Join(r, "app.py"), "import requests\n")
	}
	changes, ok, _, _, _ := ChangedFilesWithInfo(cwd, s)
	if !ok {
		t.Fatal("expected the git path")
	}
	if len(changes) != n {
		t.Errorf("got %d changed files from %d concurrently recorded repos, want %d "+
			"(a torn scratch loses sections silently)", len(changes), n, n)
	}
}

// ClearBaseline must remove the discovered-repo DIRECTORY too. os.Remove refuses a
// non-empty directory, so the obvious implementation leaks every workspace session's
// baselines and hands them to the next session reusing that id.
func TestClearBaselineRemovesDiscoveredRepos(t *testing.T) {
	needGit(t)
	base := t.TempDir()
	repo := seedRepoAt(t, filepath.Join(base, "proj"), "app.py", "x = 1\n")
	const s = "vcs-ptu-clear"
	t.Cleanup(func() { ClearBaseline(s) })

	if err := RecordEditedRepo(filepath.Join(repo, "app.py"), base, s); err != nil {
		t.Fatal(err)
	}
	if entries, err := os.ReadDir(discoveredDir(s)); err != nil || len(entries) == 0 {
		t.Fatalf("nothing recorded to clear (err=%v)", err)
	}
	ClearBaseline(s)
	if _, err := os.Stat(discoveredDir(s)); !os.IsNotExist(err) {
		t.Errorf("discovered-repo scratch survived ClearBaseline (err=%v)", err)
	}
}

// TestASessionIDCannotEscapeTheScratchDirectory closes the class Aikido's second
// finding pointed at.
//
// The session id comes straight from the agent's stdin, and sanitize neutralised
// slashes but NOT the dot names — so ".." survived and filepath.Join walked out of the
// scratch directory, resolving scratchPath("..") to the temp dir itself. Nothing
// exploited it (the reads and writes just failed against a directory), but this package
// now calls os.RemoveAll on a path built from that id, and a sanitizer that permits any
// escape is one edit away from that being destructive.
func TestASessionIDCannotEscapeTheScratchDirectory(t *testing.T) {
	base := filepath.Join(os.TempDir(), "leoprevent-baselines")
	for _, id := range []string{"..", ".", "", "../..", "a/../..", "....", "..."} {
		for _, got := range []string{scratchPath(id), discoveredDir(id)} {
			rel, err := filepath.Rel(base, got)
			if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				t.Errorf("session id %q escaped the scratch dir: %s (rel=%q)", id, got, rel)
			}
		}
	}
}

// TestACdIntoTheEditedRepoStillDiscoversIt is the regression on the live failure of
// 2026-08-25, and the mechanism is worth stating because every part of it looks correct
// in isolation.
//
// Asked to write into a project from a workspace folder, the agent ran `cd <project>`
// and then a heredoc. Claude Code reports the NEW cwd for the rest of the turn, so by
// the time PreToolUse fired, cwd named the very repository being edited — and the skip
// declined to record it, on the reasoning that the cwd repository was already captured
// at UserPromptSubmit. It was not: at prompt time cwd was the workspace folder, which is
// no repository at all, so CaptureBaseline had captured NOTHING.
//
// Net effect: the one repository being edited was the one repository discovery refused,
// and the turn reported itself unreviewed — the exact symptom this whole event exists to
// remove, which is why it survived several rounds of live testing.
func TestACdIntoTheEditedRepoStillDiscoversIt(t *testing.T) {
	needGit(t)
	base := t.TempDir()
	workspace := filepath.Join(base, "workspace")
	if err := os.MkdirAll(workspace, 0o755); err != nil {
		t.Fatal(err)
	}
	repo := seedRepoAt(t, filepath.Join(workspace, "project"), "app.py", "x = 1\n")
	s := session(t, "vcs-ptu-cd")

	// Turn start: cwd is the workspace folder, so nothing is baselined.
	if err := CaptureBaseline(workspace, s); err != nil {
		t.Fatal(err)
	}
	// The agent cds in, so every later hook reports the repo itself as cwd.
	edits(t, repo, "app.py", s, repo)
	appendTo(t, filepath.Join(repo, "app.py"), "import requests\n")

	changes, ok, skip, _, err := ChangedFilesWithInfo(repo, s)
	if err != nil || !ok {
		t.Fatalf("expected the git path, got ok=%v skip=%q err=%v", ok, skip, err)
	}
	if got := paths(changes); len(got) != 1 {
		t.Fatalf("paths = %v, want exactly the one edited file — a cd into the edited "+
			"repo must not make it undiscoverable", got)
	}
}

// TestTheBaselinedRepoIsNotRecordedTwiceAfterACd is the other half, and it fails in the
// opposite direction: a session that DID start in a repository must not gain a second,
// labelled section for it just because the agent cd'd somewhere and back. Two sections
// for one repository report every changed file twice.
func TestTheBaselinedRepoIsNotRecordedTwiceAfterACd(t *testing.T) {
	needGit(t)
	repo := seedRepoAt(t, filepath.Join(t.TempDir(), "solo"), "app.py", "x = 1\n")
	s := session(t, "vcs-ptu-nodupe")

	if err := CaptureBaseline(repo, s); err != nil { // baselined, unqualified
		t.Fatal(err)
	}
	edits(t, repo, "app.py", s, repo)
	appendTo(t, filepath.Join(repo, "app.py"), "import requests\n")

	changes, ok, _, _, err := ChangedFilesWithInfo(repo, s)
	if err != nil || !ok {
		t.Fatalf("expected the git path, got ok=%v err=%v", ok, err)
	}
	got := paths(changes)
	if len(got) != 1 || got[0] != "app.py" {
		t.Errorf("paths = %v, want exactly [app.py] — the baselined repo must not also "+
			"be recorded as a discovered one", got)
	}
}

// TestUnattributableWriteIsReviewedAgainstHead covers the one write discovery cannot
// see: a shell command whose target path is computed at runtime, so PreToolUse can
// scavenge nothing and no repository is ever named. Without the Stop-time fallback the
// change ships unreviewed.
func TestUnattributableWriteIsReviewedAgainstHead(t *testing.T) {
	needGit(t)
	base := t.TempDir()
	workspace := filepath.Join(base, "workspace")
	if err := os.MkdirAll(workspace, 0o755); err != nil {
		t.Fatal(err)
	}
	repo := seedRepoAt(t, filepath.Join(workspace, "project"), "app.py", "x = 1\n")
	s := session(t, "vcs-headfallback")

	if err := CaptureBaseline(workspace, s); err != nil { // not a repo: captures nothing
		t.Fatal(err)
	}
	// No RecordEditedRepo call at all — that is the point: nothing named this repo.
	appendTo(t, filepath.Join(repo, "app.py"), "import requests\n")

	changes, ok, skip, info, err := ChangedFilesWithInfo(workspace, s)
	if err != nil || !ok {
		t.Fatalf("expected the HEAD fallback to produce a reviewable change set, got ok=%v skip=%q err=%v", ok, skip, err)
	}
	if got := paths(changes); len(got) != 1 {
		t.Fatalf("paths = %v, want the one edited file", got)
	}
	// ⚠️ THE FLAG IS AS LOAD-BEARING AS THE REVIEW. Without it the console, the CSV and
	// the developer's banner all present this as a normal review, when its diff is a
	// superset of the turn and its findings may describe earlier uncommitted work.
	if len(info.HeadAnchored) != 1 || info.HeadAnchored[0] != "project" {
		t.Errorf("HeadAnchored = %v, want [project]", info.HeadAnchored)
	}
	// ⚠️ AND IT MUST CARRY NO LINE NUMBERS, or the server anchors positionally, reads
	// pre-turn work as introduced, and the re-wake asks the agent to edit code it never
	// wrote.
	for _, c := range changes {
		if len(c.AddedLines) != 0 {
			t.Errorf("%s carries AddedLines %v; a HEAD-anchored section must send none so "+
				"its findings are surfaced rather than applied in-turn", c.FilePath, c.AddedLines)
		}
	}
}

// TestTheHeadFallbackIsNotUsedWhenABaselineExists pins the trigger. It is a last resort:
// paying a directory scan on a turn that already has a baseline would put it on the
// common path, and its weaker HEAD anchor would displace a turn-scoped diff.
func TestTheHeadFallbackIsNotUsedWhenABaselineExists(t *testing.T) {
	needGit(t)
	repo := seedRepoAt(t, filepath.Join(t.TempDir(), "solo"), "app.py", "x = 1\n")
	s := session(t, "vcs-headfallback-off")

	if err := CaptureBaseline(repo, s); err != nil {
		t.Fatal(err)
	}
	appendTo(t, filepath.Join(repo, "app.py"), "import requests\n")

	changes, ok, _, info, err := ChangedFilesWithInfo(repo, s)
	if err != nil || !ok {
		t.Fatalf("expected the git path, got ok=%v err=%v", ok, err)
	}
	if len(info.HeadAnchored) != 0 {
		t.Errorf("HeadAnchored = %v, want none: this turn had a real baseline", info.HeadAnchored)
	}
	// And the baselined path still carries line numbers, so its findings stay attributable.
	if len(changes) != 1 || len(changes[0].AddedLines) == 0 {
		t.Errorf("a baselined turn must keep its AddedLines, got %+v", changes)
	}
}

// TestTheHeadFallbackStopsAtTwoLevels pins the depth boundary. Each pass of the walk
// reads the frontier and finds repositories one level BELOW it, so a `<=` bound reaches
// one level deeper than the constant claims — an extra tier of directory reads on every
// fallback, and a doc that no longer matches the code. Found by driving the real binary,
// not by review.
func TestTheHeadFallbackStopsAtTwoLevels(t *testing.T) {
	needGit(t)
	for _, tc := range []struct {
		name  string
		under string
		want  int
	}{
		{"one level down", "proj", 1},
		{"two levels down", filepath.Join("group", "proj"), 1},
		{"three levels down is out of reach", filepath.Join("a", "b", "proj"), 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := t.TempDir()
			ws := filepath.Join(base, "ws")
			if err := os.MkdirAll(ws, 0o755); err != nil {
				t.Fatal(err)
			}
			repo := seedRepoAt(t, filepath.Join(ws, tc.under), "app.py", "x = 1\n")
			s := session(t, "vcs-depth-"+strings.ReplaceAll(tc.name, " ", "-"))
			if err := CaptureBaseline(ws, s); err != nil {
				t.Fatal(err)
			}
			appendTo(t, filepath.Join(repo, "app.py"), "import requests\n")

			changes, _, _, info, err := ChangedFilesWithInfo(ws, s)
			if err != nil {
				t.Fatal(err)
			}
			if len(info.HeadAnchored) != tc.want {
				t.Errorf("HeadAnchored = %v, want %d repo(s)", info.HeadAnchored, tc.want)
			}
			if tc.want == 0 && len(changes) != 0 {
				t.Errorf("changes = %v, want none beyond the depth bound", paths(changes))
			}
		})
	}
}

// TestSeveralCandidateReposAreNamedRatherThanAllReviewed pins the decline.
//
// ⚠️ THE OLD BEHAVIOUR WAS A HOME-DIRECTORY SWEEP. With a cap of fifteen and "dirty and
// within two levels" as the only test, a real parent-of-checkouts directory answered with
// four unrelated repositories: measured live on 2026-08-25, a Copilot turn that wrote
// NOTHING reviewed leolearn-aikido, leoprevent, leoprevent-dashfilter and
// leoprevent-daterange, raised ten findings from other people's work in progress, and
// blocked the turn for 71 seconds. When more than one candidate remains and nothing named
// a path in any of them, which repository the turn was about is unknowable — so none is
// reviewed and all are named.
func TestSeveralCandidateReposAreNamedRatherThanAllReviewed(t *testing.T) {
	needGit(t)
	base := t.TempDir()
	ws := filepath.Join(base, "ws")
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	s := session(t, "vcs-fallback-decline")
	if err := CaptureBaseline(ws, s); err != nil {
		t.Fatal(err)
	}
	// Every one of them holds work newer than the turn start, so only the count decides.
	var names []string
	for i := 0; i < maxFallbackRepos+1; i++ {
		n := "r" + strconv.Itoa(i)
		repo := seedRepoAt(t, filepath.Join(ws, n), "app.py", "x = 1\n")
		appendTo(t, filepath.Join(repo, "app.py"), "import requests\n")
		names = append(names, n)
	}

	changes, ok, _, info, err := ChangedFilesWithInfo(ws, s)
	if err != nil {
		t.Fatal(err)
	}
	if ok || len(changes) != 0 {
		t.Errorf("reviewed %d file(s) across %d candidate repos; with none named, the turn "+
			"must review nothing", len(changes), len(names))
	}
	if len(info.HeadAnchored) != 0 {
		t.Errorf("HeadAnchored = %v, want none", info.HeadAnchored)
	}
	// ⚠️ AND IT MUST SAY WHAT IT DECLINED. Reviewing nothing silently is the original
	// bug: the developer is told the turn went unreviewed and nothing says which folder
	// to open.
	if len(info.HeadDeclined) != len(names) {
		t.Errorf("HeadDeclined = %v, want all %d candidates named", info.HeadDeclined, len(names))
	}
}

// TestWorkInARepoFromBeforeTheTurnIsNotReviewed is the regression on the live incident of
// 2026-08-25, and it is the difference between a last resort and a home-directory sweep.
//
// A Copilot turn that wrote NOTHING reviewed four unrelated checkouts under ~/Documents —
// leolearn-aikido, leoprevent, leoprevent-dashfilter, leoprevent-daterange — raised ten
// findings out of other people's work in progress, and BLOCKED the turn for 71 seconds.
// "Dirty and within two levels" was the whole test, and in a parent-of-checkouts
// directory that is true of almost everything. Modification time is the only signal
// available (nothing named a path — that is the premise of the fallback) and it is the
// right one: work left uncommitted yesterday is not what this turn did.
func TestWorkInARepoFromBeforeTheTurnIsNotReviewed(t *testing.T) {
	needGit(t)
	base := t.TempDir()
	ws := filepath.Join(base, "ws")
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	repo := seedRepoAt(t, filepath.Join(ws, "someone-elses-checkout"), "app.py", "x = 1\n")
	appendTo(t, filepath.Join(repo, "app.py"), "import subprocess\n")
	// Uncommitted, but stamped well before the turn begins.
	old := time.Now().Add(-24 * time.Hour)
	if err := os.Chtimes(filepath.Join(repo, "app.py"), old, old); err != nil {
		t.Fatal(err)
	}

	s := session(t, "vcs-stale-dirty")
	if err := CaptureBaseline(ws, s); err != nil { // records only the turn-start marker
		t.Fatal(err)
	}

	changes, ok, _, info, err := ChangedFilesWithInfo(ws, s)
	if err != nil {
		t.Fatal(err)
	}
	if ok || len(changes) != 0 {
		t.Errorf("reviewed %v; a repository whose only uncommitted work predates the turn "+
			"must not be reviewed", paths(changes))
	}
	if len(info.HeadAnchored) != 0 {
		t.Errorf("HeadAnchored = %v, want none", info.HeadAnchored)
	}
	// Nor named: nothing here is this turn's, so there is nothing to tell the developer.
	if len(info.HeadDeclined) != 0 {
		t.Errorf("HeadDeclined = %v, want none", info.HeadDeclined)
	}
}

// TestWorkInARepoDuringTheTurnIsStillReviewed is the other half — the gate must not shut
// the feature off. A single repository holding work newer than the turn start is exactly
// the case the fallback exists for.
func TestWorkInARepoDuringTheTurnIsStillReviewed(t *testing.T) {
	needGit(t)
	base := t.TempDir()
	ws := filepath.Join(base, "ws")
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	repo := seedRepoAt(t, filepath.Join(ws, "proj"), "app.py", "x = 1\n")
	s := session(t, "vcs-fresh-dirty")
	if err := CaptureBaseline(ws, s); err != nil {
		t.Fatal(err)
	}
	// Written AFTER the marker, which is what makes it this turn's work.
	appendTo(t, filepath.Join(repo, "app.py"), "import requests\n")
	future := time.Now().Add(time.Second)
	if err := os.Chtimes(filepath.Join(repo, "app.py"), future, future); err != nil {
		t.Fatal(err)
	}

	changes, ok, skip, info, err := ChangedFilesWithInfo(ws, s)
	if err != nil || !ok {
		t.Fatalf("expected a review, got ok=%v skip=%q err=%v", ok, skip, err)
	}
	if len(changes) != 1 || len(info.HeadAnchored) != 1 {
		t.Errorf("changes=%v HeadAnchored=%v, want one of each", paths(changes), info.HeadAnchored)
	}
}
