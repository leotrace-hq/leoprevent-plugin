package vcs

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
	"github.com/leotrace-hq/leoprevent-plugin/limits"
)

// TestStaleBaselinesGCedOnStopPath pins NIT-3: baselines older than the TTL are
// garbage-collected, and the sweep fires on the STOP path (ChangedFiles) for ANY
// cwd — including a non-git one — not only at turn-start in a git repo. This is
// the exact condition a Stop-only invocation hits; before the fix the sweep ran
// solely in CaptureBaseline, so a planted stale file survived a Stop hook.
func TestStaleBaselinesGCedOnStopPath(t *testing.T) {
	dir := filepath.Join(os.TempDir(), "leoprevent-baselines")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(dir, "gc-test-"+sanitize(t.Name()))
	if err := os.WriteFile(stale, []byte("ref\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(stale) })
	past := time.Now().Add(-48 * time.Hour) // well past the 6h cutoff
	if err := os.Chtimes(stale, past, past); err != nil {
		t.Fatal(err)
	}

	// A Stop-path call with a NON-git cwd must still trigger the sweep.
	_, _, _, _ = ChangedFiles(t.TempDir(), "unrelated-session")

	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Errorf("stale baseline was not GC'd on the Stop path (err=%v)", err)
	}
}

// gitRun runs a git command in dir, failing the test on error.
func gitRun(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

// initRepo makes a temp git repo with one committed file and returns its path.
// The session ID is unique per test and its scratch file is cleaned up.
func initRepo(t *testing.T) (dir, session string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir = t.TempDir()
	// -b names the initial branch, so a test that checks one out is not at the mercy of
	// the machine's init.defaultBranch: on a developer with that set to main, the mid-turn
	// checkout test fails locally while passing on runners that still default to master.
	gitRun(t, dir, "init", "-q", "-b", "master")
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte("import os\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-q", "-m", "init")
	session = sanitize(t.Name())
	t.Cleanup(func() { _ = os.Remove(scratchPath(session)) })
	return dir, session
}

// aliased converts ChangedFiles' result into the local mirror type the assertions use.
func aliased(got []transcript.Change) []changeAlias {
	out := make([]changeAlias, len(got))
	for i, c := range got {
		out[i] = changeAlias{c.FilePath, c.AddedText, c.FullContent}
	}
	return out
}

func findChange(changes []changeAlias, path string) (changeAlias, bool) {
	for _, c := range changes {
		if c.FilePath == path {
			return c, true
		}
	}
	return changeAlias{}, false
}

// changeAlias mirrors transcript.Change so the test can read fields without the
// import cycle gymnastics (it's the same struct shape).
type changeAlias = struct {
	FilePath    string
	AddedText   string
	FullContent string
}

func TestNormalizeOrigin(t *testing.T) {
	cases := map[string]string{
		"https://github.com/acme/app.git":            "github.com/acme/app",
		"https://github.com/acme/app":                "github.com/acme/app",
		"https://user:token@github.com/acme/app.git": "github.com/acme/app", // credentials stripped
		"git@github.com:acme/app.git":                "github.com/acme/app", // scp-like
		"ssh://git@gitlab.com/org/team/repo.git":     "gitlab.com/org/team/repo",
		"":                                           "",
	}
	for in, want := range cases {
		if got := normalizeOrigin(in); got != want {
			t.Errorf("normalizeOrigin(%q) = %q, want %q", in, got, want)
		}
	}
}

// A LOCAL FILESYSTEM PATH is a valid git remote (clone from a local mirror or a
// sibling worktree) but is NOT a shareable app identity — and a home directory
// embeds the developer's USERNAME. Since `repo` egresses as metadata on every cloud
// turn (including /telemetry) and is documented as a normalized, non-PII identifier,
// a path must normalize to "" rather than pass through verbatim.
//
// Observed in production: a review event recorded
// repo="/Users/<username>/Documents/leoprevent".
func TestNormalizeOriginRejectsLocalPaths(t *testing.T) {
	cases := []string{
		"/Users/alice/Documents/leoprevent", // POSIX absolute (the observed case)
		"/home/bob/src/app",                 //
		"/Users/alice/Documents/app.git",    // .git suffix must not make it look remote
		"~/src/app",                         // home-relative
		"./sibling-clone",                   // explicitly relative
		"../sibling-clone",                  //
		`C:\Users\alice\src\app`,            // Windows drive
		"C:/Users/alice/src/app",            // Windows drive, forward slashes
		`\\fileserver\share\app`,            // UNC
		"file:///Users/alice/src/app",       // local path as a URL
		"file:///Users/alice/src/app.git",   //
	}
	for _, in := range cases {
		if got := normalizeOrigin(in); got != "" {
			t.Errorf("normalizeOrigin(%q) = %q, want \"\" — a local path is not an app identity "+
				"and can egress the developer's username", in, got)
		}
	}
}

// Guard the other direction: a half-parseable value must not become a bogus
// identifier that fragments per-app rollups.
func TestNormalizeOriginRejectsNonHosts(t *testing.T) {
	cases := []string{
		"github.com",      // host with no path — not a repo
		"acme/app",        // path with no host
		"mirror:acme/app", // bare internal alias, not attributable across developers
		"   ",             // whitespace only
	}
	for _, in := range cases {
		if got := normalizeOrigin(in); got != "" {
			t.Errorf("normalizeOrigin(%q) = %q, want \"\"", in, got)
		}
	}
}

// Real remotes must keep working — the tightening must not cost a legitimate identity.
func TestNormalizeOriginKeepsRealRemotes(t *testing.T) {
	cases := map[string]string{
		"https://github.com/acme/app.git":           "github.com/acme/app",
		"git@github.com:acme/app.git":               "github.com/acme/app",
		"ssh://git@gitlab.com/org/team/repo.git":    "gitlab.com/org/team/repo",
		"https://dev.azure.com/org/proj/_git/repo":  "dev.azure.com/org/proj/_git/repo",
		"git@bitbucket.org:team/repo.git":           "bitbucket.org/team/repo",
		"https://git.internal.corp.net/infra/tools": "git.internal.corp.net/infra/tools",
		// A URL keeps its :port verbatim (only the scp-like form rewrites a colon).
		"http://localhost:7990/scm/proj/repo.git":   "localhost:7990/scm/proj/repo",
		"https://git.corp.net:8443/infra/tools":     "git.corp.net:8443/infra/tools",
		"https://user:tok@github.enterprise.io/a/b": "github.enterprise.io/a/b",
	}
	for in, want := range cases {
		if got := normalizeOrigin(in); got != want {
			t.Errorf("normalizeOrigin(%q) = %q, want %q", in, got, want)
		}
	}
}

// EMPTY-CWD GUARD. `git -C ""` is a silent NO-OP — git runs in the HOOK PROCESS's own
// working directory instead of erroring. Before the guard, RepoOrigin("") returned
// whatever repo the test binary happened to sit in (here: leoprevent's own), which in
// production means a turn gets filed under a repo the developer never touched.
//
// This test runs from inside a git repo (the package's own source tree), so it fails
// against the unguarded implementation and passes only when the empty cwd is refused.
func TestGitRefusesEmptyCwd(t *testing.T) {
	if got := RepoOrigin(""); got != "" {
		t.Errorf("RepoOrigin(\"\") = %q, want \"\" — an empty cwd must not resolve to "+
			"whatever repo the hook process is sitting in (silent misattribution)", got)
	}
	if got := RepoRoot(""); got != "" {
		t.Errorf("RepoRoot(\"\") = %q, want \"\"", got)
	}
	if got := Developer(""); got != "" {
		t.Errorf("Developer(\"\") = %q, want \"\"", got)
	}
	if isGitRepo("") {
		t.Error("isGitRepo(\"\") = true — an empty cwd is not a repo")
	}

	// Whitespace-only is the same case (a stdin field of " " is not a directory).
	if got := RepoOrigin("   "); got != "" {
		t.Errorf("RepoOrigin(\"   \") = %q, want \"\"", got)
	}
}

// The guard must degrade the change-capture paths the way "not a git repo" already
// does — no baseline, no changes, no panic — so the engine falls back to the
// transcript parser instead of diffing an unrelated tree.
func TestEmptyCwdDegradesChangeCapture(t *testing.T) {
	const session = "empty-cwd-session"
	t.Cleanup(func() { _ = os.Remove(scratchPath(session)) })

	// CaptureBaseline already returns nil early for an empty cwd (a no-op, not an
	// error — the caller only warns). What matters is that NO baseline is recorded,
	// so a later Stop can't diff against another repo's tree.
	if err := CaptureBaseline("", session); err != nil {
		t.Errorf("CaptureBaseline with an empty cwd should be a silent no-op, got %v", err)
	}
	if _, err := os.Stat(scratchPath(session)); !os.IsNotExist(err) {
		t.Error("an empty cwd must NOT write a baseline — it would belong to whatever repo the process sits in")
	}

	changes, ok, _, _ := ChangedFiles("", session)
	if ok {
		t.Errorf("ChangedFiles with an empty cwd must not claim a usable git baseline (got %d changes)", len(changes))
	}
}

// End-to-end through git: a repo whose origin is a local clone source must report no
// repo identity at all.
func TestRepoOriginLocalRemoteYieldsNothing(t *testing.T) {
	dir, _ := initRepo(t)
	gitRun(t, dir, "remote", "add", "origin", t.TempDir()) // a real local path remote
	if got := RepoOrigin(dir); got != "" {
		t.Errorf("RepoOrigin with a local-path remote = %q, want \"\" (would egress a filesystem path)", got)
	}
}

func TestRepoOriginAndDeveloper(t *testing.T) {
	dir, _ := initRepo(t)
	gitRun(t, dir, "remote", "add", "origin", "https://user:tok@github.com/acme/payments.git")
	gitRun(t, dir, "config", "user.name", "Ada Lovelace")
	gitRun(t, dir, "config", "user.email", "ada@acme.com")

	if got := RepoOrigin(dir); got != "github.com/acme/payments" {
		t.Errorf("RepoOrigin = %q (credentials must be stripped, .git trimmed)", got)
	}
	if got := Developer(dir); got != "Ada Lovelace <ada@acme.com>" {
		t.Errorf("Developer = %q", got)
	}
}

func TestRepoOriginEmptyWhenNoRemote(t *testing.T) {
	dir, _ := initRepo(t)
	if got := RepoOrigin(dir); got != "" {
		t.Errorf("RepoOrigin with no origin = %q, want empty", got)
	}
}

func TestCaptureAndChangedFiles(t *testing.T) {
	dir, session := initRepo(t)

	if err := CaptureBaseline(dir, session); err != nil {
		t.Fatalf("CaptureBaseline: %v", err)
	}

	// Modify a tracked file by writing the file DIRECTLY (no tool_use block) —
	// this is exactly the Bash-write path the transcript parser cannot see.
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte("import os\nx = requests.get(url)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// And create a brand-new untracked file.
	if err := os.WriteFile(filepath.Join(dir, "new.py"), []byte("y = eval(z)\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, ok, _, err := ChangedFiles(dir, session)
	if err != nil || !ok {
		t.Fatalf("ChangedFiles ok=%v err=%v", ok, err)
	}
	changes := make([]changeAlias, len(got))
	for i, c := range got {
		changes[i] = changeAlias{c.FilePath, c.AddedText, c.FullContent}
	}

	app, found := findChange(changes, "app.py")
	if !found {
		t.Fatal("Bash-written tracked file app.py was not captured (the gap this closes)")
	}
	if !strings.Contains(app.AddedText, "requests.get(url)") {
		t.Errorf("app.py AddedText missing the added line: %q", app.AddedText)
	}
	if strings.Contains(app.AddedText, "import os") {
		t.Errorf("app.py AddedText should be ADDED lines only, not the pre-existing import: %q", app.AddedText)
	}
	if !strings.Contains(app.FullContent, "import os") || !strings.Contains(app.FullContent, "requests.get") {
		t.Errorf("app.py FullContent should be the whole file: %q", app.FullContent)
	}

	nw, found := findChange(changes, "new.py")
	if !found {
		t.Fatal("untracked new file new.py was not captured")
	}
	if !strings.Contains(nw.AddedText, "eval(z)") || !strings.Contains(nw.FullContent, "eval(z)") {
		t.Errorf("new.py not fully captured: added=%q full=%q", nw.AddedText, nw.FullContent)
	}
}

// TestChangedFilesFromSubdirectory is the monorepo/subdir review-bypass
// regression: when the agent's cwd is a SUBDIRECTORY of the git repo (not the
// repo root), `git diff --name-status` still returns repo-root-relative paths,
// but the per-file diff that computes AddedText must be run anchored at the repo
// root — otherwise the root-relative pathspec is read relative to the subdir,
// matches nothing, and AddedText comes back EMPTY. An empty AddedText is then
// classified inert and the change is SILENTLY skipped (no review). Here cwd is the
// subdir; AddedText must still carry the added line.
func TestChangedFilesFromSubdirectory(t *testing.T) {
	dir, session := initRepo(t)
	sub := filepath.Join(dir, "service")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "h.py"), []byte("import os\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-q", "-m", "add subdir file")

	// Capture + edit with the SUBDIRECTORY as cwd (the bug only fires off-root).
	if err := CaptureBaseline(sub, session); err != nil {
		t.Fatalf("CaptureBaseline: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sub, "h.py"), []byte("import os\nx = requests.get(url)\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, ok, _, err := ChangedFiles(sub, session)
	if err != nil || !ok {
		t.Fatalf("ChangedFiles ok=%v err=%v", ok, err)
	}
	changes := make([]changeAlias, len(got))
	for i, c := range got {
		changes[i] = changeAlias{c.FilePath, c.AddedText, c.FullContent}
	}
	h, found := findChange(changes, "service/h.py")
	if !found {
		t.Fatalf("subdir file service/h.py not captured; got %+v", changes)
	}
	if !strings.Contains(h.AddedText, "requests.get(url)") {
		t.Errorf("AddedText empty/missing under subdir cwd — the review-bypass bug: %q", h.AddedText)
	}
}

func TestNonGitRepoFallsBack(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir() // not a git repo
	_, ok, _, err := ChangedFiles(dir, "sess")
	if ok || err != nil {
		t.Errorf("non-git dir must signal fallback (ok=false), got ok=%v err=%v", ok, err)
	}
}

func TestNoBaselineFallsBack(t *testing.T) {
	dir, session := initRepo(t)
	// No CaptureBaseline call → no scratch file → must fall back.
	_, ok, _, err := ChangedFiles(dir, session)
	if ok || err != nil {
		t.Errorf("missing baseline must signal fallback (ok=false), got ok=%v err=%v", ok, err)
	}
}

func TestEmptyArgsAreNoops(t *testing.T) {
	if err := CaptureBaseline("", ""); err != nil {
		t.Errorf("CaptureBaseline with empty args should be a no-op, got %v", err)
	}
	if _, ok, _, _ := ChangedFiles("", ""); ok {
		t.Error("ChangedFiles with empty args must signal fallback")
	}
}

func TestCapBytes(t *testing.T) {
	// Under the cap: unchanged.
	if got := capBytes("hello", 80); got != "hello" {
		t.Errorf("under-cap mutated: %q", got)
	}
	// Over the cap: truncated to <= cap (before the marker) with a marker appended.
	big := strings.Repeat("x", 200)
	got := capBytes(big, 80)
	if !strings.HasSuffix(got, "[truncated]\n") {
		t.Errorf("over-cap not marked truncated: %q", got)
	}
	if !strings.HasPrefix(got, strings.Repeat("x", 80)) {
		t.Errorf("over-cap kept the wrong prefix")
	}
	// Rune safety: cutting a multibyte string must not split a rune (valid UTF-8).
	multi := strings.Repeat("é", 100) // 2 bytes each → cap mid-rune
	if !utf8ValidString(capBytes(multi, 81)) {
		t.Error("capBytes split a multibyte rune (invalid UTF-8)")
	}
}

// utf8ValidString is a tiny local validity check to avoid importing unicode/utf8
// in the test just for this.
func utf8ValidString(s string) bool {
	for _, r := range s {
		if r == 0xFFFD { // RuneError from an invalid byte sequence
			return false
		}
	}
	return true
}

func TestTotalBudgetCapsFullContent(t *testing.T) {
	dir, session := initRepo(t)
	if err := CaptureBaseline(dir, session); err != nil {
		t.Fatal(err)
	}
	// Create enough big files to exceed limits.MaxChangedTotalBytes: 6 × ~limits.MaxChangedFileBytes > limits.MaxChangedTotalBytes.
	body := strings.Repeat("a = 1\n", limits.MaxChangedFileBytes/6) // ~limits.MaxChangedFileBytes of real-ish lines
	for i := 0; i < 6; i++ {
		name := filepath.Join(dir, "big"+string(rune('A'+i))+".py")
		if err := os.WriteFile(name, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, ok, _, err := ChangedFiles(dir, session)
	if err != nil || !ok {
		t.Fatalf("ChangedFiles ok=%v err=%v", ok, err)
	}
	withFull, withoutFull := 0, 0
	for _, c := range got {
		if c.FullContent != "" {
			withFull++
		} else if c.AddedText != "" {
			withoutFull++ // budget exhausted → AddedText kept, FullContent dropped
		}
	}
	if withoutFull == 0 {
		t.Errorf("total-budget cap never engaged: %d files all carried FullContent", withFull)
	}
	// Every file must still be reviewed (AddedText present) even past the budget.
	if len(got) != 6 {
		t.Errorf("expected all 6 files reviewed, got %d", len(got))
	}
}

func TestNoCommitsYetRepo(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	gitRun(t, dir, "init", "-q")
	session := sanitize(t.Name())
	t.Cleanup(func() { _ = os.Remove(scratchPath(session)) })

	// Baseline on a repo with NO commits must not error and must record something.
	if err := CaptureBaseline(dir, session); err != nil {
		t.Fatalf("CaptureBaseline on no-commit repo: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "new.py"), []byte("x = requests.get(u)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, ok, _, err := ChangedFiles(dir, session)
	if err != nil || !ok {
		t.Fatalf("ChangedFiles on no-commit repo: ok=%v err=%v", ok, err)
	}
	found := false
	for _, c := range got {
		if c.FilePath == "new.py" {
			found = true
		}
	}
	if !found {
		t.Error("file created in a fresh (no-commit) repo was not captured")
	}
}

// TestNonASCIIAndSpacedPaths: git C-quotes non-ASCII / unusual paths by default,
// which would make us read a quoted filename, fail, and SILENTLY drop the file.
// core.quotePath=false must make these round-trip — both tracked and untracked.
func TestNonASCIIAndSpacedPaths(t *testing.T) {
	dir, session := initRepo(t)
	if err := CaptureBaseline(dir, session); err != nil {
		t.Fatal(err)
	}
	// A tracked file with a non-ASCII name (modified this turn).
	naive := filepath.Join(dir, "naïve.py")
	if err := os.WriteFile(naive, []byte("import os\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, dir, "add", "naïve.py")
	gitRun(t, dir, "commit", "-q", "-m", "naive")
	if err := CaptureBaseline(dir, session); err != nil { // re-baseline so the edit below is the diff
		t.Fatal(err)
	}
	if err := os.WriteFile(naive, []byte("import os\nx = requests.get(u)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// An untracked file with a space in its name (new this turn).
	if err := os.WriteFile(filepath.Join(dir, "my route.py"), []byte("y = eval(z)\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, ok, _, err := ChangedFiles(dir, session)
	if err != nil || !ok {
		t.Fatalf("ChangedFiles ok=%v err=%v", ok, err)
	}
	seen := map[string]bool{}
	for _, c := range got {
		seen[c.FilePath] = true
	}
	if !seen["naïve.py"] {
		t.Errorf("non-ASCII tracked file was dropped (quotePath bug): %+v", got)
	}
	if !seen["my route.py"] {
		t.Errorf("spaced untracked file was dropped: %+v", got)
	}
}

func TestGitignoredFileExcluded(t *testing.T) {
	dir, session := initRepo(t)
	if err := os.WriteFile(filepath.Join(dir, ".gitignore"), []byte("ignored.py\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, dir, "add", ".gitignore")
	gitRun(t, dir, "commit", "-q", "-m", "ignore")

	if err := CaptureBaseline(dir, session); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ignored.py"), []byte("secret = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, ok, _, _ := ChangedFiles(dir, session)
	if !ok {
		t.Fatal("expected git path")
	}
	for _, c := range got {
		if c.FilePath == "ignored.py" {
			t.Error("gitignored file must be excluded from review")
		}
	}
}

// TestPreexistingUntrackedNotReChurned is the churn-bug fix: a file that was
// ALREADY untracked at turn start, and that the agent does NOT touch this turn,
// must NOT be reported as changed (else leoprevent re-reviews it every turn and
// re-wakes the agent to "fix" a file it never touched). A different file the agent
// edits this turn is still caught.
func TestPreexistingUntrackedNotReChurned(t *testing.T) {
	dir, session := initRepo(t)
	// A pre-existing untracked (non-gitignored) file, sitting in the tree already.
	if err := os.WriteFile(filepath.Join(dir, "scratch.py"), []byte("x = requests.get(url)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := CaptureBaseline(dir, session); err != nil { // snapshots scratch.py's hash
		t.Fatal(err)
	}
	// This turn the agent edits a DIFFERENT file, never touching scratch.py.
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte("import os\ny = eval(z)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, ok, _, err := ChangedFiles(dir, session)
	if err != nil || !ok {
		t.Fatalf("ChangedFiles ok=%v err=%v", ok, err)
	}
	var scratchSeen, appSeen bool
	for _, c := range got {
		switch c.FilePath {
		case "scratch.py":
			scratchSeen = true
		case "app.py":
			appSeen = true
		}
	}
	if scratchSeen {
		t.Error("pre-existing untracked file untouched this turn must NOT be reviewed (the churn bug)")
	}
	if !appSeen {
		t.Error("the file the agent DID edit must still be reviewed")
	}
}

// TestNewUntrackedFileIsReviewed: a file the agent CREATES this turn (not in the
// baseline snapshot) is reviewed — the fix must not suppress real new work.
func TestNewUntrackedFileIsReviewed(t *testing.T) {
	dir, session := initRepo(t)
	if err := CaptureBaseline(dir, session); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "new.py"), []byte("y = eval(z)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, ok, _, err := ChangedFiles(dir, session)
	if err != nil || !ok {
		t.Fatalf("ChangedFiles ok=%v err=%v", ok, err)
	}
	found := false
	for _, c := range got {
		if c.FilePath == "new.py" {
			found = true
		}
	}
	if !found {
		t.Error("a file created this turn must be reviewed")
	}
}

// TestEditedUntrackedFileIsReviewed: a pre-existing untracked file the agent EDITS
// this turn (hash changes) IS reviewed — the fix skips unchanged ones only.
func TestEditedUntrackedFileIsReviewed(t *testing.T) {
	dir, session := initRepo(t)
	if err := os.WriteFile(filepath.Join(dir, "scratch.py"), []byte("x = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := CaptureBaseline(dir, session); err != nil {
		t.Fatal(err)
	}
	// The agent edits the previously-untracked file this turn.
	if err := os.WriteFile(filepath.Join(dir, "scratch.py"), []byte("x = 1\nz = requests.get(url)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, ok, _, err := ChangedFiles(dir, session)
	if err != nil || !ok {
		t.Fatalf("ChangedFiles ok=%v err=%v", ok, err)
	}
	found := false
	for _, c := range got {
		if c.FilePath == "scratch.py" {
			found = true
		}
	}
	if !found {
		t.Error("an untracked file the agent edited this turn must be reviewed")
	}
}

// TestPureRenameYieldsNoAddedLines pins the rename-misattribution fix: a file
// with pre-existing content that the agent merely `git mv`'d after the baseline
// must NOT render as 100% added. Before the fix the per-file diff's pathspec was
// limited to the NEW path, so git could not pair the rename with the old path's
// deletion — the moved file showed as fully added, AddedLines became 1..N, and
// every PRE-EXISTING vuln in it was classified INTRODUCED and force-fixed
// downstream (violating the safety invariant: only code the agent demonstrably
// wrote may be force-fixed). A pure rename must yield empty AddedText/AddedLines.
func TestPureRenameYieldsNoAddedLines(t *testing.T) {
	dir, session := initRepo(t)
	body := "import requests\n\ndef fetch(url):\n    # pre-existing sink, agent never touched it\n    return requests.get(url)\n"
	if err := os.WriteFile(filepath.Join(dir, "old.py"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, dir, "add", "old.py")
	gitRun(t, dir, "commit", "-q", "-m", "pre-existing file")

	if err := CaptureBaseline(dir, session); err != nil {
		t.Fatalf("CaptureBaseline: %v", err)
	}
	// The agent's only action this turn: move the file.
	gitRun(t, dir, "mv", "old.py", "moved.py")

	got, ok, _, err := ChangedFiles(dir, session)
	if err != nil || !ok {
		t.Fatalf("ChangedFiles ok=%v err=%v", ok, err)
	}
	var moved *struct {
		added string
		nums  []int
		full  string
	}
	for _, c := range got {
		if c.FilePath == "moved.py" {
			moved = &struct {
				added string
				nums  []int
				full  string
			}{c.AddedText, c.AddedLines, c.FullContent}
		}
		if c.FilePath == "old.py" {
			t.Errorf("deleted-side old path must not be reported: %+v", c)
		}
	}
	if moved == nil {
		t.Fatalf("renamed file moved.py not captured; got %+v", got)
	}
	if moved.added != "" {
		t.Errorf("pure rename must yield empty AddedText, got %q (pre-existing code misattributed as written this turn)", moved.added)
	}
	if len(moved.nums) != 0 {
		t.Errorf("pure rename must yield no AddedLines, got %v (would classify pre-existing vulns INTRODUCED)", moved.nums)
	}
	if !strings.Contains(moved.full, "requests.get(url)") {
		t.Errorf("FullContent must still be read from the new path: %q", moved.full)
	}
}

// TestRenameWithEditAddsOnlyEditedLines: a `git mv` followed by a light edit must
// report ONLY the edited lines — never 1..N of the moved file.
func TestRenameWithEditAddsOnlyEditedLines(t *testing.T) {
	dir, session := initRepo(t)
	body := "import requests\n\ndef fetch(url):\n    return requests.get(url)\n" // 4 lines
	if err := os.WriteFile(filepath.Join(dir, "old.py"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, dir, "add", "old.py")
	gitRun(t, dir, "commit", "-q", "-m", "pre-existing file")

	if err := CaptureBaseline(dir, session); err != nil {
		t.Fatalf("CaptureBaseline: %v", err)
	}
	gitRun(t, dir, "mv", "old.py", "moved.py")
	// Light edit after the move: append one line (line 5 of the new file).
	if err := os.WriteFile(filepath.Join(dir, "moved.py"), []byte(body+"extra = eval(z)\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, ok, _, err := ChangedFiles(dir, session)
	if err != nil || !ok {
		t.Fatalf("ChangedFiles ok=%v err=%v", ok, err)
	}
	found := false
	for _, c := range got {
		if c.FilePath != "moved.py" {
			continue
		}
		found = true
		if want := []int{5}; !reflect.DeepEqual(c.AddedLines, want) {
			t.Errorf("AddedLines = %v, want %v (only the edited line — never 1..N of a moved file)", c.AddedLines, want)
		}
		if c.AddedText != "extra = eval(z)\n" {
			t.Errorf("AddedText = %q, want only the appended line", c.AddedText)
		}
	}
	if !found {
		t.Fatalf("renamed+edited file moved.py not captured; got %+v", got)
	}
}

func TestIsBinary(t *testing.T) {
	if isBinary([]byte("package main\n\nfunc main() {}\n")) {
		t.Error("plain source must not be classified binary")
	}
	if isBinary([]byte("")) {
		t.Error("empty file must not be classified binary")
	}
	if !isBinary([]byte("MZ\x00\x00\x90compiled")) {
		t.Error("content with a NUL byte must be classified binary")
	}
	// NUL beyond the 8000-byte sample window is not scanned (matches git heuristic).
	big := append([]byte(strings.Repeat("a", 9000)), 0)
	if isBinary(big) {
		t.Error("NUL past the 8000-byte window should not flip the verdict")
	}
}

// The fallback used to be indistinguishable from a healthy turn: every bail returned
// (nil, false, nil), so "the UserPromptSubmit hook never recorded a baseline" and "the
// baseline existed and git lost it" produced identical evidence despite needing
// opposite fixes. These pin that each bail names itself.
func TestChangedFilesReportsWhyItFellBack(t *testing.T) {
	dir, session := initRepo(t)

	if _, ok, skip, _ := ChangedFiles("", session); ok || skip != SkipNoCwdOrSession {
		t.Errorf("empty cwd: ok=%v skip=%q, want SkipNoCwdOrSession", ok, skip)
	}
	if _, ok, skip, _ := ChangedFiles(dir, ""); ok || skip != SkipNoCwdOrSession {
		t.Errorf("empty session: ok=%v skip=%q, want SkipNoCwdOrSession", ok, skip)
	}
	if _, ok, skip, _ := ChangedFiles(t.TempDir(), session); ok || skip != SkipNotGitRepo {
		t.Errorf("non-git dir: ok=%v skip=%q, want SkipNotGitRepo", ok, skip)
	}
	// A git repo with no CaptureBaseline for this session — the "hook never ran" case,
	// which is what a broken install looks like.
	if _, ok, skip, _ := ChangedFiles(dir, "session-that-never-captured"); ok || skip != SkipNoBaselineFile {
		t.Errorf("no baseline: ok=%v skip=%q, want SkipNoBaselineFile", ok, skip)
	}
	// A baseline pointing at a commit git cannot resolve — the "baseline was GC'd" case.
	// Same visible symptom as the above, opposite fix, so it must report differently.
	if err := os.MkdirAll(filepath.Dir(scratchPath("gone")), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(scratchPath("gone"), []byte("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok, skip, _ := ChangedFiles(dir, "gone"); ok || skip != SkipBaselineGone {
		t.Errorf("unresolvable baseline: ok=%v skip=%q, want SkipBaselineGone", ok, skip)
	}

	// And the healthy path must report NO reason, or the dashboard would badge every
	// good turn as degraded.
	if err := CaptureBaseline(dir, session); err != nil {
		t.Fatal(err)
	}
	if _, ok, skip, err := ChangedFiles(dir, session); !ok || skip != "" || err != nil {
		t.Errorf("healthy path: ok=%v skip=%q err=%v, want ok with no reason", ok, skip, err)
	}
}

// A mid-turn `git checkout` imports somebody else's already-merged commits into the
// working tree, and the diff against the turn-start baseline reports them as this
// turn's work. That is not cosmetic: such a finding anchors inside AddedLines, so it
// classifies as INTRODUCED, and the re-wake tells the agent to fix introduced findings
// "directly, don't ask" — i.e. to edit a teammate's merged commit.
//
// Observed live: a mid-turn `git checkout -B <branch> origin/main` pulled in 28 files,
// and the review force-fix-flagged a permission file changed by another PR two hours
// earlier.
//
// The second half is the one that matters more: the agent's OWN work must survive the
// same pass. Every simpler fix ("re-baseline onto HEAD", "drop anything clean against
// HEAD") drops it, which is a missed vulnerability under a clean verdict.
func TestMidTurnCheckoutIsNotAttributedToTheAgent(t *testing.T) {
	dir, session := initRepo(t)

	// A colleague's work, already merged and published on a remote-tracking ref before
	// this turn starts.
	gitRun(t, dir, "checkout", "-q", "-b", "colleague")
	if err := os.WriteFile(filepath.Join(dir, "settings.json"), []byte("{\n  \"allow\": [\"everything\"]\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-q", "-m", "colleague: widen the allowlist")
	gitRun(t, dir, "update-ref", "refs/remotes/origin/main", "HEAD")
	gitRun(t, dir, "checkout", "-q", "master")

	// The turn begins on the OLD commit, which does not have the colleague's file.
	if err := CaptureBaseline(dir, session); err != nil {
		t.Fatal(err)
	}

	// Mid-turn, the agent moves the tree onto the published branch AND writes code of
	// its own on top.
	gitRun(t, dir, "checkout", "-q", "-B", "work", "refs/remotes/origin/main")
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte("import os\nos.system(cmd)\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	changes, ok, _, err := ChangedFiles(dir, session)
	if err != nil || !ok {
		t.Fatalf("ChangedFiles: ok=%v err=%v", ok, err)
	}
	if _, found := findChange(aliased(changes), "settings.json"); found {
		t.Error("attributed a colleague's already-published commit to this turn — a finding there would classify as INTRODUCED and be force-fixed")
	}
	if _, found := findChange(aliased(changes), "app.py"); !found {
		t.Error("dropped the agent's OWN edit, which is a missed review under a clean verdict")
	}
}

// The agent's own COMMIT is the case every simpler fix gets wrong: the file is clean
// against HEAD and its change is explained by history, so both "re-baseline onto HEAD"
// and "drop anything clean against HEAD" would skip it. It is not published, so it
// stays in scope here.
func TestAgentsOwnCommitStaysInScopeAcrossACheckout(t *testing.T) {
	dir, session := initRepo(t)
	gitRun(t, dir, "update-ref", "refs/remotes/origin/main", "HEAD")

	if err := CaptureBaseline(dir, session); err != nil {
		t.Fatal(err)
	}

	// The agent writes and commits, then switches branch — HEAD moves twice.
	gitRun(t, dir, "checkout", "-q", "-B", "work")
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte("import os\nos.system(cmd)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-q", "-m", "agent: add a shell call")

	changes, ok, _, err := ChangedFiles(dir, session)
	if err != nil || !ok {
		t.Fatalf("ChangedFiles: ok=%v err=%v", ok, err)
	}
	c, found := findChange(aliased(changes), "app.py")
	if !found {
		t.Fatal("the agent's own committed work went unreviewed")
	}
	if !strings.Contains(c.FullContent, "os.system(cmd)") {
		t.Errorf("reviewed the wrong content: %q", c.FullContent)
	}
}

// With the tree still on the commit it started on, nothing can have been imported, so
// the subtraction must not run at all — an ordinary turn keeps its every change.
func TestNoHistoryMoveLeavesTheChangeSetAlone(t *testing.T) {
	dir, session := initRepo(t)
	gitRun(t, dir, "update-ref", "refs/remotes/origin/main", "HEAD")
	if err := CaptureBaseline(dir, session); err != nil {
		t.Fatal(err)
	}
	// Revert app.py to exactly the published content: identical to origin/main, but
	// HEAD never moved, so this is the agent's edit and must still be reviewed.
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte("import os\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "new.py"), []byte("print(1)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	changes, ok, _, err := ChangedFiles(dir, session)
	if err != nil || !ok {
		t.Fatalf("ChangedFiles: ok=%v err=%v", ok, err)
	}
	if _, found := findChange(aliased(changes), "new.py"); !found {
		t.Error("dropped a file the agent created on a turn with no history move")
	}
}

// An older client's scratch file has no history header. The subtraction must then be
// skipped entirely rather than guessed at — reviewing more, never less.
func TestOldScratchWithoutAHistoryHeaderReviewsEverything(t *testing.T) {
	dir, session := initRepo(t)
	gitRun(t, dir, "update-ref", "refs/remotes/origin/main", "HEAD")
	if err := CaptureBaseline(dir, session); err != nil {
		t.Fatal(err)
	}
	// Rewrite the scratch in the OLD format: baseline ref only.
	data, rerr := os.ReadFile(scratchPath(session))
	if rerr != nil {
		t.Fatal(rerr)
	}
	first := strings.SplitN(string(data), "\n", 2)[0]
	if err := os.WriteFile(scratchPath(session), []byte(first+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	gitRun(t, dir, "checkout", "-q", "-B", "work")
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte("import os\nos.system(cmd)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	changes, ok, _, err := ChangedFiles(dir, session)
	if err != nil || !ok {
		t.Fatalf("ChangedFiles: ok=%v err=%v", ok, err)
	}
	if _, found := findChange(aliased(changes), "app.py"); !found {
		t.Error("an old-format scratch must disable the subtraction, not drop files")
	}
}
