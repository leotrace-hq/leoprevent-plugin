// Package vcs is the git-baseline capture path: the agent-agnostic way to learn
// what changed this turn. It replaces the transcript-scoped, tool-only view with
// a real working-tree diff, which closes the Bash gap (files written via sed -i,
// heredocs, git apply, generators or --fix formatters are NOT tool_use blocks,
// so the transcript never sees them, but git does) and lets the judge reason
// over whole files instead of just the added snippet.
//
// Mechanism (mirrors the upstream security-guidance plugin):
//
//  1. At turn start (UserPromptSubmit) CaptureBaseline snapshots the working
//     tree with `git stash create` and stores the resulting SHA in a per-session
//     scratch file. `stash create` records the tree WITHOUT touching it.
//  2. At Stop, ChangedFiles diffs the current tree against that baseline. For
//     TRACKED files the diff is turn-scoped (against a turn-start snapshot, not
//     the dirty tree at large), so it has clean provenance — the reason the old
//     whole-tree git diff was removed does not apply. `git stash create` does NOT
//     snapshot untracked files, so CaptureBaseline additionally records a content
//     hash of each untracked-but-not-ignored file (see snapshotUntracked); at Stop,
//     ChangedFiles skips the ones byte-identical to turn start, so a pre-existing
//     untracked file is no longer re-reviewed every turn — only files NEW or modified
//     this turn are reported.
//
// Fail-soft: a degraded case (not a git repo, no baseline recorded, a git
// error) makes ChangedFiles return ok=false so the caller falls back to the
// transcript parser. A repo with NO COMMITS yet is NOT a fallback case: the
// baseline degrades to git's empty-tree object, so the diff stays on the git
// path and reports every tracked file as fully added (see emptyTree below).
// Capture never returns a fatal error to the hook — the contract is fail-open.
package vcs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
	"github.com/leotrace-hq/leoprevent-plugin/limits"
)

// Whole-file context gather caps live in the limits package
// (limits.MaxChangedFileBytes / MaxChangedTotalBytes).

// Untracked-file snapshot caps (see snapshotUntracked / hashFile). The baseline
// records a content hash of each untracked file so ChangedFiles can tell a file
// the agent actually created/edited this turn from a pre-existing untracked file
// (which must NOT be re-reviewed every turn — that was the change-detection bug).
const (
	maxHashBytes         = 64 * 1024 // hash size + first 64KB per file (bounds per-file cost)
	maxUntrackedSnapshot = 1000      // pathological tree → snapshot the first N; the tail stays "new"
)

// emptyTree is git's well-known empty-tree object — the baseline for a repo with
// no commits yet, so the diff shows every tracked file as added.
const emptyTree = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"

// gitTimeout bounds each git invocation so a pathological repo can't blow the
// hook's deadline.
const gitTimeout = 10 * time.Second

// CaptureBaseline records the turn-start working-tree state for sessionID so a
// later ChangedFiles call can diff against it. A no-op (nil) when cwd is not a
// git repo — the Stop hook then falls back to the transcript. Errors are
// returned for logging only; the caller fails open regardless.
func CaptureBaseline(cwd, sessionID string) error {
	// GC stale baselines on every turn-start, BEFORE any early return, so the
	// scratch dir is swept even when this turn's cwd is empty or not a git repo.
	cleanupStale()
	if cwd == "" || sessionID == "" {
		return nil
	}
	if !isGitRepo(cwd) {
		return nil // not a git repo → no baseline; ChangedFiles will fall back
	}

	// `git stash create` captures tracked changes as a dangling commit without
	// modifying the working tree. Empty output means a clean tree → use HEAD.
	ref, _ := git(cwd, "stash", "create")
	ref = strings.TrimSpace(ref)
	if ref == "" {
		if head, err := git(cwd, "rev-parse", "HEAD"); err == nil {
			ref = strings.TrimSpace(head)
		} else {
			ref = emptyTree // no commits yet
		}
	}

	path := scratchPath(sessionID)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	// Line 1 = the baseline ref. Following lines = "hash\tpath" for each untracked
	// file, so ChangedFiles can skip pre-existing untracked files that didn't change.
	content := ref + "\n" + snapshotUntracked(cwd)
	return os.WriteFile(path, []byte(content), 0o600)
}

// snapshotUntracked records each untracked-but-not-ignored file with a content
// hash ("hash\tpath" per line). Best-effort: any git error yields "" (ChangedFiles
// then treats all untracked files as new — the prior behaviour, no regression).
func snapshotUntracked(cwd string) string {
	root, err := git(cwd, "rev-parse", "--show-toplevel")
	if err != nil {
		return ""
	}
	root = strings.TrimSpace(root)
	out, err := git(cwd, "ls-files", "--others", "--exclude-standard")
	if err != nil {
		return ""
	}
	var b strings.Builder
	n := 0
	for _, p := range strings.Split(strings.TrimSpace(out), "\n") {
		if p = strings.TrimSpace(p); p == "" {
			continue
		}
		if n >= maxUntrackedSnapshot {
			break
		}
		if h := hashFile(filepath.Join(root, p)); h != "" {
			fmt.Fprintf(&b, "%s\t%s\n", h, p)
			n++
		}
	}
	return b.String()
}

// hashFile returns a content fingerprint of path: the file size plus a hash of its
// first maxHashBytes. "" on any error → treated as changed (fails toward review).
func hashFile(path string) string {
	fi, err := os.Stat(path)
	if err != nil || fi.IsDir() {
		return ""
	}
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	fmt.Fprintf(h, "%d:", fi.Size()) // size in the digest catches a change past the cap that alters length
	if _, err := io.CopyN(h, f, maxHashBytes); err != nil && err != io.EOF {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// SkipReason explains why ChangedFiles found no usable git baseline. It exists
// because the fallback is INVISIBLE otherwise: the caller degrades to transcript
// parsing (losing full-file context, real line numbers and Bash-write detection)
// and nothing anywhere records which of the several causes fired. They need
// opposite fixes — "the UserPromptSubmit hook never recorded a baseline" is a
// broken install, while "the baseline existed and git lost it" is a GC'd dangling
// stash commit — so a bare "no baseline" line cannot be acted on.
type SkipReason string

const (
	SkipNoCwdOrSession SkipReason = "cwd or session id empty"
	SkipNotGitRepo     SkipReason = "not a git repo"
	SkipNoBaselineFile SkipReason = "no baseline recorded for this session (UserPromptSubmit hook did not run, or the scratch file was swept)"
	SkipEmptyBaseline  SkipReason = "baseline file empty"
	SkipNoRepoRoot     SkipReason = "git rev-parse --show-toplevel failed"
	SkipBaselineGone   SkipReason = "git diff against the baseline failed (the dangling stash commit was likely garbage-collected)"
)

// ChangedFiles returns the files changed since this session's baseline, each
// with its added lines (AddedText) and full current content (FullContent,
// capped). ok=false means "no usable git baseline" → the caller should fall back
// to the transcript parser, and skip says why. ok=true with an empty slice means git authoritatively
// saw no changes (allow the stop). Untracked-but-not-ignored files are included
// as fully-added.
func ChangedFiles(cwd, sessionID string) (changes []transcript.Change, ok bool, skip SkipReason, err error) {
	// Sweep stale baselines on the Stop path too — not just turn-start — so GC runs
	// on essentially every hook invocation regardless of event or git status. (The
	// active session's own baseline is fresh — rewritten this turn — so it's never
	// the one removed.) Belt-and-suspenders to the CaptureBaseline sweep.
	cleanupStale()
	if cwd == "" || sessionID == "" {
		return nil, false, SkipNoCwdOrSession, nil
	}
	if !isGitRepo(cwd) {
		return nil, false, SkipNotGitRepo, nil
	}
	data, rerr := os.ReadFile(scratchPath(sessionID))
	if rerr != nil {
		return nil, false, SkipNoBaselineFile, nil // no baseline recorded → fall back
	}
	// Line 1 is the baseline ref; the rest is the "hash\tpath" snapshot of files
	// that were ALREADY untracked at turn start (so we can skip the ones the agent
	// didn't touch). An old-format scratch (ref only) → empty map → prior behaviour.
	lines := strings.Split(string(data), "\n")
	baseline := strings.TrimSpace(lines[0])
	if baseline == "" {
		return nil, false, SkipEmptyBaseline, nil
	}
	baseUntracked := map[string]string{} // path → baseline content hash
	for _, ln := range lines[1:] {
		if tab := strings.IndexByte(ln, '\t'); tab > 0 {
			baseUntracked[strings.TrimSpace(ln[tab+1:])] = ln[:tab]
		}
	}
	root, rerr := git(cwd, "rev-parse", "--show-toplevel")
	if rerr != nil {
		return nil, false, SkipNoRepoRoot, nil
	}
	root = strings.TrimSpace(root)

	// Tracked changes since the baseline (name-status so we can skip deletions
	// and follow renames to the new path). -M forces rename detection even if the
	// user's config disables it (diff.renames=false), so a `git mv` reliably shows
	// up as "R…\told\tnew" — the pairing the per-file diff below depends on.
	nameStatus, derr := git(cwd, "diff", "--name-status", "-M", baseline)
	if derr != nil {
		return nil, false, SkipBaselineGone, nil // baseline unreadable (e.g. GC'd) → fall back
	}
	files := trackedFiles(nameStatus)

	// Untracked-but-not-ignored files (new files the diff against a tracked
	// baseline won't show). --exclude-standard honours .gitignore, so build
	// artifacts / node_modules are skipped.
	untracked, _ := git(cwd, "ls-files", "--others", "--exclude-standard")
	untrackedSet := map[string]bool{}
	for _, p := range strings.Split(strings.TrimSpace(untracked), "\n") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		// Skip a file that was ALREADY untracked at turn start AND is byte-identical
		// now — the agent didn't create or edit it this turn, so reviewing it would
		// be churn (it was wrongly reported as "added every turn"). A new file (not
		// in the snapshot) or a changed hash falls through and IS reviewed.
		if h, seen := baseUntracked[p]; seen && h != "" && h == hashFile(filepath.Join(root, p)) {
			continue
		}
		files = append(files, trackedFile{path: p})
		untrackedSet[p] = true
	}

	total := 0
	for _, tf := range files {
		p := tf.path
		fp := filepath.Join(root, p)
		// Skip symlinks: a malicious repo can commit a symlink (e.g. config.yaml ->
		// /etc/passwd, or -> ~/.ssh/id_rsa). os.ReadFile FOLLOWS it, which would egress
		// the link TARGET's content to the server as file context — out-of-repo data
		// exfiltration beyond the "only changed code leaves" contract. Lstat (no-follow)
		// lets us drop links and read only real in-repo files.
		if fi, lerr := os.Lstat(fp); lerr != nil || fi.Mode()&os.ModeSymlink != 0 {
			continue
		}
		full, rerr := os.ReadFile(fp)
		if rerr != nil {
			continue // unreadable / vanished → skip
		}
		// Skip binary (non-text) files: compiled artifacts (a `go build` output, a
		// .class/.o), images, archives, minified blobs, etc. They are NOT reviewable
		// source, and — unlike FullContent — a brand-new file's AddedText is the WHOLE
		// file (uncapped), so an 8–11MB binary here becomes an 8–11MB request body that
		// exceeds the server's body cap → 400 → the client fails open and the turn goes
		// UNREVIEWED. Dropping non-text files removes no real code while closing that
		// hole at the source. (Text files are never skipped here — only batched/bounded
		// downstream — so reviewable code is always sent.)
		// The skip is NEVER silent: an unreviewed file is a potential silent false
		// negative (UTF-16-encoded source matches this heuristic too, and a NUL byte
		// is a trivial way for generated code to exempt itself), so it lands in the
		// plugin log at ERROR — clearly visible, not buried.
		if isBinary(full) {
			if utf16BOM(full) {
				slog.Error("vcs: file SKIPPED — NOT reviewed: looks UTF-16-encoded (leoprevent reviews UTF-8 text only; re-save as UTF-8 to get it reviewed)", "path", p)
			} else {
				slog.Error("vcs: file SKIPPED — NOT reviewed: binary content (NUL byte in first 8KB; not reviewable source)", "path", p)
			}
			continue
		}
		var added string
		var addedNums []int
		if untrackedSet[p] {
			added = string(full) // brand-new file: everything is added
			// every line is new → 1..N (N = line count of the full file)
			n := len(strings.Split(strings.TrimRight(string(full), "\n"), "\n"))
			addedNums = make([]int, 0, n)
			for i := 1; i <= n; i++ {
				addedNums = append(addedNums, i)
			}
		} else {
			// p is repo-root-relative (git diff output is, regardless of cwd), but a
			// git pathspec resolves relative to the -C dir. Run this from `root`, NOT
			// cwd: under a subdirectory cwd the pathspec would otherwise be read as
			// cwd/p, match nothing, and yield an empty AddedText — which the inert
			// gate then treats as "nothing added" and SILENTLY skips review (the
			// monorepo/subdir review-bypass bug).
			//
			// For a RENAMED file the pathspec must cover BOTH the old and the new
			// path: limited to the new path alone, git cannot pair the rename with
			// the old path's deletion, so a `git mv`'d file renders as 100% added →
			// AddedLines = 1..N → every PRE-EXISTING vuln in a file the agent merely
			// MOVED would be classified INTRODUCED and force-fixed downstream
			// (violating the safety invariant: only code the agent demonstrably
			// wrote may be force-fixed). With both paths (and -M) git emits only the
			// genuinely-changed lines; a pure rename yields an empty AddedText,
			// which the inert gate deliberately fails TOWARD review.
			args := []string{"diff", "-M", baseline, "--"}
			if tf.oldPath != "" {
				args = append(args, tf.oldPath)
			}
			args = append(args, p)
			diff, _ := git(root, args...)
			added = addedLines(diff)
			addedNums = addedLineNumbers(diff)
		}
		ch := transcript.Change{FilePath: p, AddedText: added, AddedLines: addedNums}
		// FullContent is the surrounding context; cap per-file and in total so a
		// large change set can't blow the judge's token budget. Over-budget files
		// still carry AddedText, so they are reviewed — just without full context.
		if body := capBytes(string(full), limits.MaxChangedFileBytes); total+len(body) <= limits.MaxChangedTotalBytes {
			ch.FullContent = body
			total += len(body)
		}
		changes = append(changes, ch)
	}
	return changes, true, "", nil
}

// trackedFile is one reviewable entry from `git diff --name-status`: the current
// (new) path, plus — for a rename — the pre-move path, which the per-file diff
// needs in its pathspec so git can pair the rename instead of rendering the
// whole moved file as added.
type trackedFile struct {
	path    string // repo-root-relative current path (the file to read/review)
	oldPath string // non-empty only for a rename ("R<score>\told\tnew")
}

// trackedFiles extracts the reviewable files from `git diff --name-status`
// output, skipping deletions. A rename resolves to the new path but KEEPS the
// old one (see trackedFile). A copy ("C<score>\tsrc\tdst", only emitted under
// explicit --find-copies) deliberately keeps the plain new-path behavior — the
// copied content IS newly placed by the agent this turn, so reviewing it as
// fully added is correct.
func trackedFiles(nameStatus string) []trackedFile {
	var out []trackedFile
	for _, line := range strings.Split(strings.TrimSpace(nameStatus), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		status := fields[0]
		switch {
		case strings.HasPrefix(status, "D"): // deletion → nothing to review
			continue
		case strings.HasPrefix(status, "R"): // rename → new path, remember the old
			if len(fields) >= 3 {
				out = append(out, trackedFile{path: fields[2], oldPath: fields[1]})
			}
		case strings.HasPrefix(status, "C"): // copy → new path (content is newly placed)
			if len(fields) >= 3 {
				out = append(out, trackedFile{path: fields[2]})
			}
		default:
			if len(fields) >= 2 {
				out = append(out, trackedFile{path: fields[1]})
			}
		}
	}
	return out
}

// addedLines returns the added lines of a unified diff (lines starting with a
// single '+', excluding the '+++' file header), newline-joined.
func addedLines(diff string) string {
	var b strings.Builder
	for _, line := range strings.Split(diff, "\n") {
		if strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++") {
			b.WriteString(line[1:])
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// hunkHeaderRE captures the new-file starting line of a unified-diff hunk:
// "@@ -12,7 +34,9 @@" → 34. The count is optional ("@@ -0,0 +1 @@").
var hunkHeaderRE = regexp.MustCompile(`^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@`)

// addedLineNumbers returns the 1-based NEW-FILE line numbers of the '+' lines in a
// unified diff, walking each hunk from its header's new-file start. This is the
// POSITIONAL truth for "what did the agent add this turn" — unlike matching added
// CONTENT, it distinguishes two identical lines (a pre-existing line and an added
// copy of it), the copy-paste case where an agent mirrors an existing handler.
// Numbering matches FullContent (the after-image), so the server can test a finding's
// cited line directly.
func addedLineNumbers(diff string) []int {
	var nums []int
	newLine := 0 // 0 = before the first hunk
	for _, line := range strings.Split(diff, "\n") {
		if m := hunkHeaderRE.FindStringSubmatch(line); m != nil {
			newLine, _ = strconv.Atoi(m[1])
			continue
		}
		if newLine == 0 {
			continue // diff header (incl. +++ / ---) before any hunk
		}
		switch {
		case strings.HasPrefix(line, "+"): // added line → record + advance new-file counter
			nums = append(nums, newLine)
			newLine++
		case strings.HasPrefix(line, "-"): // removed → does NOT advance the new-file counter
		case strings.HasPrefix(line, `\`): // "\ No newline at end of file" → ignore
		case line == "": // trailing split artifact → ignore
		default: // context line (leading space) → advances the new-file counter
			newLine++
		}
	}
	return nums
}

// capBytes truncates s to at most n bytes on a rune boundary, appending a marker.
// isBinary reports whether b looks like a binary (non-text) file, using git's own
// heuristic: a NUL byte within the first 8000 bytes. UTF-8/ASCII source code never
// contains NUL bytes; the known misclassification is UTF-16-encoded source (NULs
// throughout — old PowerShell Out-File, Notepad "Unicode" saves), which is rare and
// loudly logged at the skip site rather than transcoded.
func isBinary(b []byte) bool {
	if len(b) > 8000 {
		b = b[:8000]
	}
	return bytes.IndexByte(b, 0) >= 0
}

// utf16BOM reports whether b starts with a UTF-16 byte-order mark (FF FE little-
// endian / FE FF big-endian) — the "this is text, just not UTF-8" case of isBinary,
// called out separately in the skip log so the developer knows re-saving as UTF-8
// gets the file reviewed.
func utf16BOM(b []byte) bool {
	return len(b) >= 2 && ((b[0] == 0xFF && b[1] == 0xFE) || (b[0] == 0xFE && b[1] == 0xFF))
}

func capBytes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "\n… [truncated]\n"
}

// utf8RuneStart reports whether b is the first byte of a UTF-8 rune.
func utf8RuneStart(b byte) bool { return b&0xC0 != 0x80 }

// isGitRepo reports whether cwd is inside a git work tree.
func isGitRepo(cwd string) bool {
	_, err := git(cwd, "rev-parse", "--is-inside-work-tree")
	return err == nil
}

// RepoRoot returns the absolute repo-root path for cwd (the toplevel of the git
// work tree), or "" when cwd is not in a git repo / git errors. It's the anchor the
// cross-file import resolver joins repo-relative changed-file paths against to read
// imported helpers. "" → the cloud tier skips import resolution (degraded, never an
// error), mirroring the ChangedFiles git-vs-fallback split.
func RepoRoot(cwd string) string {
	out, err := git(cwd, "rev-parse", "--show-toplevel")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// RepoOrigin returns the repo's origin remote, NORMALIZED to "host/org/repo" — the
// stable "app" identifier for analytics (same for every developer on the repo,
// unlike the local directory name). Any embedded credentials are stripped so a
// token never lands in a log.
//
// It returns "" whenever it cannot produce a genuine shared identifier: no origin,
// not a git repo, an EMPTY cwd (the hook stdin occasionally carries one, and
// `git -C ""` fails), or a remote that is a local filesystem path rather than a URL
// (see normalizeOrigin — such a path can embed the developer's username and would
// egress as metadata on every cloud turn). The field is optional everywhere, so an
// absent repo just means that turn isn't attributed to an app; the review proceeds
// either way.
func RepoOrigin(cwd string) string {
	out, err := git(cwd, "config", "--get", "remote.origin.url")
	if err != nil {
		return ""
	}
	return normalizeOrigin(out)
}

// normalizeOrigin reduces a git remote URL to "host/org/repo": it strips the
// scheme, any "user[:pass]@" credentials, and a trailing ".git", and rewrites the
// scp-like "git@host:org/repo" form. Returns "" for empty input.
//
// It returns "" for anything that is NOT a remote URL — most importantly a LOCAL
// FILESYSTEM PATH (`/Users/alice/src/app`, `C:\src\app`, `file:///…`), which git
// accepts as a perfectly valid remote (a clone from a local mirror or another
// worktree). Such a path is not a shared "app" identity, and worse, a developer's
// home directory embeds their USERNAME — and `repo` egresses as metadata on EVERY
// cloud turn (including `/telemetry`, which sends no code), then lands in the
// review-event log and both dashboards. `developer` is the field documented as
// carrying PII; `repo` is documented as a normalized, shareable identifier, so a
// local path leaking through here is unexpected PII egress, not just a cosmetic
// analytics wart.
//
// Failing to "" is the safe direction: the field is optional everywhere (an absent
// repo simply means that turn isn't attributed to an app), whereas a bogus value
// both fragments per-app rollups and egresses the path.
func normalizeOrigin(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	s = strings.TrimSuffix(s, ".git")
	if strings.Contains(s, "://") {
		// scheme://[user[:pass]@]host/path
		scheme := s[:strings.Index(s, "://")]
		s = s[strings.Index(s, "://")+3:]
		if at := strings.LastIndex(s, "@"); at >= 0 {
			s = s[at+1:]
		}
		// file:// is a local path wearing a URL costume — no host, nothing shareable.
		if strings.EqualFold(scheme, "file") {
			return ""
		}
		return validHostPath(s)
	}
	// scp-like: [user@]host:org/repo
	if at := strings.LastIndex(s, "@"); at >= 0 {
		s = s[at+1:]
	}
	// A local path has no "host:" part at all. Reject before the colon rewrite, which
	// would otherwise pass an absolute path straight through unchanged.
	if isLocalPath(s) {
		return ""
	}
	return validHostPath(strings.Replace(s, ":", "/", 1))
}

// isLocalPath reports whether s looks like a filesystem path rather than a remote.
// Covers POSIX absolute (`/src/app`), home-relative (`~/src/app`), explicitly
// relative (`./app`, `../app`), and Windows (`C:\src\app`, `\\server\share`).
func isLocalPath(s string) bool {
	switch {
	case s == "":
		return true
	case strings.HasPrefix(s, "/"), strings.HasPrefix(s, "~"):
		return true
	case strings.HasPrefix(s, "./"), strings.HasPrefix(s, "../"):
		return true
	case strings.HasPrefix(s, `\\`): // UNC share
		return true
	case len(s) >= 3 && s[1] == ':' && (s[2] == '\\' || s[2] == '/'):
		return true // Windows drive letter, e.g. C:\src or C:/src
	}
	return false
}

// validHostPath keeps only a "host/path" that actually names a host: it must have a
// path component, and the host (minus any ":port") must contain a dot or be
// "localhost". A bare word like "mirror" is an internal alias that means something
// different on each developer's machine, so it can't attribute across a team.
// Anything else yields "" rather than a half-parsed identifier.
func validHostPath(s string) string {
	s = strings.Trim(s, "/")
	host, path, ok := strings.Cut(s, "/")
	if !ok || host == "" || path == "" {
		return ""
	}
	// A self-hosted remote may carry a port (bitbucket on :7990, gitea on :3000).
	// Judge the hostname itself, not the "host:port" pair.
	if h, _, hasPort := strings.Cut(host, ":"); hasPort {
		host = h
	}
	if host == "localhost" || strings.Contains(host, ".") {
		return s
	}
	return ""
}

// Developer returns the configured git user as "Name <email>" — the attribution
// for analytics ("which engineer"). Falls back to whichever of name/email is set,
// or "" if neither (not a git repo / unconfigured).
func Developer(cwd string) string {
	name := gitConfig(cwd, "user.name")
	email := gitConfig(cwd, "user.email")
	switch {
	case name != "" && email != "":
		return name + " <" + email + ">"
	case name != "":
		return name
	case email != "":
		return "<" + email + ">"
	default:
		return ""
	}
}

// gitConfig reads a single git config value, "" on any error.
func gitConfig(cwd, key string) string {
	out, err := git(cwd, "config", "--get", key)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// git runs `git -C cwd <args...>` with a timeout and returns stdout.
//
// core.quotePath=false is essential: by default git C-quotes any path with a
// non-ASCII byte (e.g. `"na\303\257ve.py"`) in diff/ls-files output. We'd then
// read that quoted string as a literal filename, os.ReadFile would fail, and the
// changed file would be SILENTLY DROPPED from review (a false negative). Disabling
// it makes git emit raw UTF-8 paths that round-trip through ReadFile and pathspecs.
// An EMPTY cwd is REFUSED rather than passed to git. `git -C ""` is a silent NO-OP:
// git does not error, it simply runs in the HOOK PROCESS's own working directory —
// wherever the agent happened to launch it. Every result then describes some
// arbitrary repo instead of the developer's project:
//
//   - RepoOrigin returns ANOTHER REPO'S identity, so the turn is filed under the
//     wrong app in the dashboards (silent misattribution — worse than a blank, which
//     at least reads as "unknown").
//   - CaptureBaseline / ChangedFiles snapshot and diff the WRONG tree, so the review
//     sees files the agent never touched, or misses the ones it did.
//
// The hook stdin does occasionally carry no cwd, so this is a real path, not a
// theoretical one. Failing to an error makes every caller degrade the way it already
// handles "not a git repo": no baseline (transcript fallback), no repo identity, no
// import resolution. All of those are honest; a confident wrong answer is not.
var errNoCwd = errors.New("vcs: empty cwd — refusing to run git in the hook process's own directory")

func git(cwd string, args ...string) (string, error) {
	if strings.TrimSpace(cwd) == "" {
		return "", errNoCwd
	}
	ctx, cancel := context.WithTimeout(context.Background(), gitTimeout)
	defer cancel()
	full := append([]string{"-C", cwd, "-c", "core.quotePath=false"}, args...)
	out, err := exec.CommandContext(ctx, "git", full...).Output()
	return string(out), err
}

// scratchPath is the per-session baseline file under the OS temp dir.
func scratchPath(sessionID string) string {
	return filepath.Join(os.TempDir(), "leoprevent-baselines", sanitize(sessionID))
}

// ClearBaseline removes a session's baseline scratch file. Used by the CLI exec
// loop to clean up after a headless run; a no-op if the file is already gone.
func ClearBaseline(sessionID string) { _ = os.Remove(scratchPath(sessionID)) }

// sanitize maps a session ID to a safe filename.
func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			return r
		default:
			return '_'
		}
	}, s)
}

// cleanupStale best-effort removes baseline files older than a few hours so the
// scratch dir doesn't grow without bound. Errors are ignored.
func cleanupStale() {
	dir := filepath.Join(os.TempDir(), "leoprevent-baselines")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-6 * time.Hour)
	for _, e := range entries {
		info, err := e.Info()
		if err == nil && info.ModTime().Before(cutoff) {
			_ = os.Remove(filepath.Join(dir, e.Name()))
		}
	}
}
