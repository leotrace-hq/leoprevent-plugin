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
	"sort"
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

// Baseline scratch header keys, and the bound on how many remote tips are recorded.
//
// Both prefixes are deliberately TAB-FREE: the untracked snapshot below is parsed by
// looking for a tab, so a header line is invisible to that parser and an older client
// reads a newer scratch file without confusion.
const (
	baselineHeadPrefix = "#head "
	publishedTipPrefix = "#tip "
	// repoSectionPrefix introduces one repository's block in a WORKSPACE capture (cwd
	// is a folder holding projects rather than a project). Absent entirely from a
	// single-repo scratch, so that file is byte-identical to what earlier versions
	// wrote and this header is invisible to the untracked parser like the others.
	repoSectionPrefix = "#repo "
	// repoRootPrefix carries a discovered repository's ABSOLUTE directory. It exists
	// only in the per-session scratch on the developer's own machine and NEVER travels:
	// what reaches the server is the repo's basename plus the repo-relative path. An
	// absolute path on the wire would put the developer's home directory, and so their
	// username, into every ChangedFile.Path — the same reason normalizeOrigin refuses a
	// local-path remote.
	repoRootPrefix = "#root "
	// How far below a workspace folder to look for repositories, and how many to take.
	// Both bound work on the developer's turn-start path; overshooting either reviews
	// FEWER repos, never none, and never errors.
	// A repository with more remote branches than this gets no subtraction rather
	// than an unbounded walk on the developer's Stop path. Failing that way costs a
	// noisier review, never a missed one.
	maxPublishedTips = 64
	// How many of those tips are actually diffed at Stop. Only tips that are
	// ANCESTORS of the current HEAD can explain the tree's content, which in practice
	// is one or two; the cap bounds the pathological case.
	maxTipsDiffed = 8
)

// CaptureBaseline records the turn-start working-tree state for sessionID so a
// later ChangedFiles call can diff against it. Errors are returned for logging only;
// the caller fails open regardless.
//
// ⚠️ cwd IS THE FOLDER OPEN IN THE EDITOR, WHICH IS NOT ALWAYS THE PROJECT. It may be
// a folder HOLDING repositories rather than being one, and the agent may edit a project
// somewhere else on the filesystem entirely. Neither is visible from here, so this
// captures the cwd repository ALONE and RecordEditedRepo covers the rest at PreToolUse.
// That second case used to be a silent no-op, and on an agent with no transcript
// fallback it meant a developer's every turn went unreviewed while looking exactly like
// a quiet one.
func CaptureBaseline(cwd, sessionID string) error {
	// GC stale baselines on every turn-start, BEFORE any early return, so the
	// scratch dir is swept even when this turn's cwd is empty or not a git repo.
	cleanupStale()
	if cwd == "" || sessionID == "" {
		return nil
	}
	// ⚠️ DISCARD LAST TURN'S DISCOVERED REPOSITORIES. A baseline means "the state at the
	// start of THIS turn", and the cwd repository gets that by being re-captured here on
	// every prompt. A discovered repository had no such refresh: RecordEditedRepo skips a
	// root it has already recorded, and nothing cleared the directory, so its guard's
	// "already recorded this turn" was really "this SESSION" and the baseline froze at
	// first discovery.
	//
	// Everything the agent did in turn 1 therefore stayed in the diff for turns 2, 3, 4:
	// reported live as the plugin "flagging something every turn even when there are no
	// changes". Reproduced at three turns — turn 2 touched nothing and re-reviewed turn
	// 1's file; turn 3 reviewed both.
	//
	// Clearing here rather than refreshing each recorded repo is deliberate: the next
	// PreToolUse re-captures whichever repositories THIS turn actually touches, so a
	// repository the agent has finished with costs nothing, and a `git stash create` per
	// previously-seen repo per prompt is not paid for work nobody is doing. A repo edited
	// again gets a baseline that correctly includes turn 1's uncommitted work, so only
	// this turn's changes are reviewed.
	//
	// Safe for the re-wake: a block injects a message into the SAME turn, so no
	// UserPromptSubmit fires between the block and the guard Stop, and /outcome still
	// sees the baseline its review was computed against.
	_ = os.RemoveAll(discoveredDir(sessionID))
	// Line 1 = the baseline ref. Then the HISTORY header (see snapshotHistory), then
	// "hash\tpath" for each untracked file, so ChangedFiles can skip pre-existing
	// untracked files that didn't change. Header lines carry NO tab, which is what the
	// untracked parser keys on, so an older client's format is read unchanged and a
	// newer scratch is read safely by an older client.
	//
	// ⚠️ WHEN cwd IS NOT ITSELF A REPO the same block is written ONCE PER REPO beneath
	// it, each introduced by a `#repo <dir>` header. A single-repo capture writes NO
	// such header, so its bytes are IDENTICAL to what every prior version wrote — the
	// multi-repo shape is purely additive.
	// ⚠️ ONLY THE cwd REPOSITORY IS CAPTURED HERE, and a cwd that is not itself a repo
	// captures NOTHING. That is not a gap, it is the division of labour: a workspace
	// folder holding projects, or a project somewhere else on the filesystem entirely,
	// is discovered at PreToolUse instead (RecordEditedRepo), when the agent names the
	// file it is about to write and the repository is therefore knowable.
	//
	// `rev-parse --is-inside-work-tree` searches UP and never down, so nothing at turn
	// start can see those repositories — an earlier version walked DOWN from cwd, which
	// found a parent-of-projects layout but still missed anything not beneath cwd, and
	// cost a directory scan of a possibly-huge tree on every prompt.
	if !isGitRepo(cwd) {
		// Nothing to anchor on yet; PreToolUse discovers what gets edited. But RECORD
		// THE TURN START anyway: it is the only thing that tells the Stop-time HEAD
		// fallback which uncommitted work belongs to this turn and which was already
		// sitting there, and it costs one empty file with no git call. It also
		// distinguishes "UserPromptSubmit never ran" from "it ran and had nothing to
		// capture", which the skip reasons could not previously tell apart.
		markTurnStart(sessionID)
		return nil
	}
	// ⚠️ RECORD WHICH REPOSITORY THIS BASELINE IS FOR. cwd is the repo at PROMPT time,
	// and the agent can `cd` elsewhere mid-turn — Claude Code then reports the NEW cwd
	// on the Stop, so without this the ref captured in repo A would be diffed inside
	// repo B (repoBaseline.dir falls back to cwd), and RecordEditedRepo would skip
	// repo B as "already captured at UserPromptSubmit" when it never was. Appended
	// AFTER the block, so every existing byte is unchanged and an older client reads
	// it as the unrecognised header it ignores.
	content := captureRepo(cwd)
	if root := RepoRoot(cwd); root != "" {
		content += repoRootPrefix + root + "\n"
	}

	path := scratchPath(sessionID)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0o600)
}

// captureRepo is one repository's turn-start block: the baseline ref, the history
// header, and the untracked snapshot.
//
// `git stash create` captures tracked changes as a dangling commit without modifying
// the working tree. Empty output means a clean tree → use HEAD; no commits at all →
// the empty-tree object, so a fresh repo still diffs rather than falling back.
func captureRepo(dir string) string {
	ref, _ := git(dir, "stash", "create")
	ref = strings.TrimSpace(ref)
	if ref == "" {
		if head, err := git(dir, "rev-parse", "HEAD"); err == nil {
			ref = strings.TrimSpace(head)
		} else {
			ref = emptyTree // no commits yet
		}
	}
	return ref + "\n" + snapshotHistory(dir) + snapshotUntracked(dir)
}

// snapshotHistory records where the repository's HISTORY stood at turn start: the
// commit HEAD pointed at, and every remote-tracking tip.
//
// It is what lets ChangedFiles tell the agent's work from somebody else's. The diff
// against the baseline answers "what differs from turn start", which is deliberately
// blind to WHO wrote it — that blindness is the feature, and is why Bash writes,
// generators and `--fix` formatters are all caught. Its blind spot is a git operation
// that rewrites the tree FROM HISTORY (checkout, switch, pull, merge, rebase, reset),
// which imports other people's already-merged commits and presents them as this turn's
// work. Observed live: a mid-turn `git checkout -B <branch> origin/main` pulled 28
// files in, and the review force-fix-flagged a permission file changed by somebody
// else's PR two hours earlier.
//
// Best-effort by design: any git error yields "" and the subtraction is simply not
// attempted, which reviews MORE rather than less.
func snapshotHistory(cwd string) string {
	var b strings.Builder
	if head, err := git(cwd, "rev-parse", "HEAD"); err == nil {
		if h := strings.TrimSpace(head); h != "" {
			b.WriteString(baselineHeadPrefix + h + "\n")
		}
	}
	out, err := git(cwd, "for-each-ref", "--format=%(objectname)", "refs/remotes/")
	if err != nil {
		return b.String()
	}
	seen := map[string]bool{}
	for _, ln := range strings.Split(strings.TrimSpace(out), "\n") {
		sha := strings.TrimSpace(ln)
		if sha == "" || seen[sha] {
			continue
		}
		seen[sha] = true
		b.WriteString(publishedTipPrefix + sha + "\n")
		if len(seen) >= maxPublishedTips {
			break
		}
	}
	return b.String()
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
// BaselineInfo reports how this turn's baseline behaved, for the review event.
//
// It exists because the subtraction in dropImportedByHistory is the one step here that
// can REMOVE code from review, and an over-subtraction is silent by nature — the turn
// simply looks quieter. The client log names the dropped paths on the developer's own
// machine; these two fields are what make the same thing visible fleet-wide.
type BaselineInfo struct {
	// Head is the commit HEAD pointed at when the turn started, so a turn whose tree
	// moved through history can be reconstructed without the developer's reflog.
	Head string
	// ImportedDropped counts files excluded because their content was already
	// published before the turn — brought in by a checkout, pull, merge or rebase
	// rather than written by the agent.
	ImportedDropped int
	// HeadAnchored names the repositories reviewed against HEAD as a last resort,
	// because no baseline was captured for them (see headFallbackSections). Their
	// findings are SURFACED for the developer to decide on rather than applied in-turn,
	// and their diff mixes this turn's work
	// with anything already uncommitted — so a review carrying this is weaker evidence
	// than one anchored on a turn-start baseline, and every surface that shows it must
	// say so. Basenames, never absolute paths: the path is the developer's own machine.
	HeadAnchored []string
	// HeadDeclined names repositories that held work from this turn but were NOT
	// reviewed, because more than one candidate remained and nothing had named a path in
	// any of them — so which repository the turn was about is unknowable. Reported so
	// the developer is told what went unreviewed and which folder to open, rather than
	// being handed a HEAD diff of every candidate.
	HeadDeclined []string
}

// ChangedFiles is ChangedFilesWithInfo without the diagnostics, kept as the stable
// entry point for callers that do not report them.
func ChangedFiles(cwd, sessionID string) (changes []transcript.Change, ok bool, skip SkipReason, err error) {
	changes, ok, skip, _, err = ChangedFilesWithInfo(cwd, sessionID)
	return changes, ok, skip, err
}

func ChangedFilesWithInfo(cwd, sessionID string) (changes []transcript.Change, ok bool, skip SkipReason, info BaselineInfo, err error) {
	// GC stale baselines here too (not only at capture): the Stop hook fires on
	// essentially every hook invocation regardless of event or git status. The active
	// session's own baseline is fresh — rewritten this turn — so it's never swept.
	cleanupStale()
	if cwd == "" || sessionID == "" {
		return nil, false, SkipNoCwdOrSession, BaselineInfo{}, nil
	}
	var fallbackInfo BaselineInfo
	// Two sources, one format. The cwd repository's section comes from the file
	// UserPromptSubmit wrote; every repository the agent actually edited comes from the
	// per-repo files PreToolUse wrote. Concatenating them and parsing once means the
	// discovered repos travel through exactly the same code as the cwd one.
	data, rerr := os.ReadFile(scratchPath(sessionID))
	discovered := readDiscovered(sessionID)
	var sections []repoBaseline
	if rerr == nil || len(discovered) > 0 {
		if rerr != nil {
			data = nil
		}
		if len(data) > 0 && data[len(data)-1] != '\n' {
			data = append(data, '\n')
		}
		sections = disambiguateLabels(parseBaselines(append(data, discovered...)))
	}

	// Nothing usable was captured. Report WHY in the terms the event log has always
	// used, and keep the two causes apart, because they need OPPOSITE fixes: a folder
	// with no repository in reach is the developer's to change, whereas repositories
	// present with no baseline recorded means our UserPromptSubmit hook never ran.
	//
	// ⚠️ That second case only became REACHABLE from a non-repo cwd here. It used to be
	// masked: `isGitRepo` was tested first and short-circuited, so a workspace folder
	// always reported "not a git repo" whether or not the prompt hook had fired.
	if len(sections) == 0 {
		switch {
		case !isGitRepo(cwd):
			// LAST RESORT before declaring the turn unreviewed: a workspace folder whose
			// repositories were never named by a tool (a shell write to a computed
			// path). Anything found is HEAD-anchored and surfaced-only.
			fb, declined := headFallbackSections(cwd, sessionID, nil)
			if len(fb) > 0 {
				sections = disambiguateLabels(fb)
				fallbackInfo = BaselineInfo{HeadAnchored: labelsOf(sections)}
				break
			}
			// Several repositories held work from this turn and none was named, so none
			// was reviewed. Report them so the notice can say which, and which one to
			// open.
			return nil, false, SkipNotGitRepo, BaselineInfo{HeadDeclined: declined}, nil
		case rerr != nil:
			return nil, false, SkipNoBaselineFile, BaselineInfo{}, nil
		default:
			return nil, false, SkipEmptyBaseline, BaselineInfo{}, nil
		}
	}
	// A single-repo scratch anchored on a cwd that is no longer a repository (the
	// developer moved or re-opened the folder mid-session) cannot be diffed.
	single := len(sections) == 1 && sections[0].label == ""
	if single && !isGitRepo(cwd) {
		return nil, false, SkipNotGitRepo, BaselineInfo{}, nil
	}

	cc := changeCollector{}
	info.HeadAnchored = fallbackInfo.HeadAnchored
	for _, s := range sections {
		rs, dropped := cc.fromRepo(s.dir(cwd), s)
		if rs != "" {
			// One repository of several failed to diff (its dangling stash commit was
			// GC'd, say). Reviewing the others beats discarding the whole turn — but
			// this is a step that REMOVES code from review, so it is never silent.
			if single {
				return nil, false, rs, BaselineInfo{}, nil
			}
			slog.Error("vcs: repo SKIPPED — its changes were NOT reviewed this turn",
				"repo", s.label, "reason", string(rs))
			continue
		}
		info.ImportedDropped += dropped
	}
	// BaselineHead names ONE commit, so it is recorded only when there is one
	// repository to name. Across several it would silently describe whichever we
	// happened to walk first, and a confident wrong answer is worse than a blank.
	if single {
		info.Head = sections[0].head
	}
	return cc.changes, true, "", info, nil
}

// repoBaseline is one repository's turn-start snapshot, parsed back out of the
// scratch file.
//
// label is "" for the cwd repository, whose paths stay unqualified so a single-repo
// turn is byte-identical to every version before workspaces existed. For a repository
// DISCOVERED at PreToolUse it is the repo directory's basename, which is the only
// non-PII name available: such a repo need not be under cwd at all, so it has no
// cwd-relative name to use.
type repoBaseline struct {
	label     string
	root      string            // absolute repo dir; empty for the cwd repository
	ref       string            // the baseline commit/tree to diff against
	head      string            // HEAD at turn start (history subtraction)
	tips      []string          // remote-tracking tips at turn start
	untracked map[string]string // path → content hash, already untracked at turn start
	// headOnly marks a LAST-RESORT section discovered at Stop rather than baselined at
	// turn start: its ref is HEAD, so its diff mixes this turn's work with whatever was
	// already uncommitted. See headFallbackSections.
	headOnly bool
}

// parseBaselines reads the scratch file into one entry per repository.
//
// A file with NO `#repo` header is a single-repo capture in the original format:
// line 1 is the ref, the rest is headers plus the "hash\tpath" untracked snapshot.
// That shape is parsed exactly as it always was, so an existing session's scratch
// keeps working across a plugin update.
//
// Unknown "#" headers are skipped rather than read as a ref, so a future addition to
// the format degrades to "this section has no baseline" instead of diffing against a
// nonsense revision.
func parseBaselines(data []byte) []repoBaseline {
	var out []repoBaseline
	cur := -1 // index into out, NOT a pointer: append may reallocate
	for _, ln := range strings.Split(string(data), "\n") {
		if tab := strings.IndexByte(ln, '\t'); tab > 0 {
			if cur >= 0 {
				out[cur].untracked[strings.TrimSpace(ln[tab+1:])] = ln[:tab]
			}
			continue
		}
		switch {
		case strings.HasPrefix(ln, repoSectionPrefix):
			if lbl := strings.TrimSpace(strings.TrimPrefix(ln, repoSectionPrefix)); lbl != "" {
				out = append(out, repoBaseline{label: lbl, untracked: map[string]string{}})
				cur = len(out) - 1
			}
		case strings.HasPrefix(ln, repoRootPrefix):
			if cur >= 0 {
				out[cur].root = strings.TrimSpace(strings.TrimPrefix(ln, repoRootPrefix))
			}
		case strings.HasPrefix(ln, baselineHeadPrefix):
			if cur >= 0 {
				out[cur].head = strings.TrimSpace(strings.TrimPrefix(ln, baselineHeadPrefix))
			}
		case strings.HasPrefix(ln, publishedTipPrefix):
			if sha := strings.TrimSpace(strings.TrimPrefix(ln, publishedTipPrefix)); sha != "" && cur >= 0 {
				out[cur].tips = append(out[cur].tips, sha)
			}
		case strings.HasPrefix(ln, "#"):
			// An unrecognised header from a newer client: ignore, never read as a ref.
		default:
			v := strings.TrimSpace(ln)
			if v == "" {
				continue
			}
			if cur < 0 { // original single-repo format: line 1 is the ref
				out = append(out, repoBaseline{untracked: map[string]string{}})
				cur = 0
			}
			if out[cur].ref == "" {
				out[cur].ref = v
			}
		}
	}
	// A section whose ref never materialised cannot be diffed against.
	kept := out[:0]
	for _, s := range out {
		if s.ref != "" {
			kept = append(kept, s)
		}
	}
	return kept
}

// changeCollector accumulates the turn's changes across every repository.
//
// The FullContent byte budget is deliberately SHARED rather than per-repo: it exists
// to bound one review request, and a workspace of eight projects must not be able to
// send eight times the context a single project can.
type changeCollector struct {
	changes []transcript.Change
	total   int
}

// fromRepo diffs one repository against its turn-start baseline and appends what it
// finds. It returns a SkipReason when the repository could not be diffed at all, plus
// the number of files dropped as already-published history.
//
// ⚠️ EMITTED PATHS ARE PREFIXED WITH THE REPOSITORY'S DIRECTORY in a workspace
// capture. Git reports paths relative to ITS OWN root, so two projects each holding a
// src/app.py would otherwise be indistinguishable downstream: the judge would cite a
// location matching two files, the re-wake would tell the agent to fix "src/app.py"
// without saying which, and the outcome loop would key both onto one entry. With one
// repository the prefix is empty, so paths are byte-identical to before.
func (cc *changeCollector) fromRepo(dir string, s repoBaseline) (SkipReason, int) {
	root, rerr := git(dir, "rev-parse", "--show-toplevel")
	if rerr != nil {
		return SkipNoRepoRoot, 0
	}
	root = strings.TrimSpace(root)

	// Tracked changes since the baseline (name-status so we can skip deletions
	// and follow renames to the new path). -M forces rename detection even if the
	// user's config disables it (diff.renames=false), so a `git mv` reliably shows
	// up as "R…\told\tnew" — the pairing the per-file diff below depends on.
	nameStatus, derr := git(dir, "diff", "--name-status", "-M", s.ref)
	if derr != nil {
		return SkipBaselineGone, 0 // baseline unreadable (e.g. GC'd) → fall back
	}
	files := trackedFiles(nameStatus)

	// Untracked-but-not-ignored files (new files the diff against a tracked
	// baseline won't show). --exclude-standard honours .gitignore, so build
	// artifacts / node_modules are skipped.
	untracked, _ := git(dir, "ls-files", "--others", "--exclude-standard")
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
		if h, seen := s.untracked[p]; seen && h != "" && h == hashFile(filepath.Join(root, p)) {
			continue
		}
		files = append(files, trackedFile{path: p})
		untrackedSet[p] = true
	}

	before := len(files)
	files = dropImportedByHistory(dir, files, s.head, s.tips)
	dropped := before - len(files)

	// One root handle for the whole repository: every read below is bounded by it, so
	// a path escaping the repo is refused by the OS rather than by a check of ours.
	// Opened once rather than per file — it is a directory descriptor, and on most
	// platforms it keeps referencing the right directory even if the tree is moved
	// mid-turn.
	rootDir, rootErr := os.OpenRoot(root)
	if rootErr != nil {
		return SkipNoRepoRoot, dropped
	}
	defer rootDir.Close()

	for _, tf := range files {
		p := tf.path
		// ⚠️ OPEN FIRST, THEN PROVE WHAT WAS OPENED. A repository can commit a symlink
		// (config.yaml -> /etc/passwd, or -> ./.env), and following one would egress a
		// file the developer never changed: out of the repo entirely, or in-repo but
		// deliberately excluded by gate.IsSecretPath, which matches on the PATH and so
		// never sees the target behind a link.
		//
		// The ORDER is the point, and an earlier version of this had it backwards.
		// Lstat-then-open is check-then-use: between the two calls the file can be
		// swapped for an in-repo symlink, which os.Root then follows because it stays
		// within the root — so the symlink guard was bypassable exactly when it mattered.
		// (LeoPrevent's own review caught that on this PR.)
		//
		// Reading from the descriptor we already hold is what removes the window: the
		// bytes come from the file we opened, whatever the path is swapped to afterwards.
		// SameFile then proves that descriptor was NOT reached through a link — Lstat
		// describes the link itself and Stat describes its target, so a symlink gives
		// two different files and is rejected. It fails toward skipping, which costs an
		// unreviewed file rather than an egressed one.
		//
		// NB the suggested `f.Stat()` mode test cannot work here: opening has already
		// resolved the link, so the mode is the TARGET's and ModeSymlink is never set.
		f, readErr := rootDir.Open(filepath.FromSlash(p))
		if readErr != nil {
			continue // unreadable / vanished / escapes the repo → skip
		}
		opened, statErr := f.Stat()
		onDisk, lstatErr := rootDir.Lstat(filepath.FromSlash(p))
		if statErr != nil || lstatErr != nil || !os.SameFile(opened, onDisk) {
			f.Close()
			continue // reached via a symlink, or we cannot prove it wasn't
		}
		full, readErr := io.ReadAll(f)
		f.Close()
		if readErr != nil {
			continue // unreadable → skip
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
			args := []string{"diff", "-M", s.ref, "--"}
			if tf.oldPath != "" {
				args = append(args, tf.oldPath)
			}
			args = append(args, p)
			diff, _ := git(root, args...)
			added = addedLines(diff)
			addedNums = addedLineNumbers(diff)
		}
		// ⚠️ A HEAD-ONLY SECTION SENDS NO LINE NUMBERS, AND THAT IS THE SAFETY PROPERTY.
		// Its ref is HEAD, so its "added" lines are this turn's work PLUS anything the
		// developer had uncommitted — indistinguishable. Positional anchoring would
		// therefore read the developer's own earlier work as INTRODUCED, and the re-wake
		// asks the agent to apply an introduced finding's fix in-turn without checking
		// first — so it would edit code the agent never wrote. With no line numbers the
		// server cannot place a finding and `unsureIsPreexisting` classifies it
		// PRE-EXISTING, which is surfaced for the developer to fix now or later and
		// never edited on its own. Under-claiming is the only safe direction, and it is
		// the same call `classifyFindings` makes everywhere else.
		if s.headOnly {
			addedNums = nil
		}
		ch := transcript.Change{FilePath: s.join(p), RepoDir: s.label, RepoRoot: root, AddedText: added, AddedLines: addedNums}
		// FullContent is the surrounding context; cap per-file and in total so a
		// large change set can't blow the judge's token budget. Over-budget files
		// still carry AddedText, so they are reviewed — just without full context.
		if body := capBytes(string(full), limits.MaxChangedFileBytes); cc.total+len(body) <= limits.MaxChangedTotalBytes {
			ch.FullContent = body
			cc.total += len(body)
		}
		cc.changes = append(cc.changes, ch)
	}
	return "", dropped
}

// join qualifies a repo-root-relative path with the repository's directory, so paths
// from different repositories in one workspace cannot collide. Slash-separated
// throughout: these are wire paths, and git emits slashes on every platform.
func (s repoBaseline) join(p string) string {
	if s.label == "" {
		return p
	}
	return s.label + "/" + p
}

// dir is the repository's directory on disk: the recorded absolute root for a
// PreToolUse-discovered repo, else cwd (the repository the session started in).
func (s repoBaseline) dir(cwd string) string {
	if s.root != "" {
		return s.root
	}
	return cwd
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
func ClearBaseline(sessionID string) {
	_ = os.Remove(scratchPath(sessionID))
	// RemoveAll, not Remove: the discovered-repo scratch is a DIRECTORY, and Remove
	// refuses a non-empty one — so a session that discovered anything would keep its
	// baselines and hand them to the next session reusing that id.
	_ = os.RemoveAll(discoveredDir(sessionID))
}

// sanitize maps a session ID to a safe filename.
func sanitize(s string) string {
	out := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			return r
		default:
			return '_'
		}
	}, s)
	// ⚠️ THE MAP ABOVE NEUTRALISES SLASHES BUT NOT THE DOT NAMES, so a session id of
	// ".." survived intact and filepath.Join then walked OUT of the scratch directory:
	// scratchPath("..") resolved to the temp dir itself. Only one level is reachable
	// (a "../.." becomes ".._..") and nothing exploited it today — the reads and writes
	// simply failed against a directory.
	//
	// It is closed rather than argued away because the session id comes straight from
	// the agent's stdin, and this package now does os.RemoveAll on a path built from it
	// (ClearBaseline, and the stale sweep). A sanitizer that permits ANY escape is one
	// edit away from that being destructive, and the cost of forbidding two names that
	// no real session id uses is nil.
	if out == "." || out == ".." || out == "" {
		return "_"
	}
	return out
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
			// RemoveAll: entries are now a MIX of baseline files and per-session
			// `.repos` DIRECTORIES, and Remove silently fails on a non-empty directory
			// — so plain Remove would leak every workspace session's scratch forever,
			// with nothing erroring. An active session's directory has a fresh mtime
			// (a file is added to it whenever a repo is discovered) so it is not swept.
			_ = os.RemoveAll(filepath.Join(dir, e.Name()))
		}
	}
}

// dropImportedByHistory removes files whose current content was ALREADY PUBLISHED
// before this turn began — code the agent did not write, brought into the working tree
// by a git operation that rewrites it from history (checkout, switch, pull, merge,
// rebase, reset --hard).
//
// ⚠️ WHY THIS IS NEEDED AT ALL. The diff against the turn-start baseline answers "what
// differs from turn start" and is deliberately blind to authorship — that is what
// catches Bash writes, `sed -i`, generators and `--fix` formatters, and it is the whole
// reason the git baseline replaced transcript parsing. But a mid-turn checkout imports
// other people's merged commits, and the diff reports them as this turn's work. The
// consequence is not cosmetic: a finding on such a file is anchored inside AddedLines,
// so it classifies as INTRODUCED, and the re-wake tells the agent to fix introduced
// findings "directly, don't ask". Live, that flagged a permission file changed by
// somebody else's PR two hours earlier, and a compliant agent would have reverted it.
//
// ⚠️ THE TEST IS PER FILE AND CONTENT-BASED, and it has to be, because the obvious
// alternatives all fail in the dangerous direction. "Re-baseline onto the new HEAD" and
// "drop anything clean against HEAD" both look right and both silently drop the agent's
// OWN committed work — a missed vulnerability under a clean verdict, which is the one
// failure this pipeline never accepts. A file is dropped only when its content on disk
// is identical to a commit that was already reachable from a remote-tracking ref BEFORE
// the turn started. The agent's own fresh commit is not, so it stays in scope.
//
// Gated on HEAD having actually MOVED: with the tree still on the commit it started on,
// nothing can have been imported, and the check is skipped entirely.
//
// Fails toward reviewing more, at every step: no recorded header (an older client's
// scratch), an unresolvable HEAD, an unreadable tip, or a git error all subtract
// nothing. Every drop is logged, so an over-subtraction is visible rather than silent.
func dropImportedByHistory(cwd string, files []trackedFile, baseHead string, tips []string) []trackedFile {
	if baseHead == "" || len(tips) == 0 || len(files) == 0 {
		return files
	}
	head, err := git(cwd, "rev-parse", "HEAD")
	if err != nil {
		return files
	}
	if strings.TrimSpace(head) == baseHead {
		return files // the tree never moved through history this turn
	}

	// A tip can only explain the current tree if it is an ancestor of where HEAD now
	// is; an unrelated feature branch cannot. In practice that leaves one or two.
	published := map[string]bool{}
	checked := 0
	for _, tip := range tips {
		if checked >= maxTipsDiffed {
			break
		}
		if _, aerr := git(cwd, "merge-base", "--is-ancestor", tip, "HEAD"); aerr != nil {
			continue // not an ancestor, or git could not say → ignore this tip
		}
		checked++
		// Paths that DIFFER from this tip. Anything changed-since-baseline but absent
		// here is byte-identical to already-published code.
		diff, derr := git(cwd, "diff", "--name-only", tip)
		if derr != nil {
			continue
		}
		differs := map[string]bool{}
		for _, p := range strings.Split(strings.TrimSpace(diff), "\n") {
			if p = strings.TrimSpace(p); p != "" {
				differs[p] = true
			}
		}
		for _, tf := range files {
			if !differs[tf.path] {
				published[tf.path] = true
			}
		}
	}
	if len(published) == 0 {
		return files
	}

	kept := make([]trackedFile, 0, len(files))
	var dropped []string
	for _, tf := range files {
		if published[tf.path] {
			dropped = append(dropped, tf.path)
			continue
		}
		kept = append(kept, tf)
	}
	// Loud on purpose. Subtracting from the review set is the one thing here that can
	// hide a real change, so it is never silent — the same posture as the binary-file
	// skip above.
	slog.Info("vcs: files NOT reviewed — content already published before this turn, so the agent did not write it (a mid-turn checkout/pull/merge brought them in)",
		"dropped", len(dropped), "kept", len(kept), "paths", strings.Join(dropped, ","))
	return kept
}

// discoveredDir holds one file per repository found at PreToolUse for a session.
//
// ⚠️ A DIRECTORY OF FILES RATHER THAN APPENDS TO ONE, AND CONCURRENCY IS THE REASON.
// PreToolUse fires per tool call and an agent may run several in parallel, so two hook
// processes can be writing at the same instant. Appending sections to a shared file
// interleaves them and yields a scratch that parses into nonsense — silently, since a
// mangled ref just makes the diff fail and the turn fall back. One file per repository,
// named by a digest of its root, means concurrent writers never touch the same file and
// no locking is needed.
// baselinedRoot is the absolute root of the repository CaptureBaseline snapshotted for
// this session, plus whether a scratch exists at all.
//
// ⚠️ THE SECOND RETURN IS LOAD-BEARING AND NOT A CONVENIENCE. An empty root means two
// opposite things: no capture happened (cwd was not a repository, so there is nothing to
// collide with and every discovery must be recorded) or a capture happened under a client
// that recorded no root (so the caller must fall back to comparing cwd). Collapsing them
// reinstates the live bug, because the no-capture case is exactly the workspace-folder
// session this event exists for.
//
// Read from the scratch rather than recomputed from cwd because the two diverge: see the
// warning in RecordEditedRepo.
func baselinedRoot(sessionID string) (string, bool) {
	data, err := os.ReadFile(scratchPath(sessionID))
	if err != nil {
		return "", false
	}
	for _, s := range parseBaselines(data) {
		// The unqualified cwd capture; a discovered repo always carries a label, and
		// its own root is not what this answers.
		if s.label == "" {
			return s.root, true
		}
	}
	return "", true
}

func discoveredDir(sessionID string) string { return scratchPath(sessionID) + ".repos" }

// RecordEditedRepo snapshots a baseline for the repository containing editPath, unless
// one is already recorded for it.
//
// Called from the PreToolUse hook, which fires BEFORE the write lands — so the snapshot
// is taken while the repository is still untouched, which is exactly what the baseline
// has to mean. A repo is recorded at most once per session: the first tool call naming
// a file in it wins, and later calls cost one os.Stat.
//
// ⚠️ KNOWN GAP, AND IT IS THE PRICE OF DROPPING THE DIRECTORY WALK. A tool that names no
// file — Bash above all — cannot be attributed to a repository, so a shell write into a
// repo nothing has named yet is included in that repo's baseline and becomes invisible.
// It self-corrects the moment any path-naming tool touches that repo, and the cwd repo
// (where most work happens) is unaffected because UserPromptSubmit captured it. Reviewing
// less than everything is the fail-open direction this whole path takes, but it is a real
// narrowing against walking the tree, and it is why the Stop path still reports
// SkipNoBaseline when a turn discovered nothing at all.
//
// Best-effort throughout: every failure returns nil. A baseline we could not take costs
// one repository's review, never the turn.
func RecordEditedRepo(editPath, cwd, sessionID string) error {
	if editPath == "" || sessionID == "" {
		return nil
	}
	dir := filepath.Dir(editPath)
	if !filepath.IsAbs(dir) {
		// A relative tool path is resolved against cwd, which is what the agent means
		// by it. With no cwd there is nothing to resolve against, so decline rather
		// than let `git -C ""` run in the hook process's own directory (see errNoCwd).
		if cwd == "" {
			return nil
		}
		dir = filepath.Join(cwd, dir)
	}
	root := RepoRoot(dir)
	if root == "" {
		return nil // the agent is writing outside any repository
	}
	// The repository captured at UserPromptSubmit is already in the scratch, unqualified.
	// Adding it again here would produce a SECOND section for the same repo — every
	// changed file twice, once bare and once under a basename label.
	//
	// ⚠️ COMPARED AGAINST THE BASELINED ROOT, NOT THE CURRENT cwd. An agent that runs
	// `cd` into a project moves the cwd Claude Code reports for the rest of the turn, so
	// the current cwd names a repository that may never have been baselined — and
	// skipping on it meant the ONE repository being edited was the one repository
	// discovery refused to record, silently (observed live 2026-08-25: a `cd` into the
	// target repo, then a heredoc, reported "no baseline recorded for this session").
	// With no recorded root — a scratch written by an older client mid-session — fall
	// back to the cwd comparison, which is what that scratch's own capture used.
	baselined, haveScratch := baselinedRoot(sessionID)
	switch {
	case !haveScratch:
		// Nothing was captured at UserPromptSubmit — cwd was not a repository then — so
		// there is no section to collide with and everything must be recorded. This is
		// the live case: skipping here left the edited repo undiscoverable.
	case baselined != "":
		if sameDir(baselined, root) {
			return nil
		}
	default:
		// A scratch written by an older client, which records no root. Fall back to the
		// cwd comparison that client's own capture used.
		if cwdRoot := RepoRoot(cwd); cwdRoot != "" && sameDir(cwdRoot, root) {
			return nil
		}
	}

	marker := filepath.Join(discoveredDir(sessionID), keyFor(root))
	if _, err := os.Stat(marker); err == nil {
		return nil // already recorded this turn (the dir is cleared at UserPromptSubmit)
	}
	if err := os.MkdirAll(discoveredDir(sessionID), 0o700); err != nil {
		return nil
	}
	body := repoSectionPrefix + filepath.Base(root) + "\n" +
		repoRootPrefix + root + "\n" + captureRepo(root)
	// Written whole, to a path no other writer can pick: see discoveredDir.
	_ = os.WriteFile(marker, []byte(body), 0o600)
	return nil
}

// keyFor names a discovered repo's scratch file by a digest of its absolute root, so
// the filename leaks no path even to someone reading the temp directory, and two repos
// can never collide on it however similar their names.
func keyFor(root string) string {
	sum := sha256.Sum256([]byte(root))
	return hex.EncodeToString(sum[:])[:32]
}

// sameDir compares two directories after resolving symlinks, so /tmp and /private/tmp
// on macOS are not read as two different repositories.
func sameDir(a, b string) bool {
	if a == b {
		return true
	}
	ra, ea := filepath.EvalSymlinks(a)
	rb, eb := filepath.EvalSymlinks(b)
	return ea == nil && eb == nil && ra == rb
}

// readDiscovered returns the recorded sections for every repository found this session,
// in a stable order so the change set does not reshuffle between turns.
func readDiscovered(sessionID string) []byte {
	entries, err := os.ReadDir(discoveredDir(sessionID))
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	root, rerr := os.OpenRoot(discoveredDir(sessionID))
	if rerr != nil {
		return nil
	}
	defer root.Close()
	var out []byte
	for _, n := range names {
		// Bounded by the directory we just listed. `n` is a ReadDir entry name, so it
		// is already a base name that cannot traverse — this makes that containment the
		// OS's business rather than a property a reader has to know, and matches how
		// fromRepo reads changed files a few functions up. Aikido flagged the plain
		// ReadFile here; the finding was not exploitable, but the guard is free.
		b, rerr := readAllFrom(root, n)
		if rerr != nil {
			continue
		}
		out = append(out, b...)
		if len(b) > 0 && b[len(b)-1] != '\n' {
			out = append(out, '\n')
		}
	}
	return out
}

// disambiguateLabels makes every label unique.
//
// ⚠️ DONE HERE, AT STOP, AND NOT WHEN EACH REPO IS RECORDED. Two repositories can share
// a basename (`api` in two projects is unremarkable), and the labels qualify paths — so
// a collision would silently merge two projects' files into one namespace, and a finding
// would cite a path matching two files. Recording time cannot fix it: each PreToolUse is
// a separate process racing the others, so two would read the same directory and pick
// the same suffix. Stop is single-process and sees every section, so the answer is
// deterministic. Sorted by root, so the same workspace labels the same way every turn.
func disambiguateLabels(in []repoBaseline) []repoBaseline {
	byLabel := map[string][]int{}
	for i, s := range in {
		if s.label != "" {
			byLabel[s.label] = append(byLabel[s.label], i)
		}
	}
	for _, idxs := range byLabel {
		if len(idxs) < 2 {
			continue
		}
		sort.Slice(idxs, func(a, b int) bool { return in[idxs[a]].root < in[idxs[b]].root })
		for n, i := range idxs {
			if n > 0 { // the first keeps the bare basename
				in[i].label = fmt.Sprintf("%s-%d", in[i].label, n+1)
			}
		}
	}
	return in
}

// readAllFrom reads one file bounded by root. Split out so the open/close pairing is
// not repeated inline in a loop, where an early `continue` could skip the Close.
func readAllFrom(root *os.Root, name string) ([]byte, error) {
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}
