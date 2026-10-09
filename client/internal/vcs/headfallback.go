package vcs

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// maxFallbackDepth is how far beneath cwd a repository is looked for. A workspace
	// folder holds projects one level down, and occasionally a grouping directory puts
	// them two down; beyond that the scan stops being a workspace and starts being a
	// filesystem crawl.
	maxFallbackDepth = 2
	// maxFallbackRepos bounds the repositories one Stop will diff — and over it, NOTHING
	// is reviewed and every candidate is merely named.
	//
	// ⚠️ TWO, NOT FIFTEEN, AND OVER-CAP MEANS DECLINE RATHER THAN TRUNCATE. Fifteen was
	// sized for a workspace of projects; a real parent-of-checkouts directory answered
	// with four unrelated repositories on a turn that wrote nothing (see touchedSince).
	// If several repositories hold work this turn touched and NOTHING named a path in
	// any of them, we cannot tell which one the turn was about, and the honest answer is
	// to say so rather than to HEAD-diff all of them. One or two is the case worth
	// guessing at: a single-project workspace, which is the layout this exists for.
	maxFallbackRepos = 2
	// maxFallbackDirs bounds directories visited even when nothing is found, so a
	// pathological tree cannot turn one Stop into a crawl.
	maxFallbackDirs = 400
)

// fallbackSkipDirs are trees that never contain the developer's own repository but
// routinely contain hundreds of directories, and sometimes vendored .git dirs. Matched
// per whole path segment, like the inert gate's vendored-tree list.
var fallbackSkipDirs = map[string]bool{
	"node_modules": true, "vendor": true, ".venv": true, "venv": true,
	"__pycache__": true, ".git": true, "dist": true, "build": true,
	"target": true, ".next": true, ".cache": true, "Library": true,
}

// headFallbackSections is the LAST RESORT for a turn that reviewed nothing: it finds
// repositories beneath a non-repository cwd that hold uncommitted work and no baseline,
// and returns a section for each, anchored on HEAD.
//
// ⚠️ IT EXISTS FOR THE ONE WRITE DISCOVERY CANNOT ATTRIBUTE. PreToolUse resolves the
// path a tool names, and agent.BashPathCandidates scavenges one out of a shell command,
// but a path computed at runtime (`$VAR`, `eval`, command substitution) names nothing we
// can resolve before the write. Without this, such a turn reports "no git snapshot" and
// the change ships unreviewed.
//
// ⚠️ LAZY ON PURPOSE, AND THE TRIGGER IS THE WHOLE COST ARGUMENT. It runs only when the
// turn produced NO changes at all and cwd is not itself a repository — so a normal turn
// never pays for it, and it cannot slow the common path. The rejected alternative was
// scanning at every UserPromptSubmit, which pays a directory walk plus a `git stash
// create` per repository on every prompt, writes dangling objects into repositories the
// developer is not touching, and — with any cap — picks its subset by directory order.
//
// ⚠️ ITS FINDINGS ARE SURFACED FOR THE DEVELOPER, NOT APPLIED IN-TURN. A HEAD anchor
// cannot separate this turn's work from work that was already uncommitted, so the
// sections are headOnly and carry no line numbers: see the warning in fromRepo. That is
// what makes reviewing an arbitrarily dirty repository safe rather than merely noisy.
//
// `known` is the set of repository roots already covered this turn, which must be
// excluded or a repository would be reported twice, once per section.
func headFallbackSections(cwd, sessionID string, known []string) (sections []repoBaseline, declined []string) {
	if cwd == "" || sessionID == "" {
		return nil, nil
	}
	since := turnStart(sessionID)
	seen := map[string]bool{}
	for _, k := range known {
		if r := resolveDir(k); r != "" {
			seen[r] = true
		}
	}
	var visited int
	var roots []string
	// Breadth-first by depth so the shallower, likelier projects are found before the
	// caps bite — with a depth-2 scan a nested grouping directory must not crowd out
	// its siblings one level up.
	frontier := []string{cwd}
	// `<`, not `<=`: each pass reads the frontier and discovers repositories one level
	// BELOW it, so a `<=` bound reaches maxFallbackDepth+1 levels — one deeper than the
	// constant and the doc claim, at the cost of a whole extra tier of directory reads.
	// Caught by driving the real binary against a repo three levels down.
	for depth := 0; depth < maxFallbackDepth && len(frontier) > 0; depth++ {
		var next []string
		for _, dir := range frontier {
			// ⚠️ THE CAPS ARE TESTED PER ENTRY, NOT PER FRONTIER DIRECTORY. Checking only
			// here bounds nothing in the commonest layout: a workspace folder whose
			// projects are all children of cwd is ONE frontier directory, so a single
			// pass collected every repository under it — measured at 20 of 20 against a
			// cap of 15, with `capped` never set, so the truncated scan would also have
			// claimed full coverage. Caught by driving the real binary.
			if visited >= maxFallbackDirs {
				break
			}
			visited++
			entries, err := os.ReadDir(dir)
			if err != nil {
				continue
			}
			for _, e := range entries {
				// One past the cap is enough to know we are over it; collecting more
				// would only lengthen the list we are about to decline.
				if len(roots) > maxFallbackRepos {
					break
				}
				if !e.IsDir() || fallbackSkipDirs[e.Name()] || strings.HasPrefix(e.Name(), ".") {
					continue
				}
				child := filepath.Join(dir, e.Name())
				// A repository's own subdirectories are not separate projects, so a
				// hit stops the descent here.
				if root := RepoRoot(child); root != "" && sameDir(root, child) {
					if r := resolveDir(root); r != "" && !seen[r] {
						seen[r] = true
						roots = append(roots, root)
					}
					continue
				}
				next = append(next, child)
			}
		}
		frontier = next
	}
	return build(roots, since)
}

// build turns candidate roots into HEAD-anchored sections. A repository with nothing
// uncommitted is dropped (nothing to review), as is one whose uncommitted work all
// predates the turn (touchedSince) — and if MORE than the cap remain, none are reviewed
// and all are named instead, because with nothing having named a path we cannot tell
// which of them the turn was about.
//
// The second return is the repositories NAMED but not reviewed, so the caller can say so.
func build(roots []string, since time.Time) ([]repoBaseline, []string) {
	var cand []string
	for _, root := range roots {
		if hasUncommitted(root) && touchedSince(root, since) {
			cand = append(cand, root)
		}
	}
	if len(cand) > maxFallbackRepos {
		names := make([]string, 0, len(cand))
		for _, r := range cand {
			names = append(names, filepath.Base(r))
		}
		slog.Info("vcs: several repos hold work from this turn and none was named by a tool — "+
			"reviewing NONE of them rather than guessing (open the one you are working in)",
			"repos", strings.Join(names, ", "))
		return nil, names
	}
	var out []repoBaseline
	for _, root := range cand {
		ref := emptyTree // no commits yet: diff against the empty tree, not nothing
		if head, err := git(root, "rev-parse", "HEAD"); err == nil {
			if h := strings.TrimSpace(head); h != "" {
				ref = h
			}
		}
		out = append(out, repoBaseline{
			label: filepath.Base(root),
			root:  root,
			ref:   ref,
			// No untracked snapshot: with a HEAD anchor there is no turn-start state to
			// compare against, so every untracked file reads as new. That over-reports
			// in the same direction as everything else here, and the findings are
			// surfaced rather than applied.
			untracked: map[string]string{},
			headOnly:  true,
		})
		slog.Info("vcs: no baseline for this repo — reviewing against HEAD as a last resort "+
			"(findings are SURFACED for the developer, not applied in-turn: this turn's work "+
			"cannot be separated from work already uncommitted)", "repo", filepath.Base(root), "root", root)
	}
	return out, nil
}

// hasUncommitted reports whether a repository has anything to review at all.
func hasUncommitted(root string) bool {
	out, err := git(root, "status", "--porcelain")
	return err == nil && strings.TrimSpace(out) != ""
}

// resolveDir is the symlink-resolved absolute form used to compare two directories, so
// /tmp and /private/tmp are not two repositories.
func resolveDir(dir string) string {
	if dir == "" {
		return ""
	}
	if r, err := filepath.EvalSymlinks(dir); err == nil {
		return r
	}
	return dir
}

// labelsOf is the repository names a HEAD-anchored review is reported under. Basenames,
// which is what already travels as each file's path prefix; the absolute root never does.
func labelsOf(sections []repoBaseline) []string {
	out := make([]string, 0, len(sections))
	for _, s := range sections {
		if s.headOnly {
			out = append(out, s.label)
		}
	}
	return out
}

// turnStartPath is the marker UserPromptSubmit drops when cwd is not a repository, so
// the Stop-time fallback can tell this turn's work from work that was already there.
func turnStartPath(sessionID string) string { return scratchPath(sessionID) + ".turn" }

// markTurnStart records when this turn began. Best-effort: without it the fallback
// simply declines to review, which is the safe direction.
func markTurnStart(sessionID string) {
	if sessionID == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(turnStartPath(sessionID)), 0o700); err != nil {
		return
	}
	_ = os.WriteFile(turnStartPath(sessionID), nil, 0o600)
}

// turnStart is when this turn began, or the zero time when no marker exists (an older
// client, or a swept scratch).
func turnStart(sessionID string) time.Time {
	fi, err := os.Stat(turnStartPath(sessionID))
	if err != nil {
		return time.Time{}
	}
	return fi.ModTime()
}

// touchedSince reports whether any of a repository's uncommitted files was modified at or
// after the turn began — the signal that this turn plausibly touched the repository.
//
// ⚠️ THIS IS THE SCOPE GATE, AND IT IS WHY THE FALLBACK IS NOT A HOME-DIRECTORY SWEEP.
// Without it, "reachable within two levels and dirty" was the whole test, and a real
// ~/Documents holding fifteen checkouts answered YES for four unrelated ones: measured
// live on 2026-08-25, a Copilot turn that wrote NOTHING reviewed leolearn-aikido,
// leoprevent, leoprevent-dashfilter and leoprevent-daterange, raised ten findings from
// other people's work in progress, and blocked the turn for 71 seconds. Modification
// time is the only signal available here — nothing named a path, which is the premise of
// the fallback — and it is the right one: work the developer left uncommitted yesterday
// is not what this turn did.
func touchedSince(root string, since time.Time) bool {
	if since.IsZero() {
		return false // no marker: decline rather than guess
	}
	out, err := git(root, "status", "--porcelain")
	if err != nil {
		return false
	}
	for _, ln := range strings.Split(out, "\n") {
		if len(ln) < 4 {
			continue
		}
		// Porcelain v1: two status columns, a space, then the path. A rename carries
		// "old -> new"; the new path is what exists on disk.
		p := strings.TrimSpace(ln[3:])
		if i := strings.Index(p, " -> "); i >= 0 {
			p = p[i+4:]
		}
		p = strings.Trim(p, `"`)
		fi, err := os.Stat(filepath.Join(root, p))
		if err != nil {
			continue
		}
		if !fi.ModTime().Before(since) {
			return true
		}
	}
	return false
}
