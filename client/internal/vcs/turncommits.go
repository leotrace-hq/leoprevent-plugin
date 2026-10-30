package vcs

import (
	"log/slog"
	"strconv"
	"strings"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
	"github.com/leotrace-hq/leoprevent-plugin/limits"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

const (
	maxTurnCommits    = 50
	maxTurnCommitTips = 8
)

const SkipTurnCommitsUnread SkipReason = "listing the commits made this turn failed, so work committed off the checkout could not be found"

type turnCommit struct {
	sha     string
	parent  string
	created int64
}

func (cc *changeCollector) fromTurnCommits(
	cwd string,
	sections []repoBaseline,
) SkipReason {
	groups := map[string][]repoBaseline{}
	var order []string
	for _, s := range sections {
		if s.headOnly || s.rangeDiff {
			continue
		}
		common, err := git(s.dir(cwd), "rev-parse", "--path-format=absolute", "--git-common-dir")
		if err != nil {
			continue
		}
		common = strings.TrimSpace(common)
		if _, seen := groups[common]; !seen {
			order = append(order, common)
		}
		groups[common] = append(groups[common], s)
	}
	for _, common := range order {
		if skip := cc.fromRepoTurnCommits(cwd, groups[common]); skip != "" {
			return skip
		}
	}
	return ""
}

func (cc *changeCollector) fromRepoTurnCommits(
	cwd string,
	group []repoBaseline,
) SkipReason {
	var at int64
	exclude := []string{}
	var dirs []string
	for _, s := range group {
		dirs = append(dirs, s.dir(cwd))
		if s.at > 0 && (at == 0 || s.at < at) {
			at = s.at
		}
		if s.head != "" {
			exclude = append(exclude, "^"+s.head)
		}
		for _, tip := range s.tips {
			exclude = append(exclude, "^"+tip)
		}
		if head := Head(s.dir(cwd)); head != "" {
			exclude = append(exclude, "^"+head)
		}
	}
	if at == 0 {
		return ""
	}
	label := group[0]
	dir := label.dir(cwd)
	root := RepoRoot(dir)
	if root == "" {
		return ""
	}
	ours, err := reflogSince(dirs, at)
	if err != nil {
		slog.Error("vcs: this session's reflog could NOT be read; work committed off the checkout is not reviewed", "err", err.Error())
		return SkipTurnCommitsUnread
	}
	if len(ours) == 0 {
		return ""
	}
	commits, err := turnCommits(root, at, exclude, ours)
	if err != nil {
		slog.Error("vcs: commits made this turn could NOT be listed; work committed off the checkout is not reviewed", "err", err.Error())
		return SkipTurnCommitsUnread
	}
	if len(commits) == 0 {
		return ""
	}
	seen := map[string]bool{}
	for _, c := range cc.changes {
		seen[c.FilePath] = true
	}
	for _, tip := range commitTips(commits) {
		base := turnBase(tip, commits)
		cc.fromCommitRange(root, label, base, tip, seen)
	}
	return ""
}

func turnCommits(
	root string,
	at int64,
	exclude []string,
	ours map[string]bool,
) (map[string]turnCommit, error) {
	email := committerEmail(root)
	args := []string{"log", "--all", "--no-merges", "--ignore-missing",
		"--since=@" + strconv.FormatInt(at, 10),
		"-n", strconv.Itoa(maxTurnCommits),
		"--format=%H %ct %ce %P"}
	out, err := git(root, append(args, exclude...)...)
	if err != nil {
		return nil, err
	}
	commits := map[string]turnCommit{}
	for _, ln := range strings.Split(strings.TrimSpace(out), "\n") {
		f := strings.Fields(ln)
		if len(f) < 3 {
			continue
		}
		created, perr := strconv.ParseInt(f[1], 10, 64)
		if perr != nil || created < at || !ours[f[0]] {
			continue
		}
		if email != "" && !strings.EqualFold(f[2], email) {
			continue
		}
		c := turnCommit{sha: f[0], created: created}
		if len(f) > 3 {
			c.parent = f[3]
		}
		commits[c.sha] = c
	}
	return commits, nil
}

func reflogSince(
	dirs []string,
	at int64,
) (map[string]bool, error) {
	ours := map[string]bool{}
	for _, dir := range dirs {
		out, err := git(dir, "reflog", "show", "--date=unix", "--format=%H %gd", "HEAD")
		if err != nil {
			return nil, err
		}
		for _, ln := range strings.Split(strings.TrimSpace(out), "\n") {
			sha, sel, ok := strings.Cut(strings.TrimSpace(ln), " ")
			if !ok {
				continue
			}
			_, when, ok := strings.Cut(strings.TrimSuffix(sel, "}"), "@{")
			if !ok {
				continue
			}
			if t, perr := strconv.ParseInt(when, 10, 64); perr == nil && t >= at {
				ours[sha] = true
			}
		}
	}
	return ours, nil
}

func committerEmail(
	root string,
) string {
	ident, err := git(root, "var", "GIT_COMMITTER_IDENT")
	if err != nil {
		return ""
	}
	_, rest, ok := strings.Cut(ident, "<")
	if !ok {
		return ""
	}
	email, _, ok := strings.Cut(rest, ">")
	if !ok {
		return ""
	}
	return strings.TrimSpace(email)
}

func commitTips(
	commits map[string]turnCommit,
) []turnCommit {
	parents := map[string]bool{}
	for _, c := range commits {
		parents[c.parent] = true
	}
	var tips []turnCommit
	for _, c := range commits {
		if !parents[c.sha] {
			tips = append(tips, c)
		}
	}
	for i := 1; i < len(tips); i++ {
		for j := i; j > 0 && newer(tips[j], tips[j-1]); j-- {
			tips[j], tips[j-1] = tips[j-1], tips[j]
		}
	}
	if len(tips) > maxTurnCommitTips {
		tips = tips[:maxTurnCommitTips]
	}
	return tips
}

func newer(
	a turnCommit,
	b turnCommit,
) bool {
	if a.created != b.created {
		return a.created > b.created
	}
	return a.sha < b.sha
}

func turnBase(
	tip turnCommit,
	commits map[string]turnCommit,
) string {
	cur := tip
	for steps := 0; steps <= len(commits); steps++ {
		prev, ok := commits[cur.parent]
		if !ok {
			break
		}
		cur = prev
	}
	if cur.parent == "" {
		return emptyTree
	}
	return cur.parent
}

func (cc *changeCollector) fromCommitRange(
	root string,
	s repoBaseline,
	base string,
	tip turnCommit,
	seen map[string]bool,
) {
	nameStatus, err := git(root, "diff", "--name-status", "-M", base, tip.sha)
	if err != nil {
		slog.Error("vcs: a commit made this turn could NOT be diffed; it is not reviewed", "commit", tip.sha, "err", err.Error())
		return
	}
	for _, tf := range trackedFiles(nameStatus) {
		p := tf.path
		if strings.Contains("/"+p, "/node_modules/") || seen[s.join(p)] {
			continue
		}
		seen[s.join(p)] = true
		if tf.deleted {
			if removed, ok := deletedContent(root, base, p); ok {
				cc.changes = append(cc.changes, transcript.Change{
					FilePath: s.join(p), RepoDir: s.label, RepoRoot: root,
					RemovedText: removed, Deleted: true,
				})
			}
			continue
		}
		full, ok := blobAt(root, tip.sha, p)
		if !ok {
			continue
		}
		args := []string{"diff", "-M", base, tip.sha, "--"}
		if tf.oldPath != "" {
			args = append(args, tf.oldPath)
		}
		diff, _ := git(root, append(args, p)...)
		added := addedLines(diff)
		addedNums := addedLineNumbers(diff)
		removed, removedAt := removedLines(diff, limits.MaxChangedFileBytes)
		anchors := append(append([]int(nil), addedNums...), removedAt...)
		ch := transcript.Change{FilePath: s.join(p), RepoDir: s.label, RepoRoot: root, AddedText: added, AddedLines: addedNums, RemovedText: removed, RemovedAt: removedAt}
		if body, start := wire.SliceAround(string(full), anchors, limits.MaxChangedFileBytes); cc.total+len(body) <= limits.MaxChangedTotalBytes {
			ch.FullContent = body
			if start > 1 {
				ch.BodyStartLine = start
				ch.ImportSource = capBytes(string(full), limits.MaxChangedFileBytes)
			}
			cc.total += len(body)
		}
		slog.Info("vcs: reviewing a file from a commit made this turn that the checkout no longer holds", "path", p, "commit", tip.sha)
		cc.changes = append(cc.changes, ch)
	}
}

func blobAt(
	root string,
	rev string,
	p string,
) ([]byte, bool) {
	entry, err := git(root, "ls-tree", rev, "--", p)
	if err != nil || !(strings.HasPrefix(entry, "100644 ") || strings.HasPrefix(entry, "100755 ")) {
		return nil, false
	}
	f := strings.Fields(entry)
	if len(f) < 3 {
		return nil, false
	}
	size, err := git(root, "cat-file", "-s", f[2])
	if n, perr := strconv.Atoi(strings.TrimSpace(size)); err != nil || perr != nil || n > maxTurnStartFileBytes {
		return nil, false
	}
	body, err := git(root, "cat-file", "blob", f[2])
	if err != nil {
		return nil, false
	}
	full := []byte(body)
	if isBinary(full) {
		slog.Error("vcs: file NOT reviewed: binary content in a commit made this turn", "path", p)
		return nil, false
	}
	return full, true
}
