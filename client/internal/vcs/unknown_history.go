package vcs

import (
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
)

const (
	maxAuthorshipCommits     = 32
	historyAuthorshipTimeout = 2 * time.Second
)

// Unknown history is still reviewed. Missing observations cannot distinguish a
// colleague's commit from this agent's shell-only second worktree. Nil anchors use
// the existing unsure contract: findings are surfaced, not force-fixed, and no
// agent-line attribution is claimed. Code, blob identity and review scope remain.
func keepUnprovenHistoryUnattributed(root, base, tip string, at int64, dirs []string, changes []transcript.Change) {
	if len(changes) == 0 || base == "" || at <= 0 {
		return // legacy snapshots have no history observations to compare
	}
	paths, all, err := unprovenHistory(root, base, tip, at, dirs)
	if err != nil {
		all = true
		slog.Warn("vcs: history authorship could not be established; code remains reviewed without agent attribution", "err", err)
	}
	for i := range changes {
		c := &changes[i]
		path := c.FilePath
		if c.RepoDir != "" {
			path = strings.TrimPrefix(path, c.RepoDir+"/")
		}
		if (all || paths[path]) && c.AddedLines != nil {
			c.AddedLines = nil
			slog.Info("vcs: authorship unknown; changed code remains in review", "path", c.FilePath)
		}
	}
}

func unprovenHistory(root, base, tip string, at int64, dirs []string) (map[string]bool, bool, error) {
	deadline := time.Now().Add(historyAuthorshipTimeout)
	run := func(dir string, args ...string) (string, error) {
		left := time.Until(deadline)
		if left <= 0 {
			return "", fmt.Errorf("history authorship deadline exceeded")
		}
		return gitEnv(left, nil, dir, args...)
	}
	log, err := run(root, "rev-list", "--timestamp", "--parents", "-n", strconv.Itoa(maxAuthorshipCommits+1), base+".."+tip)
	if err != nil {
		return nil, false, err
	}
	if strings.TrimSpace(log) == "" {
		return nil, false, nil
	}
	commits := strings.Split(strings.TrimSpace(log), "\n")
	if len(commits) > maxAuthorshipCommits {
		return nil, true, nil // bounded uncertainty, never a truncated authorship claim
	}
	observed, err := authoredCommitsSince(dirs, at, run)
	if err != nil {
		return nil, false, err
	}
	unknown := map[string]bool{}
	hasDeletion := false
	for _, line := range commits {
		parts := strings.Fields(line)
		if len(parts) < 2 {
			return nil, false, fmt.Errorf("empty history record")
		}
		created, err := strconv.ParseInt(parts[0], 10, 64)
		if err != nil {
			return nil, false, err
		}
		parts = parts[1:]
		var status string
		if len(parts) == 1 {
			status, err = run(root, "diff-tree", "--root", "--no-commit-id", "--name-status", "--no-renames", "-z", "-r", parts[0])
		} else {
			status, err = run(root, "diff", "--name-status", "--no-renames", "-z", parts[1], parts[0], "--")
		}
		if err != nil {
			return nil, false, err
		}
		paths, deleted, err := historyPaths(status)
		if err != nil {
			return nil, false, err
		}
		hasDeletion = hasDeletion || deleted
		// The established pre-turn import guard already subtracts older commits'
		// lines. Preserve its positional attribution of the agent's later edits.
		if created >= at && !observed[parts[0]] {
			for _, path := range paths {
				unknown[path] = true
			}
		}
	}
	if len(unknown) == 0 {
		return nil, false, nil
	}
	if tip == "HEAD" {
		// A shell mv may leave a tracked deletion and an untracked destination.
		// Without line lineage, do not lose uncertainty when a path changes.
		status, err := run(root, "diff", "--name-status", "--no-renames", "-z", "HEAD", "--")
		if err != nil {
			return nil, false, err
		}
		_, deleted, err := historyPaths(status)
		if err != nil {
			return nil, false, err
		}
		hasDeletion = hasDeletion || deleted
	}
	// A deletion can be a rename with substantial edits. Until that lineage is
	// proven, retain every file for review but withhold all authorship anchors.
	return unknown, hasDeletion, nil
}

func historyPaths(status string) ([]string, bool, error) {
	if status == "" {
		return nil, false, nil
	}
	fields := strings.Split(strings.TrimSuffix(status, "\x00"), "\x00")
	if len(fields)%2 != 0 {
		return nil, false, fmt.Errorf("unpaired history paths")
	}
	var paths []string
	deleted := false
	for i := 0; i < len(fields); i += 2 {
		if fields[i] == "" || fields[i+1] == "" {
			return nil, false, fmt.Errorf("empty history path")
		}
		paths = append(paths, fields[i+1])
		deleted = deleted || fields[i] == "D"
	}
	return paths, deleted, nil
}

func authoredCommitsSince(dirs []string, at int64, run func(string, ...string) (string, error)) (map[string]bool, error) {
	observed := map[string]bool{}
	for _, dir := range dirs {
		log, err := run(dir, "reflog", "show", "--date=unix", "--format=%H%x00%gd%x00%gs", "-n", "256", "HEAD")
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(strings.TrimSpace(log), "\n") {
			parts := strings.SplitN(line, "\x00", 3)
			if len(parts) != 3 {
				continue
			}
			_, when, ok := strings.Cut(strings.TrimSuffix(parts[1], "}"), "@{")
			stamp, err := strconv.ParseInt(when, 10, 64)
			if !ok || err != nil || stamp < at {
				continue
			}
			action, _, _ := strings.Cut(parts[2], ": ")
			switch action {
			case "commit", "commit (initial)", "commit (amend)", "commit (merge)":
				observed[parts[0]] = true
			default:
				// A fast-forward only observes an existing commit. A merge creation
				// observes the new merge commit; its parents are checked separately.
				if strings.HasPrefix(action, "merge ") && strings.Contains(parts[2], ": Merge made by ") {
					observed[parts[0]] = true
				}
			}
		}
	}
	return observed, nil
}
