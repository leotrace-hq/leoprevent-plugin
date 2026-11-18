package vcs

import (
	"os"
	"path/filepath"
	"strings"
)

func scopedSession(
	cwd, sessionID string,
) string {
	root := RepoRoot(cwd)
	if root == "" {
		root, _ = filepath.Abs(cwd)
	}
	return "v2-" + keyFor(sessionID) + "-" + keyFor(resolveDir(root))
}

func baselineSession(
	cwd, sessionID string,
) string {
	scoped := scopedSession(cwd, sessionID)
	for _, path := range []string{scratchPath(scoped), discoveredDir(scoped), turnStartPath(scoped)} {
		if _, err := os.Lstat(path); err == nil {
			return scoped
		}
	}
	entries, _ := os.ReadDir(filepath.Dir(scratchPath(scoped)))
	prefix := "v2-" + keyFor(sessionID) + "-"
	candidates := map[string]bool{}
	repo := RepoRoot(cwd)
	for _, entry := range entries {
		name := strings.TrimSuffix(strings.TrimSuffix(entry.Name(), ".repos"), ".turn")
		if strings.HasPrefix(name, prefix) && len(name) == len(scoped) {
			if repo != "" {
				handle, err := os.OpenRoot(discoveredDir(name))
				if err != nil {
					continue
				}
				data, err := handle.ReadFile(keyFor(repo))
				_ = handle.Close()
				if err != nil {
					continue
				}
				for _, section := range parseBaselines(data) {
					if sameDir(section.root, repo) {
						candidates[name] = true
					}
				}
			}
		}
	}
	absolute, _ := filepath.Abs(cwd)
	for parent := filepath.Dir(resolveDir(absolute)); parent != filepath.Dir(parent); parent = filepath.Dir(parent) {
		ancestor := prefix + keyFor(parent)
		if _, err := os.Lstat(turnStartPath(ancestor)); err == nil {
			candidates[ancestor] = true
		}
	}
	if len(candidates) == 1 {
		for candidate := range candidates {
			return candidate
		}
	}
	if len(candidates) == 0 {
		if root, exists := baselinedRoot(sessionID); exists && (root == "" || sameDir(root, repo)) {
			return sessionID
		}
	}
	return scoped
}

func refreshNestedScopes(
	cwd, sessionID string,
) {
	root := RepoRoot(cwd)
	if root == "" {
		root, _ = filepath.Abs(cwd)
	}
	base := resolveDir(root)
	scoped := scopedSession(cwd, sessionID)
	prefix := "v2-" + keyFor(sessionID) + "-"
	for parent := filepath.Dir(base); parent != filepath.Dir(parent); parent = filepath.Dir(parent) {
		refreshScope(prefix+keyFor(parent), sessionID)
	}
	entries, _ := os.ReadDir(filepath.Dir(scratchPath(scoped)))
	seen := map[string]bool{}
	for _, entry := range entries {
		name := strings.TrimSuffix(strings.TrimSuffix(entry.Name(), ".repos"), ".turn")
		if seen[name] || name == scoped || !strings.HasPrefix(name, prefix) || len(name) != len(scoped) {
			continue
		}
		seen[name] = true
		var roots []string
		if r, ok := baselinedRoot(name); ok && r != "" {
			roots = append(roots, r)
		}
		for _, section := range parseBaselines(readDiscovered(name)) {
			roots = append(roots, section.root)
		}
		for _, r := range roots {
			if strictlyWithin(base, r) {
				refreshScope(name, sessionID)
				break
			}
		}
	}
}

func refreshScope(
	name, sessionID string,
) {
	if r, ok := baselinedRoot(name); ok && r != "" {
		content, err := captureRepo(r, sessionID)
		if err != nil {
			_ = os.Remove(scratchPath(name))
		} else {
			_ = os.WriteFile(scratchPath(name), []byte(content+repoRootPrefix+r+"\n"), 0o600)
		}
	}
	entries, _ := os.ReadDir(discoveredDir(name))
	for _, entry := range entries {
		marker := filepath.Join(discoveredDir(name), entry.Name())
		data, err := os.ReadFile(marker)
		if err != nil {
			continue
		}
		sections := parseBaselines(data)
		if len(sections) == 0 || sections[0].root == "" {
			_ = os.Remove(marker)
			continue
		}
		repo := sections[0].root
		block, err := captureRepo(repo, sessionID)
		if err != nil {
			_ = os.Remove(marker)
			continue
		}
		body := repoSectionPrefix + filepath.Base(repo) + "\n" + repoRootPrefix + repo + "\n" + block
		_ = os.WriteFile(marker, []byte(body), 0o600)
	}
	if _, err := os.Stat(turnStartPath(name)); err == nil {
		markTurnStart(name)
	}
}

func strictlyWithin(
	base, dir string,
) bool {
	if dir == "" {
		return false
	}
	rel, err := filepath.Rel(base, resolveDir(dir))
	return err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func legacyBaseline(
	cwd, sessionID string,
) []byte {
	data, err := os.ReadFile(scratchPath(sessionID))
	if err != nil {
		return nil
	}
	repo := RepoRoot(cwd)
	for _, section := range parseBaselines(data) {
		if section.root != "" && !sameDir(section.root, repo) {
			return nil
		}
	}
	return data
}
