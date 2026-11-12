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
