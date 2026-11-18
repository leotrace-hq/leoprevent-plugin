package hermes

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var sessionIDPattern = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,200}$`)

var sessionCwd = func(
	home, sessionID string,
) string {
	if !sessionIDPattern.MatchString(sessionID) {
		return ""
	}
	db := filepath.Join(home, "state.db")
	if _, err := os.Stat(db); err != nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	query := "SELECT cwd FROM sessions WHERE id = '" + strings.ReplaceAll(sessionID, "'", "''") + "' LIMIT 1;"
	out, err := exec.CommandContext(ctx, "sqlite3", "-readonly", "-cmd", ".timeout 1000", db, query).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func hermesHome() string {
	if home := os.Getenv("HERMES_HOME"); home != "" {
		return home
	}
	if dir, err := os.UserHomeDir(); err == nil {
		return filepath.Join(dir, ".hermes")
	}
	return ""
}

func workspace(
	sessionID, payloadCwd string,
) string {
	home := hermesHome()
	for _, dir := range []string{sessionCwd(home, sessionID), os.Getenv("TERMINAL_CWD"), payloadCwd} {
		if usable(dir, home) {
			return dir
		}
	}
	return ""
}

func usable(
	dir, home string,
) bool {
	if dir == "" || !filepath.IsAbs(dir) {
		return false
	}
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		return false
	}
	return home == "" || !within(dir, home)
}

func within(
	dir, root string,
) bool {
	rel, err := filepath.Rel(resolved(root), resolved(dir))
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func resolved(
	path string,
) string {
	if real, err := filepath.EvalSymlinks(path); err == nil {
		return real
	}
	return filepath.Clean(path)
}

func changedDir(
	paths []string,
) string {
	home := hermesHome()
	for _, p := range paths {
		if dir := filepath.Dir(p); usable(dir, home) {
			return dir
		}
	}
	return ""
}
