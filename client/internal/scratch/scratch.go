// Package scratch owns the per-user directory the client keeps its per-turn state in.
//
// The hook is a fresh process on every event, so anything one event needs from an earlier one
// (the pre-turn baseline, the outcome ledger, the notice dedupe set, the agent guards) lives on
// disk between them. That state used to sit in fixed-name dirs under os.TempDir(), created with
// os.MkdirAll(dir, 0o700). On Linux /tmp is SHARED, and MkdirAll is a no-op when the path already
// exists: it neither fixes the mode nor notices a symlink or a dir another user owns. So another
// local user (a devcontainer, a CI runner, a multi-user box) could pre-create
// /tmp/leoprevent-baselines as 0777 and read the customer's pre-turn code out of it, or point it
// somewhere and plant files the client then trusts. macOS was never affected ($TMPDIR is per
// user), which is why it went unnoticed (LEO-542, Sonar go:S5445/S5443).
//
// The fix has two halves:
//
//   - The root moves to <os.UserCacheDir>/leoprevent, which is per user on every OS.
//   - The root is checked before use: a real directory (not a symlink), owned by us, and on Unix
//     closed to group and others. Anything else is REFUSED rather than repaired, because a dir
//     that was ever open may already hold files someone else put there.
//
// ⚠️ EVERY SCRATCH USE IS BEST-EFFORT AND MUST NEVER FAIL A TURN. A refused root does not
// return an error: Dir returns a path under a root no write can succeed in, so the caller's own
// existing error handling (a skipped baseline, a notice shown twice) is what happens. It never
// returns "" — callers filepath.Join onto the result and an empty root would turn every scratch
// path into a RELATIVE path inside the user's repo.
package scratch

import (
	"os"
	"path/filepath"
	"strconv"
)

// userCacheDir resolves the OS per-user cache dir (~/Library/Caches on macOS, $XDG_CACHE_HOME
// or ~/.cache on Linux, %LocalAppData% on Windows). A var so tests can point it at a temp dir.
var userCacheDir = os.UserCacheDir

// SetUserCacheDirForTest overrides the per-user cache dir resolver for a test and returns a
// func restoring the previous one.
func SetUserCacheDirForTest(dir string) func() {
	old := userCacheDir
	userCacheDir = func() (string, error) { return dir, nil }
	return func() { userCacheDir = old }
}

// Dir is the scratch directory for one kind of state, e.g. Dir("baselines"). It is not created:
// callers already MkdirAll the parent of the file they write, and readers must not create
// anything. The ROOT is created (0700) and checked on every call; it is a handful of syscalls
// in a process that lives for one hook event.
func Dir(name string) string { return filepath.Join(root(), name) }

// root is the checked per-user root, or refusedRoot if none can be trusted.
func root() string {
	if base, err := userCacheDir(); err == nil && base != "" {
		dir := filepath.Join(base, "leoprevent")
		if trusted(dir) {
			return dir
		}
		return refusedRoot
	}
	// No cache dir: os.UserCacheDir fails when $HOME (or %LocalAppData%) is unset, which happens
	// in stripped-down CI and container environments. Fall back to a per-uid name under the temp
	// dir rather than disabling every feature, and hold it to the same check: on a shared /tmp
	// the name is predictable, so it is the check, not the name, that keeps other users out.
	dir := filepath.Join(os.TempDir(), "leoprevent-"+strconv.Itoa(os.Geteuid())) // NOSONAR go:S5443 owner, mode and symlink are verified by trusted() before use
	if trusted(dir) {
		return dir
	}
	return refusedRoot
}

// trusted creates dir if it is missing and reports whether it is safe to keep state in.
func trusted(dir string) bool {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return false
	}
	// Lstat, not Stat: a symlink must be refused, not followed to whatever it points at.
	fi, err := os.Lstat(dir)
	if err != nil || fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		return false
	}
	return ownedAndPrivate(fi)
}
