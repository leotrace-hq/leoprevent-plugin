//go:build unix

package scratch

import (
	"os"
	"path/filepath"
	"testing"
)

// writeUnder reports whether a scratch file can be written the way the callers do it.
func writeUnder(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "probe"), []byte("x"), 0o600)
}

// TestAWorldWritableRootIsRefused is the LEO-542 attack: another user pre-creates the root
// open to everyone. MkdirAll is a no-op on an existing dir, so the old code wrote the
// customer's pre-turn code straight into it. The root must be refused, not repaired.
func TestAWorldWritableRootIsRefused(t *testing.T) {
	base := t.TempDir()
	t.Cleanup(SetUserCacheDirForTest(base))
	root := filepath.Join(base, "leoprevent")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o777); err != nil { // Chmod, not Mkdir's mode: umask would narrow it
		t.Fatal(err)
	}

	dir := Dir("baselines")
	if filepath.Dir(dir) == root {
		t.Fatalf("Dir = %q: a world-writable root was used", dir)
	}
	if err := writeUnder(dir); err == nil {
		t.Fatalf("a scratch write under the refused root %q succeeded", dir)
	}
	if fi, err := os.Stat(root); err != nil || fi.Mode().Perm() != 0o777 {
		t.Fatalf("the refused root was modified: %v %v", fi.Mode(), err)
	}
}

// TestASymlinkedRootIsRefused: the other half of the attack, a symlink at the root pointing
// somewhere the attacker reads (or somewhere they want the client to write).
func TestASymlinkedRootIsRefused(t *testing.T) {
	base := t.TempDir()
	t.Cleanup(SetUserCacheDirForTest(base))
	target := t.TempDir() // 0700 and ours, so only the link itself is wrong
	if err := os.Symlink(target, filepath.Join(base, "leoprevent")); err != nil {
		t.Fatal(err)
	}

	dir := Dir("baselines")
	if err := writeUnder(dir); err == nil {
		t.Fatalf("a scratch write under the refused root %q succeeded", dir)
	}
	if entries, _ := os.ReadDir(target); len(entries) != 0 {
		t.Fatalf("the client wrote through the symlink: %v", entries)
	}
}

// TestAGroupReadableRootIsRefused: group bits matter as much as other bits on a shared box.
func TestAGroupReadableRootIsRefused(t *testing.T) {
	base := t.TempDir()
	t.Cleanup(SetUserCacheDirForTest(base))
	root := filepath.Join(base, "leoprevent")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := writeUnder(Dir("notices")); err == nil {
		t.Fatal("a scratch write under a group-readable root succeeded")
	}
}

// TestAPrivateRootIsUsed: the happy path writes, so the refusals above are not just "nothing
// ever works".
func TestAPrivateRootIsUsed(t *testing.T) {
	base := t.TempDir()
	t.Cleanup(SetUserCacheDirForTest(base))
	if err := writeUnder(Dir("notices")); err != nil {
		t.Fatalf("scratch write under a fresh private root failed: %v", err)
	}
	fi, err := os.Lstat(filepath.Join(base, "leoprevent"))
	if err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("root mode = %v (%v), want 0700", fi.Mode(), err)
	}
}

// TestNoCacheDirFallsBackToACheckedTempRoot: with no $HOME the cache dir cannot be resolved.
// The fallback is a per-uid name under the temp dir, held to the same check.
func TestNoCacheDirFallsBackToACheckedTempRoot(t *testing.T) {
	old := userCacheDir
	userCacheDir = func() (string, error) { return "", os.ErrNotExist }
	t.Cleanup(func() { userCacheDir = old })
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)

	if err := writeUnder(Dir("notices")); err != nil {
		t.Fatalf("fallback root unusable: %v", err)
	}
	entries, _ := os.ReadDir(tmp)
	if len(entries) != 1 {
		t.Fatalf("fallback root not under TMPDIR: %v", entries)
	}

	// Pre-plant the fallback name open to everyone, as another user on a shared /tmp would.
	tmp2 := t.TempDir()
	t.Setenv("TMPDIR", tmp2)
	planted := filepath.Join(tmp2, entries[0].Name())
	if err := os.Mkdir(planted, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(planted, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := writeUnder(Dir("notices")); err == nil {
		t.Fatal("a scratch write under a planted world-writable fallback root succeeded")
	}
}
