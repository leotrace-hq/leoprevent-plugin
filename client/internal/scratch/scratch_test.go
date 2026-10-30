package scratch

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDirIsUnderTheUserCacheDir: the root is <UserCacheDir>/leoprevent, created on first use.
func TestDirIsUnderTheUserCacheDir(t *testing.T) {
	base := t.TempDir()
	t.Cleanup(SetUserCacheDirForTest(base))

	got := Dir("baselines")
	if want := filepath.Join(base, "leoprevent", "baselines"); got != want {
		t.Fatalf("Dir = %q, want %q", got, want)
	}
	if fi, err := os.Stat(filepath.Join(base, "leoprevent")); err != nil || !fi.IsDir() {
		t.Fatalf("root was not created: %v", err)
	}
}

// TestDirIsNeverRelative: callers filepath.Join onto Dir's result, and the client runs with the
// user's repo as its cwd. A relative result would put scratch files (the pre-turn code among
// them) inside that repo, so even a refused root must stay absolute.
func TestDirIsNeverRelative(t *testing.T) {
	// A cache "dir" that is a file: the root under it cannot be created, so it is refused.
	base := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(base, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(SetUserCacheDirForTest(base))
	for _, name := range []string{"baselines", "notices"} {
		got := Dir(name)
		if !filepath.IsAbs(got) {
			t.Errorf("Dir(%q) = %q, want an absolute path", name, got)
		}
		if filepath.Dir(got) == filepath.Join(base, "leoprevent") {
			t.Errorf("Dir(%q) = %q: an uncreatable root was used", name, got)
		}
	}
}
