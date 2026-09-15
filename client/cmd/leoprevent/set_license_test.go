package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/config"
)

// findFile reports whether name exists anywhere under root.
func findFile(root, name string) string {
	var hit string
	filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err == nil && info != nil && !info.IsDir() && info.Name() == name {
			hit = p
		}
		return nil
	})
	return hit
}

func TestSetLicenseWritesUserFile(t *testing.T) {
	tmp := t.TempDir()
	// Isolate the per-user config dir via the resolver seam, not env vars: on Windows
	// os.UserConfigDir reads %AppData% case-insensitively, so t.Setenv can't reliably
	// redirect it (and without isolation this test would clobber a real license.json).
	defer config.SetUserConfigDirForTest(tmp)()

	if code := runSetLicense([]string{"lp_live_abc123"}); code != 0 {
		t.Fatalf("set-license exit = %d, want 0", code)
	}
	p := findFile(tmp, "license.json")
	if p == "" {
		t.Fatal("license.json not written anywhere under the isolated config dir")
	}
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(data); !contains(got, "lp_live_abc123") {
		t.Errorf("saved file lacks the key: %s", got)
	}
}

func TestSetLicenseRejectsMissingArg(t *testing.T) {
	if code := runSetLicense(nil); code != 2 {
		t.Errorf("no-arg set-license exit = %d, want 2 (usage)", code)
	}
	if code := runSetLicense([]string{"   "}); code != 2 {
		t.Errorf("blank-arg set-license exit = %d, want 2 (usage)", code)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
