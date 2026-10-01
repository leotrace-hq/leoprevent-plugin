package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestLoginCredentialBoundToEnvironment(
	t *testing.T,
) {
	clearEnv(t)
	t.Setenv(EnvDashboardURL, "")
	_, err := SaveLoginLicense("lp_live_login", "https://dev.example", "https://portal.dev.example", "device")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ server, dashboard, expected string }{
		{"https://dev.example", "https://portal.dev.example", "lp_live_login"},
		{"https://prod.example", "https://portal.dev.example", ""},
		{"https://dev.example", "https://portal.prod.example", ""},
	} {
		t.Setenv(EnvServerURL, tc.server)
		t.Setenv(EnvDashboardURL, tc.dashboard)
		cfg, err := resolve(filepath.Join(t.TempDir(), "absent"))
		if err != nil || cfg.LicenseKey != tc.expected {
			t.Fatalf("environment selection failed: %v", err)
		}
	}
	t.Setenv(EnvLicenseKey, "lp_live_override")
	cfg, err := resolve(filepath.Join(t.TempDir(), "absent"))
	if err != nil || cfg.LicenseKey != "lp_live_override" {
		t.Fatal("environment key must retain precedence")
	}
}

func TestLoginSaveFailureKeepsCredential(
	t *testing.T,
) {
	clearEnv(t)
	path, err := SaveLicense("lp_live_existing")
	if err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	old := userConfigDir
	userConfigDir = func() (string, error) { return path, nil }
	_, err = SaveLoginLicense("lp_live_new", "https://server", "https://portal", "device")
	userConfigDir = old
	if err == nil {
		t.Fatal("expected write failure")
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("existing credential changed")
	}
}

func TestLoginSaveUsesRestrictivePermissions(
	t *testing.T,
) {
	clearEnv(t)
	path, err := SaveLoginLicense("lp_live_new", "https://server", "https://portal", "device")
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatalf("permissions: %v", info.Mode())
	}
	files, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".license-*"))
	if len(files) != 0 {
		t.Fatal("temporary credential files remain")
	}
}
