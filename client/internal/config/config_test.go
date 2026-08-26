package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeJSON(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), FileName)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// clearEnv removes ambient overrides so file-driven behavior is deterministic, and
// isolates the per-user config dir to an empty temp dir so a real ~/.config/leoprevent/
// license.json on the dev's machine can't contaminate the test.
func clearEnv(t *testing.T) {
	t.Helper()
	t.Setenv(EnvServerURL, "")
	t.Setenv(EnvTier, "")
	t.Setenv(EnvLicenseKey, "")
	isolateUserConfig(t)
}

// isolateUserConfig points userConfigDir at a fresh temp dir for the test's duration.
func isolateUserConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	old := userConfigDir
	userConfigDir = func() (string, error) { return dir, nil }
	t.Cleanup(func() { userConfigDir = old })
	return dir
}

func TestResolveFromFile(t *testing.T) {
	clearEnv(t)
	c, err := resolve(writeJSON(t, `{"server_url":"https://api.example.com","tier":"local"}`))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if c.ServerURL != "https://api.example.com" || c.Tier != TierLocal {
		t.Errorf("unexpected: %+v", c)
	}
}

func TestLicenseKeyFromFileAndEnv(t *testing.T) {
	clearEnv(t)
	c, err := resolve(writeJSON(t, `{"server_url":"https://x","license_key":"lp_live_fromfile"}`))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if c.LicenseKey != "lp_live_fromfile" {
		t.Errorf("license_key from file = %q", c.LicenseKey)
	}

	// Env overrides the file.
	t.Setenv(EnvLicenseKey, "lp_live_fromenv")
	c, err = resolve(writeJSON(t, `{"server_url":"https://x","license_key":"lp_live_fromfile"}`))
	if err != nil {
		t.Fatal(err)
	}
	if c.LicenseKey != "lp_live_fromenv" {
		t.Errorf("env must override file license_key, got %q", c.LicenseKey)
	}
}

// TestMissingLicenseKeyOK: a missing license key must NOT break config loading —
// the hook must still load and fail open (the server rejects, the client fails open).
func TestMissingLicenseKeyOK(t *testing.T) {
	clearEnv(t)
	c, err := resolve(writeJSON(t, `{"server_url":"https://x","tier":"cloud"}`))
	if err != nil {
		t.Fatalf("missing license_key must not error: %v", err)
	}
	if c.LicenseKey != "" {
		t.Errorf("license_key should be empty, got %q", c.LicenseKey)
	}
}

// TestLicenseFromUserFile: the per-user license file supplies the key even when the
// plugin json has none (the marketplace-install case), and SaveLicense round-trips.
func TestLicenseFromUserFile(t *testing.T) {
	clearEnv(t)
	c, err := resolve(writeJSON(t, `{"server_url":"https://x"}`))
	if err != nil || c.LicenseKey != "" {
		t.Fatalf("no key expected yet, got %q (err %v)", c.LicenseKey, err)
	}
	if _, err := SaveLicense("lp_live_user"); err != nil {
		t.Fatal(err)
	}
	c, err = resolve(writeJSON(t, `{"server_url":"https://x"}`))
	if err != nil {
		t.Fatal(err)
	}
	if c.LicenseKey != "lp_live_user" {
		t.Errorf("user-file key = %q, want lp_live_user", c.LicenseKey)
	}
}

// TestUserFileOverridesPluginJSON: the per-user file wins over a key in the plugin json.
func TestUserFileOverridesPluginJSON(t *testing.T) {
	clearEnv(t)
	if _, err := SaveLicense("lp_live_user"); err != nil {
		t.Fatal(err)
	}
	c, err := resolve(writeJSON(t, `{"server_url":"https://x","license_key":"lp_live_plugin"}`))
	if err != nil {
		t.Fatal(err)
	}
	if c.LicenseKey != "lp_live_user" {
		t.Errorf("user file must override plugin json, got %q", c.LicenseKey)
	}
}

// TestEnvOverridesUserFile: $LEOPREVENT_LICENSE_KEY beats the per-user file.
func TestEnvOverridesUserFile(t *testing.T) {
	clearEnv(t)
	if _, err := SaveLicense("lp_live_user"); err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvLicenseKey, "lp_live_env")
	c, err := resolve(writeJSON(t, `{"server_url":"https://x"}`))
	if err != nil {
		t.Fatal(err)
	}
	if c.LicenseKey != "lp_live_env" {
		t.Errorf("env must win over user file, got %q", c.LicenseKey)
	}
}

// TestMalformedUserFileIgnored: a corrupt per-user file must NOT break config loading
// (the hook must still load + fail open); it falls back to the plugin json key.
func TestMalformedUserFileIgnored(t *testing.T) {
	clearEnv(t)
	p, err := UserLicensePath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(`{bad`), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := resolve(writeJSON(t, `{"server_url":"https://x","license_key":"lp_live_plugin"}`))
	if err != nil {
		t.Fatalf("malformed user file must not break loading: %v", err)
	}
	if c.LicenseKey != "lp_live_plugin" {
		t.Errorf("should fall back to plugin json key, got %q", c.LicenseKey)
	}
}

func TestTierDefaultsToCloud(t *testing.T) {
	clearEnv(t)
	c, err := resolve(writeJSON(t, `{"server_url":"https://x"}`))
	if err != nil {
		t.Fatal(err)
	}
	if c.Tier != TierCloud {
		t.Errorf("tier should default to cloud, got %q", c.Tier)
	}
}

func TestEnvOverridesFile(t *testing.T) {
	isolateUserConfig(t)
	t.Setenv(EnvServerURL, "https://env-url")
	t.Setenv(EnvTier, "local")
	c, err := resolve(writeJSON(t, `{"server_url":"https://file-url","tier":"cloud"}`))
	if err != nil {
		t.Fatal(err)
	}
	if c.ServerURL != "https://env-url" || c.Tier != TierLocal {
		t.Errorf("env must override the file, got %+v", c)
	}
}

func TestEnvOnlyNoFile(t *testing.T) {
	isolateUserConfig(t)
	t.Setenv(EnvServerURL, "https://only-env")
	t.Setenv(EnvTier, "")
	// No file present → env + default tier still resolve (the CI/dev path).
	c, err := resolve(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil {
		t.Fatalf("env-only should resolve: %v", err)
	}
	if c.ServerURL != "https://only-env" || c.Tier != TierCloud {
		t.Errorf("env-only: %+v", c)
	}
}

func TestMissingServerURLIsError(t *testing.T) {
	clearEnv(t)
	if _, err := resolve(writeJSON(t, `{"tier":"cloud"}`)); err == nil {
		t.Error("missing server_url must be an error (fail open)")
	}
	if _, err := resolve(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Error("no file + no env must be an error")
	}
}

func TestRejectsBad(t *testing.T) {
	clearEnv(t)
	if _, err := resolve(writeJSON(t, `{not json`)); err == nil {
		t.Error("bad json must error")
	}
	if _, err := resolve(writeJSON(t, `{"server_url":"x","tier":"remote"}`)); err == nil {
		t.Error("bad tier must error")
	}
}

func TestDashboardURLFromFileAndEnv(t *testing.T) {
	c, err := resolve(writeJSON(t, `{"server_url":"https://x","dashboard_url":"https://prevent.example.com"}`))
	if err != nil {
		t.Fatal(err)
	}
	if c.DashboardURL != "https://prevent.example.com" {
		t.Errorf("DashboardURL = %q", c.DashboardURL)
	}

	t.Setenv(EnvDashboardURL, "https://staging.example.com")
	c, err = resolve(writeJSON(t, `{"server_url":"https://x","dashboard_url":"https://prevent.example.com"}`))
	if err != nil {
		t.Fatal(err)
	}
	if c.DashboardURL != "https://staging.example.com" {
		t.Errorf("env should win: %q", c.DashboardURL)
	}
}

// A missing dashboard_url must NOT fail config loading. It is read by the `mcp` subcommand
// alone, so failing here would take the REVIEW LOOP down on every install that predates the
// field — the hook fails open, so the symptom would be silent unreviewed turns rather than an
// error anyone sees. `mcp` refuses on its own, where the developer is watching a tool start.
func TestMissingDashboardURLIsNotAnError(t *testing.T) {
	c, err := resolve(writeJSON(t, `{"server_url":"https://x","tier":"cloud"}`))
	if err != nil {
		t.Fatalf("a config without dashboard_url must still load: %v", err)
	}
	if c.DashboardURL != "" {
		t.Errorf("DashboardURL = %q, want empty", c.DashboardURL)
	}
}

// ── THIS MACHINE'S DEVICE ID (LEO-168) ──

// TestEnsureDeviceIDIsStableAcrossCalls. It is what tells the server "this machine again" rather
// than "a second machine", so a fresh id per call would take a new slot in the person's key set on
// every enrolment and evict their other machines.
func TestEnsureDeviceIDIsStableAcrossCalls(t *testing.T) {
	clearEnv(t)
	first := EnsureDeviceID()
	if first == "" {
		t.Fatal("no device id was generated")
	}
	if second := EnsureDeviceID(); second != first {
		t.Errorf("device id changed between calls: %q then %q", first, second)
	}
}

// TestEnsureDeviceIDPersistsBeforeTheCaller Enrols. An id generated, sent, and then lost because
// the key write failed would make the next attempt a different machine — so it has to be on disk
// by the time this returns, not written alongside the key afterwards.
func TestEnsureDeviceIDPersistsBeforeTheCallerEnrols(t *testing.T) {
	dir := isolateUserConfig(t)
	id := EnsureDeviceID()
	data, err := os.ReadFile(filepath.Join(dir, "leoprevent", UserLicenseFile))
	if err != nil {
		t.Fatalf("the device id was not written: %v", err)
	}
	if !strings.Contains(string(data), id) {
		t.Errorf("the file does not carry the id it returned: %s", data)
	}
}

// TestSaveLicensePreservesTheDeviceID is the regression that matters, and it fails against a
// SaveLicense that marshals a fresh struct.
//
// `set-license` writes this same file. Overwriting it wholesale would silently make the machine a
// NEW device to the server, taking a second slot in the person's own key set and leaving the entry
// its previous id held live until the cap evicted it.
func TestSaveLicensePreservesTheDeviceID(t *testing.T) {
	clearEnv(t)
	id := EnsureDeviceID()
	if _, err := SaveLicense("lp_live_pasted"); err != nil {
		t.Fatal(err)
	}
	if got := readUserLicenseFile(); got.DeviceID != id {
		t.Errorf("device id = %q after set-license, want the pre-existing %q", got.DeviceID, id)
	}
	if got := readUserLicense(); got != "lp_live_pasted" {
		t.Errorf("license key = %q, want the one just saved", got)
	}
}

// TestADeviceIDSurvivesAKeyThatArrivedFirst: the other order, since enrolment writes the key and a
// later turn may be the first to need an id.
func TestADeviceIDSurvivesAKeyThatArrivedFirst(t *testing.T) {
	clearEnv(t)
	if _, err := SaveLicense("lp_live_first"); err != nil {
		t.Fatal(err)
	}
	id := EnsureDeviceID()
	if id == "" {
		t.Fatal("no device id was generated")
	}
	got := readUserLicenseFile()
	if got.LicenseKey != "lp_live_first" || got.DeviceID != id {
		t.Errorf("the file lost one of the two facts: %+v", got)
	}
}

// TestAFileWrittenBeforeDeviceIDsExistedStillLoads. Every machine already in the field has one, so
// the absent field must read as "no id yet" and nothing more.
func TestAFileWrittenBeforeDeviceIDsExistedStillLoads(t *testing.T) {
	dir := isolateUserConfig(t)
	path := filepath.Join(dir, "leoprevent", UserLicenseFile)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"license_key":"lp_live_legacy"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := readUserLicense(); got != "lp_live_legacy" {
		t.Errorf("legacy key = %q, want lp_live_legacy", got)
	}
	if got := readUserLicenseFile().DeviceID; got != "" {
		t.Errorf("device id = %q on a legacy file, want empty", got)
	}
	// And generating one must not lose the key that was already there.
	if EnsureDeviceID() == "" {
		t.Fatal("no device id was generated for a legacy file")
	}
	if got := readUserLicense(); got != "lp_live_legacy" {
		t.Errorf("the key was lost when a device id was added: %q", got)
	}
}
