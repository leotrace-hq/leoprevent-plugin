package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// One machine, two plugins, two channels. This is the normal state for anyone developing
// LeoPrevent, and the flat file could hold only the last login — so the other plugin matched
// nothing, sent no Bearer token, and failed open on every turn with `401 missing license`.

const (
	prodServer    = "https://api.leotrace.io"
	prodDashboard = "https://prevent.leotrace.io"
	devServer     = "https://leoprevent-dev.fly.dev"
	devDashboard  = "https://leoprevent-customer-dev.vercel.app"
)

func prodPlugin(t *testing.T) string {
	t.Helper()
	return writeJSON(t, `{"server_url":"`+prodServer+`","dashboard_url":"`+prodDashboard+`","tier":"cloud"}`)
}

func devPlugin(t *testing.T) string {
	t.Helper()
	return writeJSON(t, `{"server_url":"`+devServer+`","dashboard_url":"`+devDashboard+`","tier":"cloud"}`)
}

func keyFrom(t *testing.T, pluginJSON string) string {
	t.Helper()
	c, err := resolve(pluginJSON)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	return c.LicenseKey
}

func readStoredFile(t *testing.T) userLicense {
	t.Helper()
	path, err := UserLicensePath()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var u userLicense
	if err := json.Unmarshal(data, &u); err != nil {
		t.Fatal(err)
	}
	return u
}

func TestEachPluginResolvesItsOwnChannelsKey(t *testing.T) {
	// Arrange
	clearEnv(t)
	if _, err := SaveLoginLicense("lp_live_prod", prodServer, prodDashboard, "device-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := SaveLoginLicense("lp_live_dev", devServer, devDashboard, "device-1"); err != nil {
		t.Fatal(err)
	}

	// Act / Assert
	if got := keyFrom(t, prodPlugin(t)); got != "lp_live_prod" {
		t.Errorf("prod plugin key = %q, want lp_live_prod", got)
	}
	if got := keyFrom(t, devPlugin(t)); got != "lp_live_dev" {
		t.Errorf("dev plugin key = %q, want lp_live_dev", got)
	}
}

// The live failure: logging in on dev used to leave the prod plugin with nothing.
func TestALoginOnOneChannelLeavesTheOtherLicensed(t *testing.T) {
	// Arrange
	clearEnv(t)
	if _, err := SaveLoginLicense("lp_live_prod", prodServer, prodDashboard, "device-1"); err != nil {
		t.Fatal(err)
	}

	// Act
	if _, err := SaveLoginLicense("lp_live_dev", devServer, devDashboard, "device-1"); err != nil {
		t.Fatal(err)
	}

	// Assert
	if got := keyFrom(t, prodPlugin(t)); got != "lp_live_prod" {
		t.Errorf("prod plugin lost its key after a dev login: got %q", got)
	}
}

func TestSetLicenseForOneChannelLeavesTheOtherAlone(t *testing.T) {
	// Arrange
	clearEnv(t)
	if _, err := SaveLicenseFor("lp_live_prod", prodServer, prodDashboard); err != nil {
		t.Fatal(err)
	}

	// Act
	if _, err := SaveLicenseFor("lp_live_dev", devServer, devDashboard); err != nil {
		t.Fatal(err)
	}

	// Assert
	if got := keyFrom(t, prodPlugin(t)); got != "lp_live_prod" {
		t.Errorf("prod key = %q, want lp_live_prod", got)
	}
	if got := keyFrom(t, devPlugin(t)); got != "lp_live_dev" {
		t.Errorf("dev key = %q, want lp_live_dev", got)
	}
}

// A key minted on the other channel is real, just not real here. "" is the right answer: sending
// it would 401, and a prod key sent to dev would file customer code against the wrong cluster.
func TestAKeyFromAnotherChannelIsNotUsed(t *testing.T) {
	// Arrange
	clearEnv(t)
	if _, err := SaveLoginLicense("lp_live_dev", devServer, devDashboard, "device-1"); err != nil {
		t.Fatal(err)
	}

	// Act / Assert
	if got := keyFrom(t, prodPlugin(t)); got != "" {
		t.Errorf("prod plugin took a dev key: %q", got)
	}
}

// Enrolment writes no origin, and so did every file from before logins recorded one. Refusing
// those would un-license every machine holding one the moment it updated.
func TestAChannellessKeyServesAnyPlugin(t *testing.T) {
	// Arrange
	clearEnv(t)
	if _, err := SaveLicense("lp_live_enrolled"); err != nil {
		t.Fatal(err)
	}

	// Act / Assert
	if got := keyFrom(t, prodPlugin(t)); got != "lp_live_enrolled" {
		t.Errorf("prod plugin key = %q, want lp_live_enrolled", got)
	}
	if got := keyFrom(t, devPlugin(t)); got != "lp_live_enrolled" {
		t.Errorf("dev plugin key = %q, want lp_live_enrolled", got)
	}
}

// A file written by an older plugin has no map at all.
func TestAFlatFileFromAnOlderPluginStillResolves(t *testing.T) {
	// Arrange
	clearEnv(t)
	path, err := UserLicensePath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	legacy := `{"license_key":"lp_live_legacy","server_url":"` + devServer + `","dashboard_url":"` + devDashboard + `","device_id":"device-1"}`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}

	// Act / Assert
	if got := keyFrom(t, devPlugin(t)); got != "lp_live_legacy" {
		t.Errorf("dev plugin key = %q, want lp_live_legacy", got)
	}
	if got := keyFrom(t, prodPlugin(t)); got != "" {
		t.Errorf("prod plugin took the dev-channel legacy key: %q", got)
	}
}

// The first write on an upgraded machine must fold the flat key in, not discard it.
func TestUpgradingKeepsTheKeyThatWasAlreadyThere(t *testing.T) {
	// Arrange
	clearEnv(t)
	path, err := UserLicensePath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	legacy := `{"license_key":"lp_live_legacy_prod","server_url":"` + prodServer + `","dashboard_url":"` + prodDashboard + `"}`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}

	// Act: the dev plugin logs in, which is what used to destroy the prod key.
	if _, err := SaveLoginLicense("lp_live_dev", devServer, devDashboard, "device-1"); err != nil {
		t.Fatal(err)
	}

	// Assert
	if got := keyFrom(t, prodPlugin(t)); got != "lp_live_legacy_prod" {
		t.Errorf("prod key = %q, want lp_live_legacy_prod", got)
	}
	if got := keyFrom(t, devPlugin(t)); got != "lp_live_dev" {
		t.Errorf("dev key = %q, want lp_live_dev", got)
	}
}

// An older binary beside the new one reads only the flat fields, and this is exactly the machine
// that has two plugin versions installed.
func TestTheFlatFieldsStillMirrorTheLastWrite(t *testing.T) {
	// Arrange
	clearEnv(t)

	// Act
	if _, err := SaveLoginLicense("lp_live_prod", prodServer, prodDashboard, "device-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := SaveLoginLicense("lp_live_dev", devServer, devDashboard, "device-1"); err != nil {
		t.Fatal(err)
	}

	// Assert
	stored := readStoredFile(t)
	if stored.LicenseKey != "lp_live_dev" || stored.ServerURL != devServer {
		t.Errorf("flat mirror = %q @ %q, want lp_live_dev @ %s", stored.LicenseKey, stored.ServerURL, devServer)
	}
	if got := len(readChannelsFile()); got != 2 {
		t.Errorf("stored channels = %d, want 2", got)
	}
}

// device_id names the MACHINE, not the credential. Splitting it per channel would make one
// laptop enrol as two and take two slots in its own per-person key set.
func TestTheDeviceIDIsSharedAcrossChannels(t *testing.T) {
	// Arrange
	clearEnv(t)
	if _, err := SaveLoginLicense("lp_live_prod", prodServer, prodDashboard, "device-1"); err != nil {
		t.Fatal(err)
	}

	// Act
	if _, err := SaveLicenseFor("lp_live_dev", devServer, devDashboard); err != nil {
		t.Fatal(err)
	}

	// Assert
	if got := readStoredFile(t).DeviceID; got != "device-1" {
		t.Errorf("device_id = %q, want device-1 preserved across a second channel's write", got)
	}
}

// Two deployments can share a review server and differ downstream; that was the rule before
// keys were per channel and it still is.
func TestARecordedDashboardMustStillAgree(t *testing.T) {
	// Arrange
	clearEnv(t)
	if _, err := SaveLoginLicense("lp_live_prod", prodServer, prodDashboard, "device-1"); err != nil {
		t.Fatal(err)
	}

	// Act / Assert
	other := writeJSON(t, `{"server_url":"`+prodServer+`","dashboard_url":"https://elsewhere.example","tier":"cloud"}`)
	if got := keyFrom(t, other); got != "" {
		t.Errorf("key served to a plugin with a different dashboard: %q", got)
	}
}

func TestATrailingSlashDoesNotSplitAChannel(t *testing.T) {
	// Arrange
	clearEnv(t)
	if _, err := SaveLoginLicense("lp_live_prod", prodServer+"/", prodDashboard+"/", "device-1"); err != nil {
		t.Fatal(err)
	}

	// Act / Assert
	if got := keyFrom(t, prodPlugin(t)); got != "lp_live_prod" {
		t.Errorf("key = %q, want lp_live_prod despite the trailing slashes", got)
	}
}

// A machine running two plugin versions is the case this whole file exists for, and only the new
// binary writes the map. When the OLDER one logs in it rewrites the flat fields alone, leaving the
// map entry for that channel stale — so the flat entry has to win for its own channel, or the
// developer sees a 401 for a key they just set.
func TestAnOlderBinarysLoginIsNotShadowedByAStaleMapEntry(t *testing.T) {
	// Arrange: a new binary stored both channels.
	clearEnv(t)
	if _, err := SaveLoginLicense("lp_live_prod_old", prodServer, prodDashboard, "device-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := SaveLoginLicense("lp_live_dev", devServer, devDashboard, "device-1"); err != nil {
		t.Fatal(err)
	}

	// Act: the OLD binary logs in on prod. It marshals its own struct, so it writes the flat
	// fields and nothing else — it cannot reach channels.json at all.
	path, err := UserLicensePath()
	if err != nil {
		t.Fatal(err)
	}
	legacy := `{"license_key":"lp_live_prod_new","server_url":"` + prodServer + `","dashboard_url":"` + prodDashboard + `","device_id":"device-1"}`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}

	// Assert
	if got := keyFrom(t, prodPlugin(t)); got != "lp_live_prod_new" {
		t.Errorf("prod key = %q, want the key the older binary just wrote", got)
	}
	if got := keyFrom(t, devPlugin(t)); got != "lp_live_dev" {
		t.Errorf("dev key = %q, want lp_live_dev untouched", got)
	}
}

// The reason the map is a file of its own: an older binary marshals userLicense on every write,
// which would drop a field it does not know about. A single `set-license` from the un-upgraded
// plugin would then flatten the machine back to one key, during exactly the mixed-version window
// this exists for.
func TestAnOlderBinarysWriteCannotDestroyTheOtherChannelsKey(t *testing.T) {
	// Arrange: both channels stored by a new binary.
	clearEnv(t)
	if _, err := SaveLoginLicense("lp_live_prod", prodServer, prodDashboard, "device-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := SaveLoginLicense("lp_live_dev", devServer, devDashboard, "device-1"); err != nil {
		t.Fatal(err)
	}

	// Act: the old binary rewrites license.json wholesale, as its own struct would.
	path, err := UserLicensePath()
	if err != nil {
		t.Fatal(err)
	}
	legacy := `{"license_key":"lp_live_prod_rotated","server_url":"` + prodServer + `","dashboard_url":"` + prodDashboard + `","device_id":"device-1"}`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}

	// Assert
	if got := keyFrom(t, devPlugin(t)); got != "lp_live_dev" {
		t.Errorf("dev key = %q, want lp_live_dev to survive an old binary's write", got)
	}
	if got := keyFrom(t, prodPlugin(t)); got != "lp_live_prod_rotated" {
		t.Errorf("prod key = %q, want the rotated one", got)
	}
}

// The two files are separate, so a channels.json that never got written must not strand a
// machine: the flat key still answers for its own channel.
func TestAMissingChannelsFileFallsBackToTheFlatKey(t *testing.T) {
	// Arrange
	clearEnv(t)
	if _, err := SaveLoginLicense("lp_live_prod", prodServer, prodDashboard, "device-1"); err != nil {
		t.Fatal(err)
	}
	channels, err := UserChannelsPath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(channels); err != nil {
		t.Fatal(err)
	}

	// Act / Assert
	if got := keyFrom(t, prodPlugin(t)); got != "lp_live_prod" {
		t.Errorf("prod key = %q, want lp_live_prod from the flat fields alone", got)
	}
}
