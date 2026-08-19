// Package config resolves the client configuration: which leotrace server to talk
// to (server_url), which tier (cloud|local), and the customer license_key sent as a
// Bearer token. Resolution order (later wins):
//
//  1. leoprevent.json shipped IN the plugin (at the plugin root, one dir above the
//     binary in bin/). This is a committed WORKING default — server_url + tier so the
//     plugin talks to production out of the box; an on-prem install edits this file.
//  2. The per-user license file — <UserConfigDir>/leoprevent/license.json, written by
//     the `set-license` subcommand. Supplies the license_key ONLY. It lives OUTSIDE the
//     plugin dir, so a marketplace/plugin auto-update (which re-copies the plugin dir)
//     can never clobber the key — the production way a dev sets their key.
//  3. Environment override — $LEOPREVENT_SERVER_URL / $LEOPREVENT_TIER /
//     $LEOPREVENT_LICENSE_KEY. OPTIONAL, for CI / dev / staging only. NOT the sole
//     production mechanism: a GUI-launched agent doesn't inherit a shell's env.
//
// The client reads NO project .env and never the working directory — only its own
// shipped config + the namespaced overrides above. A missing server_url is a hard
// error → the hook fails open (it never reviews against a misconfigured target).
package config

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// Tier values.
const (
	TierCloud = "cloud" // POST /review — our server selects + judges; code egress
	TierLocal = "local" // POST /rules — on-device selection, local judging; no code egress

	// DefaultTier applies when neither the file nor the env sets a tier.
	DefaultTier = TierCloud
)

// Optional env overrides (CI/dev/staging — never the sole production source).
const (
	EnvServerURL      = "LEOPREVENT_SERVER_URL"
	EnvTier           = "LEOPREVENT_TIER"
	EnvLicenseKey     = "LEOPREVENT_LICENSE_KEY"
	EnvResolveImports = "LEOPREVENT_RESOLVE_IMPORTS" // 0|false|off|no disables cross-file context
	// EnvDashboardURL overrides the customer dashboard origin the `mcp` subcommand reads
	// stats from. A SEPARATE deployment from the review server — the dashboards read Mongo
	// directly and never call the Go server (CLAUDE.md), so the two are different hosts and
	// one URL could not serve both.
	EnvDashboardURL = "LEOPREVENT_DASHBOARD_URL"
	// EnvEnrollToken is the ORG-scoped enrolment token an enterprise admin pushes through managed
	// settings' `env` block. It is NOT a license key and cannot review anything: the server
	// exchanges it for this machine's own per-user key (see client/internal/enroll). It rides the
	// env because managed settings apply uniformly across an organisation, so one identical value
	// is the only credential an admin can distribute — which is exactly what this is.
	EnvEnrollToken = "LEOPREVENT_ENROLL_TOKEN"
)

// FileName is the committed config shipped at the plugin root.
const FileName = "leoprevent.json"

// UserLicenseFile is the per-user license file, written by `set-license` and read by
// Load. It lives in the OS user-config dir (NOT the plugin dir), so a plugin
// auto-update — which re-copies the plugin dir — can never clobber the key.
const UserLicenseFile = "license.json"

// userConfigDir resolves the OS per-user config dir (os.UserConfigDir: ~/Library/
// Application Support on macOS, %AppData% on Windows, ~/.config on Linux — the SAME
// base the client log uses). A package var so tests can isolate it.
var userConfigDir = os.UserConfigDir

// SetUserConfigDirForTest overrides the per-user config dir resolver for a test
// and returns a restore func. It lets tests in OTHER packages (e.g. the set-license
// CLI in cmd/leoprevent) isolate the write off the real %AppData% / ~/.config.
// Env-var isolation is NOT reliable here: on Windows os.UserConfigDir reads %AppData%
// with case-insensitive lookup, so t.Setenv can't dependably redirect it — overriding
// the resolver is the only cross-platform-safe seam. Test-only.
func SetUserConfigDirForTest(dir string) func() {
	old := userConfigDir
	userConfigDir = func() (string, error) { return dir, nil }
	return func() { userConfigDir = old }
}

// UserLicensePath is <UserConfigDir>/leoprevent/license.json.
func UserLicensePath() (string, error) {
	dir, err := userConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "leoprevent", UserLicenseFile), nil
}

// userLicense holds only the customer key; server_url + tier stay the deployment's job
// (the shipped leoprevent.json), never the dev's.
type userLicense struct {
	LicenseKey string `json:"license_key"`
}

// SaveLicense writes key to the per-user license file (0600), creating the dir, and
// returns the path written. Used by the `set-license` subcommand.
func SaveLicense(key string) (string, error) {
	path, err := UserLicensePath()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	data, err := json.MarshalIndent(userLicense{LicenseKey: key}, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		return "", err
	}
	return path, nil
}

// readUserLicense returns the key from the per-user license file, or "" if absent or
// unreadable. SOFT on every error (a malformed user file must NEVER break config
// loading — the hook must still load and fail open); it just means "no user key".
func readUserLicense() string {
	path, err := UserLicensePath()
	if err != nil {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Warn("could not read user license file; ignoring", "path", path, "err", err.Error())
		}
		return ""
	}
	var u userLicense
	if err := json.Unmarshal(data, &u); err != nil {
		slog.Warn("user license file is malformed; ignoring", "path", path, "err", err.Error())
		return ""
	}
	return u.LicenseKey
}

// UserLicenseKey returns the key from the per-user license file, or "".
//
// Exported for the rejected-key recovery (client/internal/enroll), which needs to name the
// credential this machine is using WITHOUT requiring a full, valid Config: Load fails outright on
// a missing server_url, so a recovery built on it would silently no-op in exactly the degraded
// situations it exists for — and did, until a test caught it.
//
// ⚠️ IT READS THE FILE, NOT THE RESOLVED KEY. If a key came from $LEOPREVENT_LICENSE_KEY this
// returns a different value (or none). That is the honest behaviour rather than a gap: an
// env-provided key cannot be replaced by enrolment anyway, since the env wins the resolution
// above, so there is nothing for a recovery to do in that case.
func UserLicenseKey() string { return readUserLicense() }

// Config is the resolved client configuration.
type Config struct {
	ServerURL string `json:"server_url"`
	Tier      string `json:"tier"`
	// LicenseKey is the opaque customer credential sent as a Bearer token on every
	// request. OPTIONAL here: a missing key must NOT break config loading (the hook
	// must still load and fail open) — instead the server rejects an unauthenticated
	// request and the client fails open (no review). This is the per-customer secret
	// in the shipped leoprevent.json.
	LicenseKey string `json:"license_key"`
	// ResolveImports gates the CLOUD-tier cross-file context feature: resolve the
	// in-repo files the changed code imports and calls into, and send them so the
	// server can judge a sink that lives one import away. nil ⇒ ENABLED by default
	// (a pointer so an explicit `false` in leoprevent.json can disable it; env
	// $LEOPREVENT_RESOLVE_IMPORTS overrides either way). Widens cloud-tier egress
	// (imported files leave the machine) — see the egress non-negotiable.
	ResolveImports *bool `json:"resolve_imports,omitempty"`
	// EnrollToken is the org enrolment token. OPTIONAL, and deliberately not required for anything:
	// a deployment that hands developers their keys directly never sets it, and a missing one just
	// means no enrolment is attempted. Never a review credential.
	EnrollToken string `json:"enroll_token,omitempty"`
	// DashboardURL is the customer dashboard origin the `mcp` subcommand reads stats from
	// (LEO-88). OPTIONAL and unused by every other path — the review loop never touches it,
	// so a config without it reviews exactly as before and only `leoprevent mcp` refuses.
	//
	// ⚠️ THERE IS NO COMPILED-IN DEFAULT, deliberately, and the same reasoning as `--agent`:
	// a fallback origin baked into the binary would send one deployment's developers to
	// another deployment's dashboard, silently and with a valid-looking answer. An on-prem
	// install sets it in leoprevent.json beside server_url; the release generates it.
	DashboardURL string `json:"dashboard_url,omitempty"`
}

// ResolveImportsEnabled reports whether the cloud tier should resolve cross-file
// imported context. Default ON; an explicit `false` (file) or falsey env disables.
func (c *Config) ResolveImportsEnabled() bool {
	return c.ResolveImports == nil || *c.ResolveImports
}

// isFalsey matches the same disable values as $LEOPREVENT_AUDIT (logx) so the env
// toggles agree across the codebase.
func isFalsey(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "0", "false", "off", "no":
		return true
	}
	return false
}

// Load resolves config from the shipped leoprevent.json (overlaid by env).
func Load() (*Config, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("config: locate executable: %w", err)
	}
	// Resolve symlinks so config is found next to the REAL binary (matching the
	// install path, which also EvalSymlinks) — a symlinked launcher otherwise looks
	// in the wrong dir, misses leoprevent.json, and fails open with no review.
	if resolved, lerr := filepath.EvalSymlinks(exe); lerr == nil {
		exe = resolved
	}
	// Binary is at <plugin>/bin/; the shipped config is at <plugin>/leoprevent.json.
	return resolve(filepath.Join(filepath.Dir(exe), "..", FileName))
}

// resolve reads the optional config file at path, overlays env overrides, applies
// the default tier, and validates.
func resolve(path string) (*Config, error) {
	var c Config
	if data, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(data, &c); err != nil {
			return nil, fmt.Errorf("config: parse %s: %w", path, err)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}

	// Per-user license file (update-proof; written by `set-license`). Overlays the
	// plugin json's key — which is empty for a marketplace install — and is in turn
	// overridden by $LEOPREVENT_LICENSE_KEY below.
	if key := readUserLicense(); key != "" {
		c.LicenseKey = key
	}

	if v := os.Getenv(EnvServerURL); v != "" {
		c.ServerURL = v
	}
	if v := os.Getenv(EnvTier); v != "" {
		c.Tier = v
	}
	if v := os.Getenv(EnvLicenseKey); v != "" {
		c.LicenseKey = v
	}
	if v := os.Getenv(EnvEnrollToken); v != "" {
		c.EnrollToken = v
	}
	if v := os.Getenv(EnvDashboardURL); v != "" {
		c.DashboardURL = v
	}
	if v := os.Getenv(EnvResolveImports); v != "" {
		enabled := !isFalsey(v)
		c.ResolveImports = &enabled
	}
	if c.Tier == "" {
		c.Tier = DefaultTier
	}

	if c.ServerURL == "" {
		return nil, fmt.Errorf("config: server_url not set (shipped %s missing it, $%s unset)", FileName, EnvServerURL)
	}
	if c.Tier != TierCloud && c.Tier != TierLocal {
		return nil, fmt.Errorf("config: tier must be %q or %q, got %q", TierCloud, TierLocal, c.Tier)
	}
	warnInsecureCloudURL(&c)
	return &c, nil
}

// warnInsecureCloudURL logs (does NOT fail) when the cloud tier points at a
// non-HTTPS, non-loopback server. The cloud tier egresses the Bearer license key +
// the dev's code, prompt and PII, so a plaintext http:// target to a REMOTE host
// sends all of that in the clear. A localhost http:// is fine (dev / self-hosted),
// so only a remote http:// is flagged. A warning, not an error — config must still
// load and the hook still fail open; this just makes the misconfig visible in
// client.log instead of silently shipping secrets unencrypted.
func warnInsecureCloudURL(c *Config) {
	if c.Tier != TierCloud {
		return
	}
	u, err := url.Parse(c.ServerURL)
	if err != nil || u.Scheme != "http" {
		return
	}
	switch u.Hostname() {
	case "localhost", "127.0.0.1", "::1":
		return
	}
	slog.Warn("cloud server_url is plaintext http:// to a remote host — license key + code + prompt + PII will egress UNENCRYPTED; use https://",
		"server_url", c.ServerURL)
}
