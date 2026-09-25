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
//     can never clobber the key — the production way a dev sets their key. It holds ONE
//     KEY PER CHANNEL (see userLicense), so the dev and prod plugins on one machine each
//     resolve their own.
//  3. Environment override — $LEOPREVENT_SERVER_URL / $LEOPREVENT_TIER /
//     $LEOPREVENT_LICENSE_KEY. OPTIONAL, for CI / dev / staging only. NOT the sole
//     production mechanism: a GUI-launched agent doesn't inherit a shell's env.
//
// The client reads NO project .env and never the working directory — only its own
// shipped config + the namespaced overrides above. A missing server_url is a hard
// error → the hook fails open (it never reviews against a misconfigured target).
package config

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	pathpkg "path"
	"path/filepath"
	"strings"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
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
	// EnvDashboardURL overrides the customer dashboard origin the read subcommands
	// (`stats`, `mcp`) read from. A SEPARATE deployment from the review server — the
	// dashboards read Mongo directly and never call the Go server (CLAUDE.md), so the two
	// are different hosts and one URL could not serve both.
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

const UserMCPToolsFile = "mcp-tools.json"

func UserMCPToolsPath() (string, error) {
	dir, err := userConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "leoprevent", UserMCPToolsFile), nil
}

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

// UserChannelsFile holds one key per channel, beside the license file.
const UserChannelsFile = "channels.json"

// UserChannelsPath is <UserConfigDir>/leoprevent/channels.json.
func UserChannelsPath() (string, error) {
	dir, err := userConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "leoprevent", UserChannelsFile), nil
}

// UserLicensePath is <UserConfigDir>/leoprevent/license.json.
func UserLicensePath() (string, error) {
	dir, err := userConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "leoprevent", UserLicenseFile), nil
}

// channelKey is one channel's credential: the key minted on that server, and the dashboard
// origin it was minted with.
type channelKey struct {
	LicenseKey   string `json:"license_key"`
	DashboardURL string `json:"dashboard_url,omitempty"`
}

// userLicense is the per-user license file, unchanged in shape.
//
// ⚠️ ONE KEY PER CHANNEL, AND THE MAP LIVES IN A FILE OF ITS OWN. A machine can run the dev
// plugin and the prod plugin at once — the normal state for anyone developing LeoPrevent — and a
// key minted on one server is not a key on the other. This file holds one, so whichever plugin
// logged in last owned it; the other matched nothing, sent no Bearer token at all, and failed
// open on every turn with `401 missing license`. Silent, because failing open is silent: found
// on a laptop that had gone sixteen hours reviewing nothing in Claude Code while Codex worked.
//
// The per-channel keys are therefore in channels.json BESIDE this file, not a field inside it.
// An older binary marshals this struct on every write, which would drop a field it does not know
// about — so a single `set-license` from the un-upgraded plugin would silently flatten the
// machine back to one key, during exactly the mixed-version window the fix is for. A separate
// file is one an older binary cannot reach.
//
// This file keeps holding the flat key, read AND written, mirroring the most recent write: that
// is what an older binary reads, and it is the old last-login-wins behaviour unchanged.
// device_id stays here and stays SHARED — it names the MACHINE, not the credential, and
// splitting it per channel would make one laptop enrol as two, taking two slots in its own
// per-person key set (see EnsureDeviceID).
type userLicense struct {
	LicenseKey   string `json:"license_key,omitempty"`
	ServerURL    string `json:"server_url,omitempty"`
	DashboardURL string `json:"dashboard_url,omitempty"`
	// DeviceID identifies THIS MACHINE to enrolment, so a re-enrolment replaces this machine's
	// own key rather than adding another (LEO-168). NOT a credential and not a secret: it names
	// a device, and the server checks the asserted address against the account's allowlist
	// exactly as before.
	//
	// It lives here rather than in a file of its own because the two facts have the same
	// lifetime and the same home, and one file is one thing to keep 0600. Absent on any file
	// written before this existed, which the server tolerates.
	DeviceID string `json:"device_id,omitempty"`
}

// SaveLicense writes key to the per-user license file (0600), creating the dir, and
// returns the path written. Used by the `set-license` subcommand.
//
// ⚠️ IT PRESERVES AN EXISTING device_id. Overwriting the file wholesale would discard it, so a
// developer running `set-license` would silently become a NEW machine to the server and take a
// second slot in their own per-person key set — leaving the entry their previous id held live
// until the cap evicted it.
func SaveLicense(key string) (string, error) {
	return saveUserLicense(func(u *userLicense) { u.setChannel("", "", key) })
}

// SaveLicenseFor stores key as this plugin's CHANNEL credential, leaving every other channel
// alone. Used by `set-license`, which knows the server it is being run against because the
// plugin it lives in ships one.
//
// ⚠️ IT DOES NOT TOUCH THE OTHER CHANNEL. Pasting a dev key used to overwrite the one prod key
// the machine had, so the prod plugin silently stopped reviewing — the shape this whole map
// exists to remove.
func SaveLicenseFor(key, serverURL, dashboardURL string) (string, error) {
	return saveUserLicense(func(u *userLicense) { u.setChannel(serverURL, dashboardURL, key) })
}

// setChannel records key under its channel and mirrors it into the flat fields.
//
// The mirror is what an OLDER plugin binary on this machine reads, and a machine running two
// plugin versions is the normal case here, so dropping it would break the setup this fixes. It
// tracks the most recent write, which is the old last-one-wins behaviour exactly.
func (u *userLicense) setChannel(serverURL, dashboardURL, key string) {
	server, dashboard := normaliseURL(serverURL), normaliseURL(dashboardURL)
	// Folding through channels() first is what carries an existing key over: on an upgraded
	// machine it is only in the flat fields, and on a machine an older binary has written since,
	// the flat fields are newer than the map.
	next := u.channels()
	next[server] = channelKey{LicenseKey: key, DashboardURL: dashboard}
	writeChannelsFile(next)
	u.LicenseKey, u.ServerURL, u.DashboardURL = key, server, dashboard
}

// readChannelsFile decodes channels.json, or nil. Soft on every error, for the same reason as
// the license file: a malformed file means "nothing stored", never a broken hook.
func readChannelsFile() map[string]channelKey {
	path, err := UserChannelsPath()
	if err != nil {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Warn("could not read user channels file; ignoring", "path", path, "err", err.Error())
		}
		return nil
	}
	var keys map[string]channelKey
	if err := json.Unmarshal(data, &keys); err != nil {
		slog.Warn("user channels file is malformed; ignoring", "path", path, "err", err.Error())
		return nil
	}
	return keys
}

// writeChannelsFile replaces channels.json (0600). Best-effort: the flat fields in license.json
// still carry the key just written, so a failure here costs the OTHER channel's key, never this
// one — the same single-key behaviour the machine had before.
func writeChannelsFile(keys map[string]channelKey) {
	path, err := UserChannelsPath()
	if err != nil {
		return
	}
	data, err := json.MarshalIndent(keys, "", "  ")
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return
	}
	if err := writeFileAtomic(path, append(data, '\n')); err != nil {
		slog.Warn("could not save the per-channel license keys", "path", path, "err", err.Error())
	}
}

// saveUserLicense reads the per-user file, applies mutate, and writes it back — so each caller
// changes one field without having to know what the others are.
func saveUserLicense(mutate func(*userLicense)) (string, error) {
	path, err := UserLicensePath()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	u := readUserLicenseFile()
	mutate(&u)
	data, err := json.MarshalIndent(u, "", "  ")
	if err != nil {
		return "", err
	}
	if err := writeFileAtomic(path, append(data, '\n')); err != nil {
		return "", err
	}
	return path, nil
}

// writeFileAtomic replaces path via a temp file in the same directory and a rename, so a reader
// never sees a half-written credential and a failed write never destroys the previous one.
// os.CreateTemp is already 0600, which is what both files need.
func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".license-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err = tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// EnsureDeviceID returns this machine's device id, generating and PERSISTING one if it has none.
//
// ⚠️ IT PERSISTS BEFORE THE CALLER ENROLS, DELIBERATELY. An id generated, sent, and then lost
// because the key write failed would make the next attempt a different machine, so a machine
// stuck in that state would burn one slot of its own key set per attempt. A device id is not a
// credential, so writing it early costs nothing.
//
// Best-effort: on any failure it returns whatever it has, empty included. The server accepts an
// empty id and falls back to matching on (device, os, arch), so the worst case is the coarser
// identity an older client already gets — never a refused enrolment.
func EnsureDeviceID() string {
	if id := readUserLicenseFile().DeviceID; id != "" {
		return id
	}
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		slog.Warn("could not generate a device id; enrolment will identify this machine by hostname",
			"err", err.Error())
		return ""
	}
	id := hex.EncodeToString(b[:])
	if _, err := saveUserLicense(func(u *userLicense) { u.DeviceID = id }); err != nil {
		// Returned anyway: an unpersisted id is still better than none for THIS enrolment, and
		// the next turn simply generates another.
		slog.Warn("could not save this machine's device id", "err", err.Error())
	}
	return id
}

// readUserLicense returns the key from the per-user license file, or "" if absent or
// unreadable. SOFT on every error (a malformed user file must NEVER break config
// loading — the hook must still load and fail open); it just means "no user key".
func readUserLicense() string { return readUserLicenseFile().LicenseKey }

// readUserLicenseFile decodes the whole per-user file, or the zero value. Soft on every error,
// for the reason above: a malformed file means "nothing stored", never a broken hook.
func readUserLicenseFile() userLicense {
	path, err := UserLicensePath()
	if err != nil {
		return userLicense{}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Warn("could not read user license file; ignoring", "path", path, "err", err.Error())
		}
		return userLicense{}
	}
	var u userLicense
	if err := json.Unmarshal(data, &u); err != nil {
		slog.Warn("user license file is malformed; ignoring", "path", path, "err", err.Error())
		return userLicense{}
	}
	return u
}

// normaliseURL trims the trailing slash the two sides disagree about: leoprevent.json ships
// "https://api.leotrace.io" and a login records the same origin, but either may carry a slash.
func normaliseURL(u string) string { return strings.TrimRight(u, "/") }

// channels returns the file's keys by channel, folding a flat legacy file into the same shape.
//
// A flat file written before this existed becomes one entry under its own server_url — or, when
// it records none, a CHANNEL-LESS entry under "". A channel-less key is usable by any plugin,
// which is deliberate and not a hole: that is what enrolment writes (SaveLicense clears the URLs),
// and what every file written before logins recorded an origin looks like. Refusing those would
// un-license every machine that has one the moment it updates.
func (u userLicense) channels() map[string]channelKey {
	out := map[string]channelKey{}
	for server, k := range readChannelsFile() {
		if k.LicenseKey != "" {
			out[normaliseURL(server)] = k
		}
	}
	// ⚠️ THE FLAT ENTRY WINS FOR ITS OWN CHANNEL, AND THAT ORDER IS THE WHOLE POINT.
	//
	// EVERY version writes the flat fields; only a new one writes the map. So on a machine
	// running two plugin versions — the machine this exists for — the flat fields are the more
	// recent signal whenever the older binary wrote last. Letting the map win instead would
	// serve the key from before that login, indefinitely, and the developer would be looking at
	// a `set-license` they had just run and a 401 saying it was not accepted.
	if u.LicenseKey != "" {
		out[normaliseURL(u.ServerURL)] = channelKey{LicenseKey: u.LicenseKey, DashboardURL: normaliseURL(u.DashboardURL)}
	}
	return out
}

// keyFor returns the credential stored for this plugin's channel, or "" when the machine holds
// none for it.
//
// ⚠️ "" IS THE RIGHT ANSWER, NOT A FALLBACK TO SOMEBODY ELSE'S KEY. A key minted on dev is real,
// just not real on prod: sending it would 401, and — worse — a prod key sent to dev would file a
// customer's code against the dev cluster, where nobody looks. The server is the tenant boundary,
// so the channel is part of the credential's identity.
func (u userLicense) keyFor(serverURL, dashboardURL string) string {
	byChannel := u.channels()
	if k, ok := byChannel[normaliseURL(serverURL)]; ok {
		// A recorded dashboard must still agree: two deployments can share a review server and
		// differ downstream, and that was already the rule before keys were per channel.
		if k.DashboardURL == "" || k.DashboardURL == normaliseURL(dashboardURL) {
			return k.LicenseKey
		}
		return ""
	}
	return byChannel[""].LicenseKey
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
	ServerURL string                   `json:"server_url"`
	Tier      string                   `json:"tier"`
	MCPTools  []transcript.MCPToolRule `json:"mcp_tools,omitempty"`
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
	// DashboardURL is the customer dashboard origin the `stats` and `mcp` subcommands read
	// from (LEO-88, LEO-248). OPTIONAL and unused by the review loop, which never touches it
	// — so a config without it reviews exactly as before and only those two refuse.
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

func (c *Config) MCPToolRules() []transcript.MCPToolRule {
	return append(transcript.DefaultMCPToolRules(), c.MCPTools...)
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
	if userPath, err := UserMCPToolsPath(); err == nil {
		if data, err := os.ReadFile(userPath); err == nil {
			var userConfig struct {
				MCPTools []transcript.MCPToolRule `json:"mcp_tools"`
			}
			if err := json.Unmarshal(data, &userConfig); err != nil {
				return nil, fmt.Errorf("config: parse %s: %w", userPath, err)
			}
			c.MCPTools = append(c.MCPTools, userConfig.MCPTools...)
		} else if !os.IsNotExist(err) {
			return nil, fmt.Errorf("config: read %s: %w", userPath, err)
		}
	}

	if v := os.Getenv(EnvServerURL); v != "" {
		c.ServerURL = v
	}
	if v := os.Getenv(EnvTier); v != "" {
		c.Tier = v
	}
	if v := os.Getenv(EnvEnrollToken); v != "" {
		c.EnrollToken = v
	}
	if v := os.Getenv(EnvDashboardURL); v != "" {
		c.DashboardURL = v
	}
	if key := readUserLicenseFile().keyFor(c.ServerURL, c.DashboardURL); key != "" {
		c.LicenseKey = key
	}
	if v := os.Getenv(EnvLicenseKey); v != "" {
		c.LicenseKey = v
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
	for _, rule := range c.MCPTools {
		if !strings.HasPrefix(rule.Tool, "mcp__") {
			return nil, fmt.Errorf("config: mcp_tools tool %q must start with mcp__", rule.Tool)
		}
		if _, err := pathpkg.Match(rule.Tool, "mcp__example__publish"); err != nil {
			return nil, fmt.Errorf("config: invalid mcp_tools pattern %q: %w", rule.Tool, err)
		}
		if len(rule.Fields) == 0 {
			return nil, fmt.Errorf("config: mcp_tools pattern %q has no fields", rule.Tool)
		}
		for field, ext := range rule.Fields {
			if field == "" || !strings.HasPrefix(ext, ".") || strings.ContainsAny(ext, `/\\`) {
				return nil, fmt.Errorf("config: invalid mcp_tools field %q or extension %q", field, ext)
			}
		}
		if rule.Format != "" && rule.Format != "html_script" {
			return nil, fmt.Errorf("config: unknown mcp_tools format %q", rule.Format)
		}
		if rule.Format == "html_script" && (rule.Fields["hosted_location"] == "" || rule.Fields["integrity_hash"] == "") {
			return nil, fmt.Errorf("config: html_script format requires hosted_location and integrity_hash fields")
		}
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

func SaveLoginLicense(
	key, serverURL, dashboardURL, deviceID string,
) (string, error) {
	return saveUserLicense(func(u *userLicense) {
		u.setChannel(serverURL, dashboardURL, key)
		u.DeviceID = deviceID
	})
}
