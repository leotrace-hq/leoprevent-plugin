// Package update surfaces a once-per-day "a newer LeoPrevent is available" nag.
//
// Design — how updates reach developers: the client already
// POSTs the server on every Stop, and the server stamps the latest client version
// onto every response header (X-LeoPrevent-Latest-Version). So we learn "latest"
// for free — no extra network, no GitHub poll from the dev's machine (which a
// locked-down, allowlist-only environment would block). Two halves:
//
//   - RecordLatest: called from apiclient when it sees the header — persists the
//     advertised latest into a small per-user cache file.
//   - PendingNag: called on UserPromptSubmit (the single-writer, no-decision hook
//     channel — the Stop path is reserved for the re-wake) — compares the running
//     version to the cached latest and, if behind, returns the nag at most once per
//     day PER INSTALL (keyed agent@version: a single missed notice shouldn't be the
//     last one a dev ever sees, a heavy multi-session day shouldn't repeat it every
//     session, and one agent's install consuming the nag must not silence another's).
//
// Everything here is BEST-EFFORT and FAIL-SILENT: any parse/IO error means no nag,
// never a broken hook. The nag lags the discovery by one turn (learn on Stop N,
// show on UserPromptSubmit N+1); for an update notice that is immaterial.
package update

import (
	"encoding/json"
	"maps"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

// renagInterval is how long a shown nag suppresses the next one for the same
// install (agent@version). A newer latest re-arms immediately regardless.
const renagInterval = 24 * time.Hour

// pruneWindow bounds the warned_by map: entries older than this are dropped on
// save, so the cache doesn't accrue keys across agent/version history.
const pruneWindow = 30 * 24 * time.Hour

// warnedEntry records one shown nag: WHICH latest was advertised (so a newer
// latest re-arms the nag for that install) and when (the daily throttle).
type warnedEntry struct {
	Latest string `json:"latest"`
	At     string `json:"at"` // RFC3339; empty/garbled reads as "long ago"
}

// state is the persisted cache. Latest is SHARED — any agent's server contact
// learns it for all. The warned marker is keyed "agent@current-version": the
// agents have separate installs with separate update actions, so each deserves
// its own daily reminder — and a STALE install (e.g. an old marketplace copy a
// second surface still runs) can only ever suppress ITSELF, never a newer
// install of the same agent (the ghost-eats-the-nag bug: a 0.2.1 copy consumed
// the shared once-a-day marker on a surface that didn't render it, silencing
// the 0.2.2 install the developer was actually watching).
//
// Migration: the pre-map cache used flat "warned"/"warned_at" fields; they are
// deliberately NOT decoded (a re-nag once after upgrading is the self-heal,
// same pattern as the warned_at migration before it). While an OLD client
// coexists on the same file its saves drop warned_by — worst case a duplicate
// nag that day, never a missed one; it disappears when the stale install goes.
type state struct {
	Latest   string                 `json:"latest"`
	WarnedBy map[string]warnedEntry `json:"warned_by,omitempty"`
	How      map[string]string      `json:"how,omitempty"` // server update wording, see RecordHow
}

// userConfigDir resolves the OS per-user config dir; a package var so tests can
// point it at a temp dir (mirrors config.userConfigDir).
var userConfigDir = os.UserConfigDir

// now is a seam so tests can step the clock across the re-nag interval.
var now = time.Now

// SetNowForTest overrides the clock and returns a restore func.
func SetNowForTest(fn func() time.Time) func() {
	prev := now
	now = fn
	return func() { now = prev }
}

// SetUserConfigDirForTest overrides the config-dir resolver and returns a restore
// func.
func SetUserConfigDirForTest(dir string) func() {
	prev := userConfigDir
	userConfigDir = func() (string, error) { return dir, nil }
	return func() { userConfigDir = prev }
}

// cachePath is <UserConfigDir>/leoprevent/update.json.
func cachePath() (string, error) {
	dir, err := userConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "leoprevent", "update.json"), nil
}

func load() state {
	var s state
	path, err := cachePath()
	if err != nil {
		return s
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return s
	}
	_ = json.Unmarshal(data, &s) // garbled → zero state, no nag
	return s
}

func save(s state) {
	path, err := cachePath()
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return
	}
	if data, err := json.Marshal(s); err == nil {
		_ = os.WriteFile(path, data, 0o600)
	}
}

// RecordLatest persists the latest version the server advertised. Ignores an empty
// or non-semver value (an old server that sends no header, or a garbled one). The
// warned markers are preserved, so we don't immediately re-nag for a version we
// already showed — but if latest moved forward, PendingNag re-arms because each
// entry records which latest it nagged for.
func RecordLatest(latest string) {
	if _, ok := parse(latest); !ok {
		return
	}
	s := load()
	if s.Latest == latest {
		return // no change, avoid a needless write
	}
	s.Latest = latest
	save(s)
}

// PendingNag reports whether the running version (current) is behind the cached
// latest and due a nag for THIS install (keyed agent@current). On true it stamps
// the install's warned entry (so each install fires at most once per
// renagInterval while behind; a newer latest re-arms it immediately) and returns
// the latest version string. A non-semver current (e.g. "dev") never nags.
func PendingNag(agent, current string) (latest string, ok bool) {
	cur, curOK := parse(current)
	if !curOK {
		return "", false
	}
	s := load()
	lat, latOK := parse(s.Latest)
	if !latOK || !less(cur, lat) {
		return "", false // unknown, equal, or ahead — nothing to say
	}
	key := agent + "@" + current
	if e, exists := s.WarnedBy[key]; exists && e.Latest == s.Latest && !warnedLongAgo(e.At) {
		return "", false // this install nagged for this exact latest within the interval
	}
	if s.WarnedBy == nil {
		s.WarnedBy = map[string]warnedEntry{}
	}
	s.WarnedBy[key] = warnedEntry{Latest: s.Latest, At: now().UTC().Format(time.RFC3339)}
	pruneStale(s.WarnedBy)
	save(s)
	return s.Latest, true
}

// warnedLongAgo reports whether the recorded nag time is at least renagInterval in
// the past. An empty or garbled timestamp reads as "long ago" → re-nag once and
// self-heal by stamping a real time.
func warnedLongAgo(warnedAt string) bool {
	t, err := time.Parse(time.RFC3339, warnedAt)
	if err != nil {
		return true
	}
	return now().Sub(t) >= renagInterval
}

// pruneStale drops warned entries that are garbled or older than pruneWindow,
// bounding the map across agent/version history.
func pruneStale(m map[string]warnedEntry) {
	for k, e := range m {
		t, err := time.Parse(time.RFC3339, e.At)
		if err != nil || now().Sub(t) >= pruneWindow {
			delete(m, k)
		}
	}
}

// licenseNagKey is the warned_by key for the "no license set" nag. It is keyed by
// agent only (not version): the missing-license state is a property of the INSTALL,
// not of which build is running, so upgrading shouldn't re-arm it immediately.
func licenseNagKey(agent string) string { return agent + "@no-license" }

// PendingLicenseNag reports whether the developer should be reminded that no
// license key is set — at most once per renagInterval per agent. It reuses the
// update cache's warned_by map (same file, same throttle, same pruning) because
// the two nags share one delivery channel and one "don't spam the dev" budget.
//
// Unlike PendingNag there is no version to compare: the caller has already
// established the key is missing, so this is purely the throttle.
func PendingLicenseNag(agent string) bool {
	s := load()
	key := licenseNagKey(agent)
	if e, exists := s.WarnedBy[key]; exists && !warnedLongAgo(e.At) {
		return false
	}
	if s.WarnedBy == nil {
		s.WarnedBy = map[string]warnedEntry{}
	}
	// Latest is empty: this nag isn't about a version, so nothing re-arms it early.
	s.WarnedBy[key] = warnedEntry{At: now().UTC().Format(time.RFC3339)}
	pruneStale(s.WarnedBy)
	save(s)
	return true
}

// LicenseMessage is the terminal-half nag for a missing license key.
func LicenseMessage(
	agent string,
) string {
	return "⚠️  LeoPrevent: no license key set. Your turns are NOT being security-reviewed. " + HowLicense(agent)
}

func HowLicense(
	agent string,
) string {
	switch agent {
	case "codex", "copilot":
		return "Ask your agent to run the installed LeoPrevent binary with login (remote sessions: login --no-browser). " +
			"Approve in your browser and wait for LeoPrevent · Connected."
	default:
		return "Connect with /leoprevent:login, approve in your browser, and wait for LeoPrevent · Connected. " +
			"For remote sessions, ask your agent to run the installed LeoPrevent binary with login --no-browser."
	}
}

// LicenseContextMessage is the missing-license nag phrased for INJECTION into the
// model's turn, so it reaches the desktop app and web UI (which never render a
// systemMessage). Same shape and rationale as ContextMessage — see its doc for why
// the wording leads with the instruction and asks for a quoted, labelled line.
//
// This one matters more than the update nag: an unlicensed install reviews NOTHING,
// and every other channel that would say so is either invisible on this surface or
// never fires. It is still model-mediated, so it is a visibility layer, not a
// guarantee.
func LicenseContextMessage(agent string) string {
	return "Begin your reply with exactly this markdown, before anything else:\n\n" +
		"> ⚠️ **LeoPrevent** · automated plugin notice, not part of your request\n" +
		"> \n" +
		"> No license key is set, so your changes are **not** being security-reviewed. " +
		HowLicense(agent) + "\n\n---\n\n" +
		"Then continue with the developer's request as normal, without mentioning this again."
}

// Message is the developer-facing nag (the terminal systemMessage), for the given agent
// ("claude" | "codex" | "copilot"): the action first, then the versions, then the
// fallback. Kept here so the wording lives beside the decision.
func Message(
	agent string,
	environment string,
	current string,
	latest string,
) string {
	lead, alt := How(agent, environment)
	msg := "⚠️ " + sentence(lead) + " LeoPrevent " + latest + " is available, you're on " + current + "."
	if alt != "" {
		msg += " " + alt
	}
	return msg
}

// sentence ends s with a full stop unless it already ends a sentence.
func sentence(s string) string {
	if strings.HasSuffix(s, ".") || strings.HasSuffix(s, "!") || strings.HasSuffix(s, "?") {
		return s
	}
	return s + "."
}

// How is the agent-specific "here's how to update" instruction in two parts: the LEAD
// (the one action to take, rendered as the notice's headline) and the ALT (a fallback
// sentence, possibly empty). Shared by both the terminal message and the injected
// context so the two can never drift apart.
//
// The wording is SERVER-CONTROLLED: the server stamps it on every response
// (wire.UpdateHowHeader) and RecordHow caches it beside the advertised latest version,
// so a reword is one server deploy rather than a plugin release that only reaches
// installs after they have already updated. The compiled-in defaults below are what an
// old server, an unreachable one, or a rejected value fall back to. Change wording on
// the SERVER (server/internal/api/messaging.go), and keep these in step with it.
//
// Server keys are "<agent>.lead" / "<agent>.alt", optionally narrowed to a surface as
// "<agent>:<environment>.lead"; each part is looked up on its own and the surface-
// specific one wins.
//
// Phrased as "Ask Claude", not "ask me": How() feeds BOTH Message() (the terminal
// systemMessage, which is the plugin speaking) and ContextMessage() (which the agent
// restates). "Ask me to update it" reads as nonsense in the first.
func How(
	agent string,
	environment string,
) (lead string, alt string) {
	s := load()
	pick := func(part, fallback string) string {
		if v := s.How[agent+":"+environment+"."+part]; v != "" {
			return v
		}
		if v := s.How[agent+"."+part]; v != "" {
			return v
		}
		return fallback
	}
	dl, da := defaultHow(agent, environment)
	return pick("lead", dl), pick("alt", da)
}

// defaultHow is the compiled-in update instruction per agent. It never says the plugin
// updates itself: Claude Desktop third-party marketplaces default to auto-update off, so
// that sentence left installs waiting for an update that never came (LEO-391). Desktop
// keeps its click-path because it has no /plugin command.
func defaultHow(
	agent string,
	environment string,
) (lead string, alt string) {
	switch agent {
	case "codex":
		return "Run `codex plugin marketplace upgrade`, then re-add the plugin", ""
	case "copilot":
		return `Run "Chat: Update Plugins" from the VS Code command palette, then reload`, ""
	default: // claude
		lead = `Ask Claude to "update the LeoPrevent plugin"`
		if environment == wire.EnvClaudeDesktop {
			return lead, "Or open Customize → Plugins → Browse → Code, open the leotrace menu, then choose Check for updates."
		}
		return lead, "Or run `/plugin marketplace update leotrace` and update leoprevent in `/plugin`."
	}
}

const (
	maxHowKeys  = 16
	maxHowKey   = 48
	maxHowRunes = 300
)

// RecordHow caches the server's update wording (wire.UpdateHowHeader, a URL-encoded
// query string of key=instruction, see How for the keys). Each entry is sanitised on its
// own: a key must be lowercase letters, digits, '-', ':' or '.', and a value one line of printable text under
// maxHowRunes. A header that yields no valid entry changes nothing, so a garbled header
// can never blank the wording; a valid one REPLACES the cache, so the server can retire
// a surface-specific override by omitting it.
func RecordHow(raw string) {
	if raw == "" {
		return
	}
	q, err := url.ParseQuery(raw)
	if err != nil {
		return
	}
	clean := map[string]string{}
	for k, vs := range q {
		if len(clean) >= maxHowKeys || !validHowKey(k) || len(vs) == 0 {
			continue
		}
		if v, ok := cleanHow(vs[0]); ok {
			clean[k] = v
		}
	}
	if len(clean) == 0 {
		return
	}
	s := load()
	if maps.Equal(s.How, clean) {
		return
	}
	s.How = clean
	save(s)
}

func validHowKey(k string) bool {
	if k == "" || len(k) > maxHowKey {
		return false
	}
	for _, r := range k {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == ':' || r == '.') {
			return false
		}
	}
	return true
}

func cleanHow(v string) (string, bool) {
	v = strings.TrimSpace(v)
	if v == "" || utf8.RuneCountInString(v) > maxHowRunes || !utf8.ValidString(v) {
		return "", false
	}
	for _, r := range v {
		if unicode.IsControl(r) {
			return "", false
		}
	}
	return v, true
}

// ContextMessage is the same nag phrased for INJECTION into the model's turn
// (UserPromptSubmit additionalContext) rather than for direct display. The
// systemMessage half of the nag is terminal-only — it is not forwarded over the
// stream-json protocol, so the desktop app and web UI never receive it. Assistant
// text is the one channel every surface renders, so on those surfaces the notice
// only lands if the agent restates it; hence the explicit instruction here.
//
// The wording is LOAD-BEARING and was tuned against a live agent, so change it only
// with a re-test. It leads with the instruction, keeps it to one short imperative
// sentence, and then states the facts. An earlier draft buried the instruction
// mid-sentence and closed with "do not treat this as part of their request" — the
// agent read that as permission to ignore it and said nothing (observed on a bare
// "hi" turn), which silently defeats the whole channel.
//
// It asks for ONE line and to continue with the request, so the nag can't derail the
// turn the developer actually asked for. Being model-mediated the phrasing may still
// vary and can occasionally be skipped — acceptable for an update notice (the
// marketplace can auto-update anyway); never use this channel for anything exact.
// It asks for a QUOTED block followed by a rule, so the notice reads as plugin chrome
// rather than as part of the answer — without it the nag renders as an ordinary opening
// paragraph and looks like the agent's own remark. The block leads with the ACTION as
// its bold headline, then the versions and the fallback, and ends with an italic line
// marking it as a plugin notice (LEO-391).
func ContextMessage(
	agent string,
	environment string,
	current string,
	latest string,
) string {
	lead, alt := How(agent, environment)
	body := "LeoPrevent " + latest + " is available, you're on " + current + "."
	if alt != "" {
		body += " " + alt
	}
	return "Begin your reply with exactly this markdown, before anything else:\n\n" +
		"> ⚠️ **" + strings.TrimSuffix(lead, ".") + "**\n" +
		"> \n" +
		"> " + body + "\n" +
		"> \n" +
		"> *Automated plugin notice, not part of your request.*\n\n---\n\n" +
		"Then continue with the developer's request as normal, without mentioning this again."
}

// parse turns "0.1.5" into comparable [major, minor, patch]. Extra dot-segments are
// ignored; a trailing pre-release/build suffix on the patch (e.g. "5-rc1") is
// truncated at the first non-digit. Returns ok=false for anything without at least
// one numeric segment (e.g. "dev", "").
//
// The suffix truncation is LOAD-BEARING for the dev channel (LEO-57): a dev build
// carries a prerelease version ("0.2.16-dev.<sha>") which parses to the SAME base
// [0,2,16] as its eventual release "0.2.16", so a dev build is never advertised as
// NEWER than that release — a production install on the base version never nags off
// a dev release. (The primary guarantee is still environment isolation: a dev build
// is advertised only by the dev server, which prod installs never contact. This
// truncation is the same-base safety net.)
func parse(v string) ([3]int, bool) {
	var out [3]int
	v = strings.TrimSpace(strings.TrimPrefix(v, "v"))
	if v == "" {
		return out, false
	}
	parts := strings.SplitN(v, ".", 4)
	any := false
	for i := 0; i < 3 && i < len(parts); i++ {
		n := leadingInt(parts[i])
		if n < 0 {
			return out, false
		}
		out[i] = n
		any = true
	}
	return out, any
}

// leadingInt parses the leading run of digits of s (so "5-rc1" → 5). Returns -1 if
// s has no leading digit.
func leadingInt(s string) int {
	end := 0
	for end < len(s) && s[end] >= '0' && s[end] <= '9' {
		end++
	}
	if end == 0 {
		return -1
	}
	n, err := strconv.Atoi(s[:end])
	if err != nil {
		return -1
	}
	return n
}

// less reports whether a < b component-wise (major, then minor, then patch).
func less(a, b [3]int) bool {
	for i := 0; i < 3; i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}
