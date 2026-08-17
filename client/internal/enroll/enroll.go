// Package enroll gets this machine its own license key from an organisation enrolment token.
//
// THE PROBLEM IT SOLVES ON THE CLIENT SIDE. An enterprise admin can push plugin config to every
// developer from one JSON block in the claude.ai admin console, but managed settings apply
// UNIFORMLY across an organisation — there is no per-user or per-group targeting — so the only
// credential an admin can push to 20,000 machines is one identical value. A shared license key
// would be that value, and it cannot be revoked for one person or attributed to one person.
//
// So the admin pushes an ENROLMENT token instead, in the managed `env` block, and each machine
// exchanges it for its own per-user key on the first turn that would otherwise go unreviewed. The
// key lands in the per-user license.json — outside the plugin directory, so a plugin auto-update
// cannot clobber it — and every turn after that authenticates as that developer.
//
// ⚠️ FAIL-OPEN, LIKE EVERYTHING ELSE ON THIS PATH. Every failure here returns quietly and leaves
// the turn to proceed unreviewed: a developer must never be trapped because enrolment did not
// work. The Stop path's existing skip notice is what tells them the turn was not reviewed.
//
// ⚠️ ATTEMPTED AT MOST ONCE PER SESSION. A machine whose address the admin has not authorised
// would otherwise POST to /enroll on every single Stop, forever. Once per session is enough to
// pick up an admin's fix promptly while bounding a fleet of unauthorised machines to one request
// each per session.
package enroll

import (
	"log/slog"
	"os"
	"runtime"
	"strings"

	"github.com/leotrace-hq/leoprevent-plugin/buildinfo"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/apiclient"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/config"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/notify"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/vcs"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

// throttleKey namespaces this attempt in the per-session scratch the skip notices use.
const throttleKey = "enroll_attempt"

// Ensure enrols this machine if it has no key and has been given a token, and reports whether
// cfg now carries a usable license key.
//
// It MUTATES cfg on success, so the caller's reviewer is built with the new key and the very first
// turn is reviewed rather than the second. It also persists the key, and the ORDER matters: the
// server keeps only a digest, so a key we fail to write is a key nobody can ever use again, and the
// next attempt would rotate it and invalidate whatever did get written. Persist, then use.
func Ensure(cfg *config.Config, cwd, sessionID string) bool {
	if cfg == nil {
		return false
	}
	if cfg.LicenseKey != "" {
		return true // already licensed; nothing to do
	}
	if cfg.EnrollToken == "" {
		return false // no token pushed: this deployment does not use enrolment
	}
	// CLOUD ONLY. The local tier sends no code and no metadata and has no account behind it, so
	// there is nothing for a per-user key to attribute and no seat to claim.
	if cfg.Tier != config.TierCloud {
		return false
	}
	if !notify.FirstThisSession(sessionID, throttleKey) {
		return false
	}

	// The identity we ASSERT. The server checks it against the account's allowlist before minting,
	// so this is a claim rather than a credential — but without it there is nothing to mint for,
	// and a machine with no git identity cannot be attributed to a person anyway.
	developer := vcs.Developer(cwd)
	if strings.TrimSpace(developer) == "" {
		slog.Warn("enrolment skipped: no git identity on this machine to enrol")
		return false
	}

	host, _ := os.Hostname()
	client := apiclient.New(cfg.ServerURL, "") // no license key: that is what we are here for
	resp, err := client.Enroll(cfg.EnrollToken, wire.EnrollRequest{
		Developer:     developer,
		OS:            runtime.GOOS,
		Arch:          runtime.GOARCH,
		ClientVersion: buildinfo.Version,
		Device:        host,
	})
	if err != nil {
		// Deliberately terse and deliberately not alarming: the commonest cause is an address the
		// admin has not put on the allowlist yet, which is their action and not the developer's.
		slog.Warn("enrolment failed; this turn will not be reviewed", "err", err.Error())
		return false
	}

	path, serr := config.SaveLicense(resp.LicenseKey)
	if serr != nil {
		// The key exists server-side and we cannot store it. Say so loudly: the next attempt will
		// ROTATE rather than return this one, so a silent failure here would burn a credential per
		// session and never converge.
		slog.Error("enrolled but could not save the license key; the next attempt will rotate it",
			"err", serr.Error())
		return false
	}

	cfg.LicenseKey = resp.LicenseKey
	slog.Info("enrolled this machine", "license", resp.LicenseID, "account", resp.AccountID,
		"rotated", resp.Rotated, "path", path)
	return true
}
