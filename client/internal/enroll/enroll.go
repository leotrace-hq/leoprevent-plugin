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
// ⚠️ A FIRST-TIME ENROLMENT IS ATTEMPTED AT MOST ONCE PER SESSION. A machine whose address the
// admin has not authorised would otherwise POST to /enroll on every single Stop, forever. Once
// per session is enough to pick up an admin's fix promptly while bounding a fleet of
// unauthorised machines to one request each per session.
//
// ⚠️ A RE-ENROLMENT IS BOUNDED DIFFERENTLY, AND MUST NOT SHARE THAT BUDGET. Recovering from a
// refused credential only runs for a key the server actually rejected, and is rate-limited
// machine-wide by reEnrolCooldown — both tighter than a session. Sharing the session budget
// stranded a live machine for hours: it recovered once, and every later rejection that day found
// the budget spent. See throttleKey.
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

// throttleKey namespaces a FIRST-TIME enrolment attempt in the per-session scratch the skip
// notices use.
//
// ⚠️ IT GATES THE FIRST-TIME PATH ONLY, AND A RE-ENROLMENT MUST NOT SHARE IT. Doing so was a
// live bug: a machine that recovered once in a session consumed the budget, so every later
// rejection in that session found it spent and returned without minting. A session is a
// working day on a long-running agent, which is exactly the window in which a seat is revoked
// and re-granted, or a key rotated on another machine.
//
// A re-enrolment needs no session throttle because it is already bounded twice, and both bounds
// are tighter: it only runs for a credential the server actually refused (staleKeyMarked), and
// reEnrolCooldown caps the rate machine-wide. A companion resetKey const was declared for this
// and never referenced — an unused package-level const compiles silently, so the gap looked
// closed in review while the code took throttleKey on both paths.
const throttleKey = "enroll_attempt"

// Ensure enrols this machine if it has no key and has been given a token, and reports whether
// cfg is known to carry a usable license key.
//
// It MUTATES cfg on success, so the caller's reviewer is built with the new key and the very first
// turn is reviewed rather than the second. It also persists the key, and the ORDER matters: the
// server keeps only a digest, so a key we fail to write is a key nobody can ever use again, and the
// next attempt would rotate it and invalidate whatever did get written. Persist, then use.
func Ensure(cfg *config.Config, cwd, sessionID string) bool {
	if cfg == nil {
		return false
	}
	// ⚠️ RECORD THE CREDENTIAL THE REVIEWER WILL ACTUALLY BE BUILT WITH. Ensure runs immediately
	// before delivery.New(cfg), so whatever cfg holds when this returns is what every request this
	// turn authenticates as — including a key just minted above. MarkStaleKey needs exactly that
	// value and cannot reach it any other way: the engine holds a Reviewer, not a config.
	//
	// Deferred rather than assigned at each return, so a branch added later cannot forget it.
	defer func() { noteActiveKey(cfg.LicenseKey) }()

	rejected := ""
	if cfg.LicenseKey != "" {
		// ⚠️ A KEY THE SERVER REJECTED IS NOT A KEY. Without this branch a machine holding an
		// unrecognised credential is stuck forever: it 401s on every call, fails open, reports
		// nothing, and never enrols because it believes it is licensed. Keyed on the CREDENTIAL,
		// not the session, so it recovers in a later session and in a headless run — see stale.go
		// for why the session-keyed first attempt at this was almost useless.
		if !staleKeyMarked(cfg.LicenseKey) {
			return true // licensed and nothing has told us otherwise
		}
		if coolingDown() {
			// Even a freshly minted key can be refused (a misconfigured account, a revoked seat
			// re-revoked). Without this a machine in that state mints once per turn forever.
			slog.Warn("this machine's license key was rejected, but a re-enrolment was attempted recently; waiting")
			return true
		}
		slog.Warn("the server rejected this machine's license key; re-enrolling")
		noteReEnrolAttempt()
		// Remembered so the marker can be cleared on success, and so the guards below can tell a
		// recovery from a first-time enrolment.
		//
		// ⚠️ THE KEY IS NOT CLEARED HERE, AND CLEARING IT WAS WORSE THAN A NO-OP. Every guard
		// below can still return without minting, and a cleared key then leaves the reviewer with
		// NO credential — turning a request that might have been accepted into a certain 401
		// ("missing license"). Live, that cost one review in every two while a machine was in this
		// state. Nothing needs it cleared: the enrolment call builds its own unauthenticated client
		// on the line below, and license.json is left alone until a mint SUCCEEDS anyway, so
		// discarding the in-memory copy only ever removed the fallback.
		//
		// Our belief that the key is dead can also simply be wrong (a marker written against the
		// wrong credential, a server that refused it once), so keeping it is the fail-open reading:
		// degrade as little as possible, and let the server be the one that says no.
		rejected = cfg.LicenseKey
	}
	if cfg.EnrollToken == "" {
		return false // no token pushed: this deployment does not use enrolment
	}
	// CLOUD ONLY. The local tier sends no code and no metadata and has no account behind it, so
	// there is nothing for a per-user key to attribute and no seat to claim.
	if cfg.Tier != config.TierCloud {
		return false
	}
	// FIRST-TIME enrolments only — a recovery is bounded by the stale marker and the cooldown
	// instead. See throttleKey for why sharing this budget stranded a machine for a whole session.
	if rejected == "" && !notify.FirstThisSession(sessionID, throttleKey) {
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
	clearStaleKey(rejected)
	slog.Info("enrolled this machine", "license", resp.LicenseID, "account", resp.AccountID,
		"rotated", resp.Rotated, "path", path)
	return true
}
