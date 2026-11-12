// Package policycheck asks the server, before a turn sends anything, whether the repository is
// one the organisation's policy excludes from review (docs/enterprise.md § Policies on reviews),
// and caches the answer for ten minutes in the plugin's per-user state.
//
// An excluded repository is always skipped. What a check that can't be made (network error,
// timeout, 429, 5xx) means depends on the license, which the plugin remembers from the last
// answer the server gave (has_exclusions, cached per license):
//
//   - a license whose Org excludes something keeps the Policies PRD's rule: skip, because sending
//     code before knowing would defeat the exclusion;
//   - any other license (none known, or never answered yet) fails open and the turn proceeds, as
//     every other hook error does (AGENTS.md § Fail-open). /review refuses an excluded repository
//     itself, so it stays the second line.
//
// A failure is remembered for FailTTL, so a server that is down costs one bounded wait, not one
// per turn. A 404 is a server without the check (older, or policies off): the feature is absent,
// nothing is excluded, and the license is recorded as having no exclusions. Agent-agnostic: every
// adapter gets the same answer through the engine.
package policycheck

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/apiclient"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/scratch"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

// TTL is how long an answer is reused for a repository.
const TTL = 10 * time.Minute

// FailTTL is how long a failed check is remembered for a license: within it, no check is made
// and the turn is decided as a failed check would decide it.
const FailTTL = 60 * time.Second

// Notice ids, for the once-per-session throttle.
const (
	NoticeExcluded  = "repo_excluded"
	NoticeUnchecked = "policy_unchecked"
)

// Default copy, used only when the server sends none. No em dashes (AGENTS.md). The unchecked
// notice is shown only to a license the server said has exclusions, so it may say so.
const (
	DefaultExcludedNotice  = "LeoPrevent: your organisation's policy excludes this repository from review, so nothing from this turn was sent or reviewed."
	DefaultUncheckedNotice = "⚠️ LeoPrevent: your organisation excludes some repositories from review, and the server couldn't be reached to check this one, so nothing from this turn was sent and it was NOT reviewed."
)

// Answer is the server's answer for one repository.
type Answer struct {
	Excluded bool
	Reason   string
	Notice   *wire.ServerNotice
	// HasExclusions is the server's word that the license's Org excludes something somewhere,
	// and UncheckedNotice its copy for a later failed check.
	HasExclusions   bool
	UncheckedNotice *wire.ServerNotice
	// Absent is a server with no policy check (404): nothing is excluded.
	Absent bool
	// NoVerdict is a 4xx other than 404 (a bad key, say): not excluded for this repository, but
	// it says nothing about the license's exclusions, so the remembered answer is left alone.
	NoVerdict bool
}

// Checker asks the server. An error means the check couldn't be made.
type Checker interface {
	PolicyCheck(repo string) (Answer, error)
}

// API is the server's check over the plugin's API client. A 404 is a server without the check,
// or with policies off: the feature is absent, so nothing is excluded. Any other 4xx is not this
// check's to judge (a bad key is the review's own skip to report), so it also reads as not
// excluded. A network error, a timeout, a 429 or a 5xx means the check couldn't be made.
type API struct{ Client *apiclient.Client }

// PolicyCheck implements Checker.
func (a API) PolicyCheck(repo string) (Answer, error) {
	resp, err := a.Client.PolicyCheck(wire.PolicyCheckRequest{Repo: repo})
	if err == nil {
		return Answer{Excluded: resp.Excluded, Reason: resp.Reason, Notice: resp.Notice,
			HasExclusions: resp.HasExclusions, UncheckedNotice: resp.UncheckedNotice}, nil
	}
	var se *apiclient.StatusError
	if errors.As(err, &se) && se.Status < 500 && se.Status != http.StatusTooManyRequests {
		if se.Status == http.StatusNotFound {
			return Answer{Absent: true}, nil
		}
		return Answer{NoVerdict: true}, nil
	}
	return Answer{}, err
}

// Result is the decision for a turn.
type Result struct {
	// Skip is true when nothing may be sent for this turn.
	Skip bool
	// NoticeID and Notice are what to show the developer, once per session.
	NoticeID string
	Notice   string
	// Repo is the repository that decided it, and Reason the exclusion or error, for the log.
	Repo   string
	Reason string
	// Unchecked is the error of a check that couldn't be made for a license with no known
	// exclusions, which the turn proceeds past (fail-open). For the log only.
	Unchecked string
}

// cached is the on-disk form of one repository's answer.
type cached struct {
	Excluded bool               `json:"excluded"`
	Reason   string             `json:"reason,omitempty"`
	Notice   *wire.ServerNotice `json:"notice,omitempty"`
	At       time.Time          `json:"at"`
}

// licenseState is the on-disk per-license memory: whether the last answer said the license's
// Org has exclusions (with the server's copy for a failed check), and when a check last failed.
type licenseState struct {
	HasExclusions   bool               `json:"has_exclusions"`
	UncheckedNotice *wire.ServerNotice `json:"unchecked_notice,omitempty"`
	FailedAt        time.Time          `json:"failed_at,omitzero"`
	FailReason      string             `json:"fail_reason,omitempty"`
}

// Check asks about every repository the turn touches ("" is a repository with no remote) and
// skips the turn when any is excluded, or when the check can't be made for a license known to
// exclude something. license scopes the cache, so a key change never reuses another account's
// answer.
func Check(c Checker, license string, repos []string, now time.Time) Result {
	if c == nil {
		return Result{}
	}
	if len(repos) == 0 {
		repos = []string{""}
	}
	var out Result
	st := loadLicense(license)
	for _, repo := range repos {
		ans, ok := load(license, repo, now)
		if !ok {
			var err error
			if recentFailure(st, now) {
				err = errors.New("recent failure (cached): " + st.FailReason)
			} else if ans, err = c.PolicyCheck(repo); err != nil {
				st.FailedAt, st.FailReason = now, err.Error()
				saveLicense(license, st)
			}
			if err != nil {
				if st.HasExclusions {
					msg := DefaultUncheckedNotice
					if st.UncheckedNotice != nil && st.UncheckedNotice.Message != "" {
						msg = st.UncheckedNotice.Message
					}
					return Result{Skip: true, NoticeID: NoticeUnchecked, Notice: msg, Repo: repo, Reason: err.Error()}
				}
				if out.Unchecked == "" {
					out.Repo, out.Unchecked = repo, err.Error()
				}
				continue
			}
			save(license, repo, ans, now)
			if !ans.NoVerdict {
				st = licenseState{HasExclusions: ans.HasExclusions || ans.Excluded, UncheckedNotice: ans.UncheckedNotice}
				saveLicense(license, st)
			}
		}
		if ans.Excluded {
			msg := DefaultExcludedNotice
			if ans.Notice != nil && ans.Notice.Message != "" {
				msg = ans.Notice.Message
			}
			return Result{Skip: true, NoticeID: NoticeExcluded, Notice: msg, Repo: repo, Reason: ans.Reason}
		}
	}
	return out
}

func recentFailure(st licenseState, now time.Time) bool {
	return !st.FailedAt.IsZero() && !st.FailedAt.After(now) && now.Sub(st.FailedAt) < FailTTL
}

func path(license, repo string) string {
	sum := sha256.Sum256([]byte(license + "\x00" + repo))
	return filepath.Join(scratch.Dir("policy"), hex.EncodeToString(sum[:16])+".json")
}

// licensePath sits next to the per-repository answers; the "license" prefix keeps its hash
// apart from any repository's.
func licensePath(license string) string {
	sum := sha256.Sum256([]byte("license\x00" + license))
	return filepath.Join(scratch.Dir("policy"), "license-"+hex.EncodeToString(sum[:16])+".json")
}

func load(license, repo string, now time.Time) (Answer, bool) {
	b, err := os.ReadFile(path(license, repo))
	if err != nil {
		return Answer{}, false
	}
	var c cached
	if json.Unmarshal(b, &c) != nil || c.At.After(now) || now.Sub(c.At) >= TTL {
		return Answer{}, false
	}
	return Answer{Excluded: c.Excluded, Reason: c.Reason, Notice: c.Notice}, true
}

// loadLicense returns the zero state (no known exclusions, no recent failure) when nothing is
// remembered or the file can't be read.
func loadLicense(license string) licenseState {
	var st licenseState
	if b, err := os.ReadFile(licensePath(license)); err == nil {
		if json.Unmarshal(b, &st) != nil {
			return licenseState{}
		}
	}
	return st
}

// save is best-effort: a lost write costs one more check, never the turn.
func save(license, repo string, a Answer, now time.Time) {
	writeJSON(path(license, repo), cached{Excluded: a.Excluded, Reason: a.Reason, Notice: a.Notice, At: now})
}

// saveLicense is best-effort too: a lost write forgets a failure, or reads a license as having
// no exclusions until the next answer (which /review's own refusal backs).
func saveLicense(license string, st licenseState) {
	writeJSON(licensePath(license), st)
}

func writeJSON(p string, v any) {
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return
	}
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	tmp := p + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, p)
	}
}
