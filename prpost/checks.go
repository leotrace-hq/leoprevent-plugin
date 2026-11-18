package prpost

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// THE CHECK RUN (LEO-289): the lane's verdict as a row in the pull request's checks list.
//
// A comment is the wrong carrier for "reviewed, nothing found": it is a paragraph saying nothing
// happened, and a clean review therefore posts none at all (see Assembled.Post). Without a row,
// a reviewer cannot tell a clean review from a lane that never ran. The check run is that row.
//
// ⚠️ IT IS NOT A BLOCKING REVIEW, AND THE ADVISORY POSTURE IS UNCHANGED. A failing check run gates
// a merge only if the CUSTOMER marks it required in their own branch protection, which is their
// decision and reversible from their side. The review is still posted as `COMMENT`, never
// `REQUEST_CHANGES`.
//
// ⚠️ ONLY A GITHUB APP CAN CREATE ONE, WITH `checks: write`. The webhook lane holds an installation
// token and so can; the workflow lane's GITHUB_TOKEN already gets a row from the Actions job
// itself and does not call this. An installation that has not accepted `checks: write` answers
// 403, reported as ErrChecksNotPermitted so the caller carries on exactly as it did before checks
// existed.

// CheckName is the row's label in the checks list.
const CheckName = "LeoPrevent"

// checkExternalID marks a run as this lane's. The name alone is not enough: a customer's own
// Actions job may be called LeoPrevent too, and only the App that created a run may update it.
const checkExternalID = "leoprevent-pr-lane"

// Conclusion is the verdict a completed run carries.
type Conclusion string

const (
	// ConclusionSuccess: the review ran and reported nothing.
	ConclusionSuccess Conclusion = "success"
	// ConclusionFailure: the review reported findings, which are on the pull request as comments.
	ConclusionFailure Conclusion = "failure"
	// ConclusionNeutral: no verdict was reached. Never red for a failure of ours, and never green,
	// which would claim a clean review nobody performed.
	ConclusionNeutral Conclusion = "neutral"
)

// ErrChecksNotPermitted means the installation has not granted `checks: write`.
var ErrChecksNotPermitted = errors.New("github: installation has not granted checks: write")

// maxCheckTitle and maxCheckSummary are GitHub's own limits on a run's output.
const (
	maxCheckTitle   = 255
	maxCheckSummary = 65535
)

type checkOutput struct {
	Title   string `json:"title"`
	Summary string `json:"summary"`
}

type checkRunPayload struct {
	Name       string       `json:"name,omitempty"`
	HeadSHA    string       `json:"head_sha,omitempty"`
	ExternalID string       `json:"external_id,omitempty"`
	Status     string       `json:"status,omitempty"`
	Conclusion Conclusion   `json:"conclusion,omitempty"`
	Output     *checkOutput `json:"output,omitempty"`
}

// StartCheck marks the review of headSHA as running and returns the run's id.
//
// ⚠️ ONE RUN PER HEAD SHA. A re-delivery of the same commit (a reopen, a redelivered webhook)
// moves this lane's existing run back to in_progress rather than stacking a second row. A new push
// is a new SHA and so a new run. If the existing run cannot be updated, a new one is created: two
// rows is a nuisance, a review with no row is the ambiguity this exists to remove.
func (c Client) StartCheck(headSHA string) (int64, error) {
	if !isSHA(headSHA) {
		return 0, fmt.Errorf("github: check run needs a commit SHA, got %q", headSHA)
	}
	running := checkRunPayload{Status: "in_progress", Output: &checkOutput{
		Title:   "Reviewing",
		Summary: "LeoPrevent is reviewing this pull request's changes.",
	}}
	if id, err := c.existingCheck(headSHA); err != nil {
		if errors.Is(err, ErrChecksNotPermitted) {
			return 0, err
		}
	} else if id != 0 {
		if err := c.patchCheck(id, running); err == nil {
			return id, nil
		} else if errors.Is(err, ErrChecksNotPermitted) {
			return 0, err
		}
	}
	running.Name = CheckName
	running.HeadSHA = headSHA
	running.ExternalID = checkExternalID
	data, err := c.checkCall(http.MethodPost, c.pathFor("/repos/%s/%s/check-runs", c.Owner, c.Repo), running)
	if err != nil {
		return 0, err
	}
	var created struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(data, &created); err != nil || created.ID == 0 {
		return 0, fmt.Errorf("github: check run created with no id")
	}
	return created.ID, nil
}

// FinishCheck completes a run with its verdict. The title and summary are OUR text only — counts
// and fixed sentences, never model prose — so nothing in them needs the marker sanitising the
// review comments do.
func (c Client) FinishCheck(id int64, conclusion Conclusion, title, summary string) error {
	switch conclusion {
	case ConclusionSuccess, ConclusionFailure, ConclusionNeutral:
	default:
		return fmt.Errorf("github: unknown check conclusion %q", conclusion)
	}
	return c.patchCheck(id, checkRunPayload{
		Status:     "completed",
		Conclusion: conclusion,
		Output: &checkOutput{
			Title:   clip(title, maxCheckTitle),
			Summary: clip(summary, maxCheckSummary),
		},
	})
}

// existingCheck finds this lane's run on headSHA, or 0 when there is none.
func (c Client) existingCheck(headSHA string) (int64, error) {
	path := c.pathFor("/repos/%s/%s/commits/%s/check-runs", c.Owner, c.Repo, headSHA) +
		"?check_name=" + CheckName + "&filter=latest&per_page=100"
	data, err := c.checkCall(http.MethodGet, path, nil)
	if err != nil {
		return 0, err
	}
	var list struct {
		CheckRuns []struct {
			ID         int64  `json:"id"`
			ExternalID string `json:"external_id"`
		} `json:"check_runs"`
	}
	if err := json.Unmarshal(data, &list); err != nil {
		return 0, err
	}
	for _, r := range list.CheckRuns {
		if r.ExternalID == checkExternalID {
			return r.ID, nil
		}
	}
	return 0, nil
}

func (c Client) patchCheck(id int64, body checkRunPayload) error {
	if id <= 0 {
		return fmt.Errorf("github: no check run to update")
	}
	_, err := c.checkCall(http.MethodPatch, c.pathFor("/repos/%s/%s/check-runs/%d", c.Owner, c.Repo, id), body)
	return err
}

// checkCall is `do` with a 403 reported as ErrChecksNotPermitted.
func (c Client) checkCall(method, path string, body any) ([]byte, error) {
	data, resp, err := c.do(method, path, body)
	if err != nil && resp != nil && resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("%w: %v", ErrChecksNotPermitted, err)
	}
	return data, err
}

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	cut := n - len("…")
	for cut > 0 && !utf8Start(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

func utf8Start(b byte) bool { return b&0xC0 != 0x80 }
