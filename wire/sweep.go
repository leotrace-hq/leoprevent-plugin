package wire

const (
	MaxSweepFiles  = 40
	MaxSweepIssues = 120
)

type SweepPlanRequest struct {
	Repo string `json:"repo"`
}

type SweepPlanResponse struct {
	Connected bool        `json:"connected"`
	Complete  bool        `json:"complete"`
	Files     []SweepFile `json:"files"`
	Settled   int         `json:"settled,omitempty"`
}

type SweepFile struct {
	Path   string `json:"path"`
	Issues int    `json:"issues"`
}

type SweepRequest struct {
	ReviewID string        `json:"review_id,omitempty"`
	Files    []ChangedFile `json:"files"`
	Meta     TurnMeta      `json:"meta"`
}

type SweepResponse struct {
	ReviewID     string    `json:"review_id"`
	Checked      int       `json:"checked"`
	Disputed     int       `json:"disputed"`
	Real         int       `json:"real"`
	Absent       int       `json:"absent"`
	Unjudged     int       `json:"unjudged"`
	Findings     []Finding `json:"findings"`
	RealFindings []Finding `json:"real_findings"`
}

const (
	SweepNoticeSweep   = "sweep"
	SweepNoticePlan    = "plan"
	SweepNoticeResolve = "resolve"
	SweepNoticeIntro   = "intro"
)

type SweepNoticeRequest struct {
	Kind       string `json:"kind"`
	Complete   bool   `json:"complete,omitempty"`
	Files      int    `json:"files,omitempty"`
	Issues     int    `json:"issues,omitempty"`
	Checked    int    `json:"checked,omitempty"`
	Disputed   int    `json:"disputed,omitempty"`
	Real       int    `json:"real,omitempty"`
	Absent     int    `json:"absent,omitempty"`
	Skipped    int    `json:"skipped,omitempty"`
	Unjudged   int    `json:"unjudged,omitempty"`
	Failed     int    `json:"failed_batches,omitempty"`
	Fixed      int    `json:"fixed,omitempty"`
	StillOpen  int    `json:"still_open,omitempty"`
	Unchanged  int    `json:"unchanged,omitempty"`
	NotChecked int    `json:"not_checked,omitempty"`
	Settled    int    `json:"settled,omitempty"`

	Continued         bool `json:"continued,omitempty"`
	RemainingFiles    int  `json:"remaining_files,omitempty"`
	RemainingFindings int  `json:"remaining_findings,omitempty"`
}

type SweepNoticeResponse struct {
	Notice string `json:"notice"`
}
