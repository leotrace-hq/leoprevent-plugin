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
