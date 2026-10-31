package wire

type ServerNotice struct {
	ID        string `json:"id"`
	Message   string `json:"message"`
	ActionURL string `json:"action_url,omitempty"`
}

type ErrorResponse struct {
	Error           string        `json:"error"`
	Notice          *ServerNotice `json:"notice,omitempty"`
	RetryWithNewKey *bool         `json:"retry_with_new_key,omitempty"`
	// Retryable false tells the plugin a 5xx is the server's settled answer for this exact
	// request (LEO-418): the server already ran its own recovery for a deterministic failure,
	// such as a judge cut off at max_tokens twice, so replaying the identical body can only
	// spend the rest of the Stop hook's deadline before failing open anyway. Omitted (older
	// servers, and every transient fault) keeps the client's 429/5xx retry. True changes
	// nothing, and the field never makes a 4xx retryable.
	Retryable *bool `json:"retryable,omitempty"`
}

// PolicyCheckRequest is the POST /policy/check body (docs/enterprise.md § Policies on reviews):
// the repository a turn is about to send, asked BEFORE anything else is sent for it. Repo is the
// normalised origin (TurnMeta.Repo), or "" for a repository with no remote, which the server
// matches against the literal `no-remote` exclusion. Nothing else travels.
type PolicyCheckRequest struct {
	Repo string `json:"repo"`
}

// PolicyCheckResponse says whether the repository's place excludes it from review. Reason names
// the exclusion that matched (a glob, or `no-remote`), for the client log only.
type PolicyCheckResponse struct {
	Excluded bool   `json:"excluded"`
	Reason   string `json:"reason,omitempty"`
	// Notice is the server's wording for the excluded skip (notice copy is server-controlled);
	// nil leaves the client's default.
	Notice *ServerNotice `json:"notice,omitempty"`
	// HasExclusions is true when the license's Org has an exclusion anywhere in its tree. The
	// plugin caches it per license: when a later check can't be made, a license known to exclude
	// something skips the turn, and any other proceeds (fail-open; /review refuses an excluded
	// repository as the second line). Absent (older servers) reads as false.
	HasExclusions bool `json:"has_exclusions,omitempty"`
	// UncheckedNotice is the server's wording for the skip shown when a later check for this
	// license can't be made (it is cached with HasExclusions, since that notice is shown exactly
	// when the server can't answer). Sent only with HasExclusions; nil leaves the client's default.
	UncheckedNotice *ServerNotice `json:"unchecked_notice,omitempty"`
}

// RouteResponse is GET /route?repo= (Plugin setup's "Where would a review go?"): the routing
// decision for the calling key and a repository, as the server would make it for a review.
type RouteResponse struct {
	Routing          bool   `json:"routing"`
	OrgID            string `json:"org_id,omitempty"`
	WorkspaceID      string `json:"workspace_id,omitempty"`
	WorkspaceName    string `json:"workspace_name,omitempty"`
	Placed           bool   `json:"placed"`
	Skip             string `json:"skip,omitempty"`
	OutsideWorkspace bool   `json:"outside_workspace,omitempty"`
	Excluded         bool   `json:"excluded,omitempty"`
	Reason           string `json:"reason,omitempty"`
	Repo             string `json:"repo,omitempty"`
}
