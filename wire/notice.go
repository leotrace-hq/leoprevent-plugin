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
