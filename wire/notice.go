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
}
