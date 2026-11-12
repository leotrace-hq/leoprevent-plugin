package apiclient

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

func statusError(
	path string,
	response *http.Response,
) *StatusError {
	result := &StatusError{Path: path, Status: response.StatusCode}
	body, err := io.ReadAll(io.LimitReader(response.Body, 16385))
	if err != nil {
		return result
	}
	snippet := body
	if len(snippet) > maxErrBodySnippet {
		snippet = snippet[:maxErrBodySnippet]
	}
	result.Body = strings.Join(strings.Fields(string(snippet)), " ")
	if len(body) > 16384 {
		return result
	}
	var payload wire.ErrorResponse
	if json.Unmarshal(body, &payload) != nil {
		return result
	}
	result.RetryWithNewKey = payload.RetryWithNewKey
	if validNotice(payload.Notice) {
		result.Notice = payload.Notice
	}
	return result
}

func validNotice(
	notice *wire.ServerNotice,
) bool {
	if notice == nil || len(notice.ID) == 0 || len(notice.ID) > 64 ||
		len(notice.Message) > 2000 || strings.TrimSpace(notice.Message) == "" || !utf8.ValidString(notice.Message) {
		return false
	}
	for _, char := range notice.ID {
		if !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '_' || char == '-' || char == '.') {
			return false
		}
	}
	for _, char := range notice.Message {
		if unicode.IsControl(char) && char != '\n' && char != '\t' {
			return false
		}
	}
	if notice.ActionURL == "" {
		return true
	}
	if len(notice.ActionURL) > 2048 || strings.ContainsAny(notice.ActionURL, " \t\r\n") {
		return false
	}
	link, err := url.Parse(notice.ActionURL)
	return err == nil && (link.Scheme == "https" || link.Scheme == "http") && link.Hostname() != "" && link.User == nil
}
