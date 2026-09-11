package apiclient

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

func TestServerNoticeCompatibility(
	t *testing.T,
) {
	keep := false
	notice := &wire.ServerNotice{ID: "future.policy.v2", Message: "First line\n" + strings.Repeat("x", 600), ActionURL: "https://example.com/help"}
	body, _ := json.Marshal(wire.ErrorResponse{Error: "unavailable", Notice: notice, RetryWithNewKey: &keep})
	result := statusError("/review", &http.Response{StatusCode: 403, Body: io.NopCloser(strings.NewReader(string(body)))})
	if result.Notice == nil || *result.Notice != *notice || result.RetryWithNewKey == nil || *result.RetryWithNewKey {
		t.Fatalf("notice was not preserved: %+v", result)
	}
	if len(result.Body) > maxErrBodySnippet {
		t.Fatal("diagnostic body was not bounded")
	}
	for _, raw := range []string{`{"error":"legacy"}`, "proxy failed", `{"notice":"wrong type"}`, `{"notice":`, strings.Repeat("x", 16385)} {
		legacy := statusError("/rules", &http.Response{StatusCode: 403, Body: io.NopCloser(strings.NewReader(raw))})
		if legacy.Notice != nil || legacy.RetryWithNewKey != nil || legacy.Status != 403 {
			t.Fatalf("bad fallback: %+v", legacy)
		}
	}
}

func TestMalformedNoticeFallsBack(
	t *testing.T,
) {
	for _, notice := range []wire.ServerNotice{
		{ID: "", Message: "message"},
		{ID: "a/b", Message: "message"},
		{ID: "valid", Message: " "},
		{ID: "valid", Message: strings.Repeat("x", 2001)},
		{ID: "valid", Message: "escape \x1b[2J"},
		{ID: "valid", Message: "message", ActionURL: "javascript:alert(1)"},
		{ID: "valid", Message: "message", ActionURL: "https://user:secret@example.com"},
		{ID: "valid", Message: "message", ActionURL: "https://example.com/\ntext"},
	} {
		raw, _ := json.Marshal(wire.ErrorResponse{Error: "failure", Notice: &notice})
		result := statusError("/review", &http.Response{StatusCode: 403, Body: io.NopCloser(strings.NewReader(string(raw)))})
		if result.Notice != nil {
			t.Fatalf("accepted invalid notice: %+v", notice)
		}
	}
}
