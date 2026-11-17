package wire

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSnykMetadataNeverCrossesWire(t *testing.T) {
	f := Finding{Rule: "snyk:sql", SnykIssueID: "private-id", SnykURL: "https://app.snyk.io/private", SnykRole: "raised"}
	raw, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"private-id", "app.snyk.io", "SnykIssueID", "snyk_issue_id", "raised"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("metadata leaked: %s", raw)
		}
	}
	var decoded Finding
	if err := json.Unmarshal([]byte(`{"SnykIssueID":"x","snyk_issue_id":"y","SnykURL":"z","SnykRole":"raised"}`), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.SnykIssueID != "" || decoded.SnykURL != "" || decoded.SnykRole != "" {
		t.Fatal("client metadata accepted")
	}
}
