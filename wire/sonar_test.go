package wire

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSonarMetadataNeverCrossesWire(t *testing.T) {
	f := Finding{Rule: "sonar:go-s5445", SonarIssueID: "private-key", SonarURL: "https://sonarcloud.io/private", SonarRole: "raised"}
	raw, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"private-key", "sonarcloud.io", "SonarIssueID", "raised"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("metadata leaked: %s", raw)
		}
	}
}

func TestScannerDisputePrefixesAreDistinct(t *testing.T) {
	seen := map[string]bool{}
	for _, d := range ScannerDisputes {
		if d.Prefix == "" || d.Name == "" || seen[d.Prefix] || !strings.HasSuffix(d.Prefix, "-fp:") {
			t.Fatalf("bad dispute prefix %+v", d)
		}
		seen[d.Prefix] = true
	}
}
