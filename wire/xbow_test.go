package wire

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestXbowMetadataNeverCrossesWire(t *testing.T) {
	// Arrange
	f := Finding{Rule: "xbow:cwe-89", XbowFindingID: "private-id", XbowRole: "raised"}

	// Act
	raw, err := json.Marshal(f)
	var decoded Finding
	derr := json.Unmarshal([]byte(`{"XbowFindingID":"x","xbow_finding_id":"y","XbowRole":"raised"}`), &decoded)

	// Assert
	if err != nil || derr != nil {
		t.Fatal(err, derr)
	}
	for _, secret := range []string{"private-id", "XbowFindingID", "xbow_finding_id", "raised"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("metadata leaked: %s", raw)
		}
	}
	if decoded.XbowFindingID != "" || decoded.XbowRole != "" {
		t.Fatal("client metadata accepted")
	}
}
