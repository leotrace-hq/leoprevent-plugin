package wire

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestFileDecisionBoundsAndProtectedPaths(t *testing.T) {
	d := NewFileDecisions()
	for _, p := range []string{"/Users/alice/secret.go", "../../private.go", "C:\\work\\file.go", "config/.env", "src/../.env", "src/a\n.go"} {
		d.Add("discovery", p, "unreadable")
	}
	d.Add("relevance", "src/api.go", "test")
	for i := 0; i < 250; i++ {
		d.Add("relevance", fmt.Sprintf("src/%d.go", i), "sent")
	}
	if ValidFileDecisions(d) == nil || len(d.Files) != MaxFileDecisions || d.Omitted != 57 {
		t.Fatalf("bad bounded report: %+v", d)
	}
	for _, f := range d.Files[:6] {
		if f.Path != "" {
			t.Fatalf("unsafe path: %q", f.Path)
		}
	}
	b, _ := json.Marshal(d)
	if strings.Contains(string(b), "alice") {
		t.Fatal("absolute path escaped")
	}
	if d.Files[6].Path != "src/api.go" {
		t.Fatal("lost identifiable skipped file")
	}
	d.Counts["relevance:test"] = 0
	if ValidFileDecisions(d) != nil {
		t.Fatal("accepted inconsistent row totals")
	}
}
func TestFileDecisionCloneDoesNotShareState(t *testing.T) {
	a := NewFileDecisions()
	a.Add("relevance", "a.go", "sent")
	b := a.Clone()
	b.Add("context", "b.go", "context_budget")
	if len(a.Files) != 1 || len(a.Counts) != 1 {
		t.Fatal("clone mutated original")
	}
}

func TestLateExclusionIsKeptWhenPassedFilesFillTheBound(t *testing.T) {
	d := NewFileDecisions()
	for i := 0; i < MaxFileDecisions; i++ {
		d.Add("relevance", fmt.Sprintf("src/%d.go", i), "sent")
	}
	d.Add("relevance", "tests/payment_test.go", "test")
	if ValidFileDecisions(d) == nil || d.Omitted != 1 || d.Files[0].Path != "tests/payment_test.go" {
		t.Fatal("an important exclusion was hidden behind passed files")
	}
}
