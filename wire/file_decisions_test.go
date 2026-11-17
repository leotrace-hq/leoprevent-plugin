package wire

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func checkDecisionBudget(t *testing.T, d *FileDecisions) int {
	t.Helper()
	b, err := json.Marshal(d.Files)
	if err != nil || len(b) > MaxFileDecisionBytes || ValidFileDecisions(d) == nil {
		t.Fatalf("invalid report: bytes=%d files=%d omitted=%d err=%v", len(b), len(d.Files), d.Omitted, err)
	}
	if d.groups != nil && d.fileBytes != len(b) {
		t.Fatalf("cached size %d differs from encoded size %d", d.fileBytes, len(b))
	}
	return len(b)
}

// Return the number of observed decisions, including the first omitted example.
func fillDecisionBudget(d *FileDecisions, stage, reason string, path func(int) string) int {
	for i := 0; ; i++ {
		d.Add(stage, path(i), reason)
		if d.Omitted > 0 {
			return i + 1
		}
	}
}

func TestFileDecisionProtectedPathsAndMoreThan200Examples(t *testing.T) {
	d := NewFileDecisions()
	for _, p := range []string{"/Users/alice/secret.go", "../../private.go", "C:\\work\\file.go", "config/.env", "src/../.env", "src/a\n.go"} {
		d.Add("discovery", p, "unreadable")
	}
	d.Add("relevance", "src/api.go", "test")
	for i := 0; i < 1000; i++ {
		d.Add("relevance", fmt.Sprintf("src/%d.go", i), "sent")
	}
	checkDecisionBudget(t, d)
	if d.Version != 2 || len(d.Files) != 1007 || d.Omitted != 0 {
		t.Fatal("short paths still hit a record-count cap")
	}
	for _, f := range d.Files[:6] {
		if f.Path != "" {
			t.Fatalf("unsafe path: %q", f.Path)
		}
	}
	b, _ := json.Marshal(d)
	if strings.Contains(string(b), "alice") || d.Files[6].Path != "src/api.go" {
		t.Fatal("path protection lost")
	}
	d.Counts["relevance:test"] = 0
	if ValidFileDecisions(d) != nil {
		t.Fatal("accepted inconsistent totals")
	}
}

func TestBudgetMeasuresEncodedBytesIncludingEscaping(t *testing.T) {
	var capacities []int
	for _, prefix := range []string{"src/", "src/" + strings.Repeat("a", 480), "src/" + strings.Repeat("<", 480)} {
		d := NewFileDecisions()
		observed := fillDecisionBudget(d, "relevance", "sent", func(i int) string { return fmt.Sprintf("%s%05d.go", prefix, i) })
		checkDecisionBudget(t, d)
		if d.Omitted != 1 || observed != len(d.Files)+1 {
			t.Fatal("wrong omitted total")
		}
		capacities = append(capacities, len(d.Files))
		bad := d.Clone()
		bad.Files = append(bad.Files, bad.Files[len(bad.Files)-1])
		bad.Counts["relevance:sent"]++
		encoded, _ := json.Marshal(bad.Files)
		if len(encoded) <= MaxFileDecisionBytes || ValidFileDecisions(bad) != nil {
			t.Fatal("server accepted an over-budget array")
		}
	}
	if capacities[0] <= capacities[1] || capacities[1] <= capacities[2] {
		t.Fatalf("budget ignored path length or JSON escaping: %v", capacities)
	}
}

func TestLongLateExclusionCanReplaceSeveralShortExamples(t *testing.T) {
	d := NewFileDecisions()
	fillDecisionBudget(d, "context", "context_unavailable", func(i int) string { return fmt.Sprintf("lib/%05d.go", i) })
	beforeFiles, beforeOmitted := len(d.Files), d.Omitted
	p := "cache/" + strings.Repeat("<", 480) + ".py"
	d.AddVendored("relevance", p, `(^|/)cache/`)
	checkDecisionBudget(t, d)
	removed := beforeFiles + 1 - len(d.Files)
	if removed <= 1 || d.Omitted != beforeOmitted+removed || d.Files[0].Path != "lib/00000.go" || d.Files[len(d.Files)-1].Path != p || d.EnryVendorCounts[`(^|/)cache/`] != 1 {
		t.Fatal("long late exclusion lost its example, early donors, or exact counts")
	}
	for i := 0; i < 1000; i++ {
		d.Add("context", fmt.Sprintf("lib/more-%d.go", i), "context_unavailable")
	}
	found := false
	for _, f := range d.Files {
		found = found || f.Path == p
	}
	if !found {
		t.Fatal("common decisions evicted a rare example")
	}
	checkDecisionBudget(t, d)
}

func TestLateExclusionReplacesPassedExamples(t *testing.T) {
	d := NewFileDecisions()
	fillDecisionBudget(d, "relevance", "sent", func(i int) string { return fmt.Sprintf("src/%05d.go", i) })
	d.Add("relevance", "tests/payment_test.go", "test")
	checkDecisionBudget(t, d)
	if d.Files[len(d.Files)-1].Path != "tests/payment_test.go" {
		t.Fatal("passed rows hid a late exclusion")
	}
}

func TestEverySkipGroupFitsEvenWithHeavilyEscapedPaths(t *testing.T) {
	d := NewFileDecisions()
	p := "src/" + strings.Repeat("<", 500) + ".go"
	fillDecisionBudget(d, "context", "context_unavailable", func(int) string { return p })
	reasons := []string{"secret", "outside_root", "unreadable", "symlink_or_stat", "binary", "deleted_unavailable", "imported_history", "vendored", "editor_backup", "tool_data", "migration", "lockfile", "test", "inert_extension", "generated", "passive_svg", "generated_or_binary", "comments_only", "context_budget", "context_sliced", "context_unavailable"}
	for _, stage := range []string{"discovery", "relevance", "context"} {
		for _, reason := range reasons {
			d.Add(stage, p, reason)
		}
	}
	for i := 0; i < 1000; i++ {
		d.Add("context", p, "context_unavailable")
	}
	checkDecisionBudget(t, d)
	seen := map[decisionGroup]bool{}
	for _, f := range d.Files {
		seen[decisionGroup{f.Stage, f.Reason}] = true
		if (f.Reason == "secret" || f.Reason == "outside_root") && f.Path != "" {
			t.Fatal("protected path retained")
		}
	}
	if len(seen) != 63 {
		t.Fatalf("lost skip groups: retained %d", len(seen))
	}
}

func TestFailedMultiEvictionLeavesExistingExamplesUntouched(t *testing.T) {
	d := NewFileDecisions()
	fillDecisionBudget(d, "relevance", "test", func(i int) string { return fmt.Sprintf("src/%05d_test.go", i) })
	// Only one passed row can donate. The incoming test group is already dominant,
	// so the plan cannot evict enough bytes for a long replacement from other groups.
	d.Files[len(d.Files)-1].Reason = "sent"
	d.Counts["relevance:test"]--
	d.Counts["relevance:sent"] = 1
	d = d.Clone() // Rebuild collector caches after constructing the fixture.
	before := append([]FileDecision(nil), d.Files...)
	omitted := d.Omitted
	d.Add("relevance", "src/"+strings.Repeat("<", 500)+".go", "test")
	if !reflect.DeepEqual(before, d.Files) || d.Omitted != omitted+1 {
		t.Fatal("an unsuccessful plan partially evicted existing examples")
	}
	checkDecisionBudget(t, d)
}

func TestCloneKeepsCountsAndSamplingStateIndependent(t *testing.T) {
	a := NewFileDecisions()
	fillDecisionBudget(a, "context", "context_unavailable", func(i int) string { return fmt.Sprintf("lib/%05d.go", i) })
	a.AddVendored("relevance", "cache/first.py", `(^|/)cache/`)
	before, _ := json.Marshal(a)
	b := a.Clone()
	b.AddVendored("relevance", "cache/second.py", `(^|/)cache/`)
	b.Add("relevance", "src/api_test.go", "test")
	after, _ := json.Marshal(a)
	if string(before) != string(after) || b.EnryVendorCounts[`(^|/)cache/`] != 2 || a.EnryVendorCounts[`(^|/)cache/`] != 1 {
		t.Fatal("clone mutated original state")
	}
	checkDecisionBudget(t, b)
}

func TestRuleTotalsIncludeOmittedPathsWithoutPerFileLabels(t *testing.T) {
	d := NewFileDecisions()
	for i := 0; d.Omitted == 0; i++ {
		d.AddVendored("relevance", fmt.Sprintf("testdata/%05d.go", i), `(^|/)testdata/`)
	}
	// This longer path cannot fit in the remaining space, and its own already
	// dominant group cannot donate. Its rule count must survive without a filename.
	d.AddVendored("relevance", "cache/"+strings.Repeat("a", 480)+".py", `(^|/)cache/`)
	checkDecisionBudget(t, d)
	if d.Omitted != 2 || d.EnryVendorCounts[`(^|/)cache/`] != 1 || d.EnryVendorCounts[`(^|/)testdata/`] != d.Counts["relevance:vendored"]-1 {
		t.Fatal("lost omitted-path rule totals")
	}
	b, _ := json.Marshal(d)
	if strings.Contains(string(b), `"enry_vendor_rule"`) {
		t.Fatal("per-file rule strings are still emitted")
	}
	var decoded FileDecisions
	if err := json.Unmarshal(b, &decoded); err != nil || ValidFileDecisions(&decoded) == nil || decoded.EnryVendorCounts[`(^|/)cache/`] != 1 {
		t.Fatal("lost aggregate rule counts over JSON")
	}
	for _, n := range []int{0, -1, d.Counts["relevance:vendored"] + 1} {
		bad := d.Clone()
		bad.EnryVendorCounts[`(^|/)cache/`] = n
		if ValidFileDecisions(bad) != nil {
			t.Fatalf("accepted invalid aggregate count %d", n)
		}
	}
}

func TestUnknownRuleCountsKeepCoreDecisionsWithoutMutatingInput(t *testing.T) {
	d := NewFileDecisions()
	d.AddVendored("relevance", "cache/store.py", `(^|/)cache/`)
	d.Add("relevance", "future-vendor/store.py", "vendored")
	d.EnryVendorCounts[`(^|/)future-vendor/`] = 1
	before, _ := json.Marshal(d)
	got := ValidFileDecisions(d)
	if got == nil || len(got.Files) != 2 || got.Counts["relevance:vendored"] != 2 || len(got.EnryVendorCounts) != 1 {
		t.Fatal("unknown rule discarded core decisions")
	}
	after, _ := json.Marshal(d)
	if string(before) != string(after) {
		t.Fatal("normalization mutated the request")
	}
	bad := d.Clone()
	bad.Files[0].Path = "/private/customer.py"
	if ValidFileDecisions(bad) != nil {
		t.Fatal("unknown counts bypassed path validation")
	}
	for i := 0; i < 250; i++ {
		d.EnryVendorCounts[fmt.Sprintf("future-pattern-%d", i)] = 1
	}
	if ValidFileDecisions(d) == nil {
		t.Fatal("a larger future rule list discarded core decisions")
	}
}

func TestLegacyReportsRemainReadableButNewCollectionUsesV2(t *testing.T) {
	var old FileDecisions
	if err := json.Unmarshal([]byte(`{"version":1,"counts":{"relevance:vendored":1},"files":[{"stage":"relevance","path":"cache/store.py","reason":"vendored","enry_vendor_rule":"old optional detail"}],"omitted":0}`), &old); err != nil || ValidFileDecisions(&old) == nil {
		t.Fatal("legacy v1 report rejected")
	}
	b, _ := json.Marshal(old)
	if strings.Contains(string(b), "old optional detail") {
		t.Fatal("removed legacy row field survived decoding")
	}
	clone := old.Clone()
	if clone.Version != 1 {
		t.Fatal("clone changed the wire version")
	}
	clone.Add("relevance", "src/test.go", "test")
	if clone.Version != 2 || ValidFileDecisions(clone) == nil {
		t.Fatal("new collection did not use the byte-budget contract")
	}
	for len(old.Files) <= legacyMaxFileDecisions {
		old.Files = append(old.Files, old.Files[0])
		old.Counts["relevance:vendored"]++
	}
	if ValidFileDecisions(&old) != nil {
		t.Fatal("v1 cardinality contract was silently relaxed")
	}
	old.Version = 2
	if ValidFileDecisions(&old) == nil {
		t.Fatal("v2 still enforces the old record cap")
	}
}
