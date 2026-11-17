package gate

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"github.com/go-enry/go-enry/v2/data"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

func TestDecisionReportPreservesGateAndNamesSkippedFiles(t *testing.T) {
	files := []transcript.Change{{FilePath: "README.md", AddedText: "hello"}, {FilePath: "src/main.go", AddedText: "package main\nfunc main() { work() }"}, {FilePath: "src/main_test.go", AddedText: "test()"}}
	d := wire.NewFileDecisions()
	got := RunWithDecisions(files, d)
	if !reflect.DeepEqual(got, Run(files)) || !reflect.DeepEqual(got, RunWithDecisions(files, nil)) {
		t.Fatal("instrumentation changed selection")
	}
	if len(got) != 1 || d.Counts["relevance:test"] != 1 || d.Files[2].Path != "src/main_test.go" || wire.ValidFileDecisions(d) == nil {
		t.Fatalf("bad decisions: %+v", d)
	}
}

func TestVendorRuleLookupOnlyWhenTracking(t *testing.T) {
	for _, tc := range []struct {
		path string
		rule bool
	}{
		{"cache/store.py", true},
		{"web/widgets/react.js", true},
		{`node_modules\pkg\lib.js`, true},
		{".cache/store.py", false}, // Explicit exclusion takes precedence.
		{".github/workflows/build.yml", false},
		{"src/main.go", false},
	} {
		t.Run(tc.path, func(t *testing.T) {
			c := transcript.Change{FilePath: tc.path, AddedText: "run()"}
			reason, rule := exclusionReason(c, false)
			trackedReason, trackedRule := exclusionReason(c, true)
			if reason != trackedReason || rule != "" || (trackedRule != "") != tc.rule {
				t.Fatalf("untracked=(%q, %q), tracked=(%q, %q)", reason, rule, trackedReason, trackedRule)
			}
		})
	}
}

func TestGateRetainsVendorPathsAndTotalsAfterContextFillsByteBudget(t *testing.T) {
	d := wire.NewFileDecisions()
	for i := 0; d.Omitted == 0; i++ {
		d.Add("context", fmt.Sprintf("lib/%d.go", i), "context_unavailable")
	}
	files := []transcript.Change{
		{FilePath: "django/core/cache/backends/filebased.py", AddedText: "run()"},
		{FilePath: "node_modules/pkg/lib.js", AddedText: "run()"},
		{FilePath: ".cache/tool.py", AddedText: "run()"},
		{FilePath: "src/main.go", AddedText: "package main\nfunc main() { work() }"},
	}
	got := RunWithDecisions(files, d)
	if !reflect.DeepEqual(got, files[3:]) || !reflect.DeepEqual(got, Run(files)) {
		t.Fatal("rule instrumentation changed gate decisions")
	}
	want := map[string]bool{
		files[0].FilePath: true,
		files[1].FilePath: true,
		files[2].FilePath: true,
	}
	for _, f := range d.Files {
		if f.Reason != "vendored" {
			continue
		}
		if !want[f.Path] {
			t.Fatalf("unexpected vendor example: %+v", f)
		}
		delete(want, f.Path)
	}
	if len(want) != 0 || wire.ValidFileDecisions(d) == nil || d.Counts["relevance:vendored"] != 3 {
		t.Fatalf("lost vendor examples: %+v, %+v", want, d)
	}
	encoded, _ := json.Marshal(d)
	if strings.Contains(string(encoded), `"enry_vendor_rule"`) || d.EnryVendorCounts[`(^|/)cache/`] != 1 || d.EnryVendorCounts[`(^|/)node_modules/`] != 1 || len(d.EnryVendorCounts) != 2 {
		t.Fatal("per-file labels survived, or aggregate rule totals were lost")
	}
}

func TestHeuristicWarningSurvivesMissingIndividualRule(t *testing.T) {
	// Simulate a fast-matcher result whose individual pattern is unavailable.
	matchers := data.VendorMatchers
	data.VendorMatchers = nil
	t.Cleanup(func() { data.VendorMatchers = matchers })
	var log bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&log, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	d := wire.NewFileDecisions()
	got := RunWithDecisions([]transcript.Change{{FilePath: "cache/store.py", AddedText: "persist(key)"}}, d)
	if len(got) != 0 || wire.ValidFileDecisions(d) == nil || d.Counts["relevance:vendored"] != 1 {
		t.Fatal("missing rule changed the vendor decision")
	}
	if !strings.Contains(log.String(), "WARN") || !strings.Contains(log.String(), "go-enry heuristic") {
		t.Fatalf("heuristic drop lost its warning: %s", log.String())
	}
	log.Reset()
	if len(Run([]transcript.Change{{FilePath: "cache/store.py", AddedText: "persist(key)"}})) != 0 {
		t.Fatal("untracked gate changed the vendor decision")
	}
	if !strings.Contains(log.String(), "WARN") || !strings.Contains(log.String(), "go-enry heuristic") {
		t.Fatalf("untracked heuristic drop lost its warning: %s", log.String())
	}
}
