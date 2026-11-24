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
	"github.com/go-enry/go-enry/v2/regex"
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
		{"cache/store.py", false},
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
		{FilePath: "cache/node_modules/pkg/lib.js", AddedText: "run()"},
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
	if strings.Contains(string(encoded), `"enry_vendor_rule"`) || d.EnryVendorCounts[`(^|/)node_modules/`] != 2 || len(d.EnryVendorCounts) != 1 {
		t.Fatal("per-file labels survived, or aggregate rule totals were lost")
	}
}

func TestHeuristicWarningSurvivesMissingIndividualRule(t *testing.T) {
	// Simulate a fast-matcher result absent from the cached individual patterns.
	fastMatcher := data.FastVendorMatcher
	data.FastVendorMatcher = regex.MustCompile(`(^|/)unknown_vendor/`)
	t.Cleanup(func() { data.FastVendorMatcher = fastMatcher })
	var log bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&log, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	d := wire.NewFileDecisions()
	got := RunWithDecisions([]transcript.Change{{FilePath: "unknown_vendor/store.py", AddedText: "persist(key)"}}, d)
	if len(got) != 0 || wire.ValidFileDecisions(d) == nil || d.Counts["relevance:vendored"] != 1 {
		t.Fatal("missing rule changed the vendor decision")
	}
	if !strings.Contains(log.String(), "WARN") || !strings.Contains(log.String(), "go-enry heuristic") {
		t.Fatalf("heuristic drop lost its warning: %s", log.String())
	}
	log.Reset()
	if len(Run([]transcript.Change{{FilePath: "unknown_vendor/store.py", AddedText: "persist(key)"}})) != 0 {
		t.Fatal("untracked gate changed the vendor decision")
	}
	if !strings.Contains(log.String(), "WARN") || !strings.Contains(log.String(), "go-enry heuristic") {
		t.Fatalf("untracked heuristic drop lost its warning: %s", log.String())
	}
}

func TestCacheSourceAndArtifactDecisions(t *testing.T) {
	for _, tc := range []struct {
		path   string
		body   string
		reason string
	}{
		{"django/core/cache/backends/filebased.py", "persist(key)", "sent"},
		{"src/cmd/go/internal/cache/cache.go", "persist(key)", "sent"},
		{"tools/cache/reflector.go", "persist(key)", "sent"},
		{"activesupport/lib/active_support/cache/redis_cache_store.rb", "persist(key)", "sent"},
		{`src\cache\store.py`, "persist(key)", "sent"},
		{"cache/node_modules/pkg/index.js", "persist(key)", "vendored"},
		{"node_modules/pkg/cache/index.js", "persist(key)", "vendored"},
		{"cache/vendor/pkg/lib.go", "persist(key)", "vendored"},
		{"cache/.cache/tool.py", "persist(key)", "vendored"},
		{"cache/__pycache__/tool.py", "persist(key)", "vendored"},
		{"cache/.next/tool.js", "persist(key)", "vendored"},
		{"cache/.pnp/cache/pkg/index.js", "persist(key)", "vendored"},
		{".yarn/cache/pkg/index.js", "persist(key)", "vendored"},
		{"web/.nx/cache/hash/outputs/main.js", "persist(key)", "vendored"},
		{`web\tmp\cache\store.rb`, "persist(key)", "vendored"},
		{"cache/store.min.js", "persist(key)", "vendored"},
		{"cache/api.pb.go", "persist(key)", "generated"},
		{"cache/test_store.py", "persist(key)", "test"},
		{"cache/store.py", "# just a comment", "comments_only"},
		{"cache/store.py", "persist(\x00key)", "generated_or_binary"},
	} {
		t.Run(tc.path+"/"+tc.reason, func(t *testing.T) {
			changes := []transcript.Change{{FilePath: tc.path, AddedText: tc.body, FullContent: tc.body}}
			d := wire.NewFileDecisions()
			got := RunWithDecisions(changes, d)
			if !reflect.DeepEqual(got, Run(changes)) || !reflect.DeepEqual(got, RunWithDecisions(changes, nil)) {
				t.Fatal("tracked and untracked selection disagree")
			}
			if (len(got) == 1) != (tc.reason == "sent") || len(d.Files) != 1 || d.Files[0].Reason != tc.reason || wire.ValidFileDecisions(d) == nil {
				t.Fatalf("got selected=%d, report=%+v; want %s", len(got), d, tc.reason)
			}
			if d.EnryVendorCounts[`(^|/)cache/`] != 0 {
				t.Fatal("disabled cache rule was counted")
			}
		})
	}
}
