package gate

import (
	"reflect"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

func TestDecisionReportPreservesGateAndNamesSkippedFiles(t *testing.T) {
	files := []transcript.Change{{FilePath: "README.md", AddedText: "hello"}, {FilePath: "src/main.go", AddedText: "package main\nfunc main() { work() }"}, {FilePath: "src/main_test.go", AddedText: "test()"}}
	d := wire.NewFileDecisions()
	got := RunWithDecisions(files, d)
	if !reflect.DeepEqual(got, Run(files)) {
		t.Fatal("instrumentation changed selection")
	}
	if len(got) != 1 || d.Counts["relevance:test"] != 1 || d.Files[2].Path != "src/main_test.go" || wire.ValidFileDecisions(d) == nil {
		t.Fatalf("bad decisions: %+v", d)
	}
}
