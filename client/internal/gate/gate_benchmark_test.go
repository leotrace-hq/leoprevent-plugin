package gate

import (
	"fmt"
	"io"
	"log/slog"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

var benchmarkChanges []transcript.Change

// BenchmarkRun compares ordinary source, mixed turns and positive vendor matches.
// Logging is disabled so the result measures filtering and report collection only.
func BenchmarkRun(b *testing.B) {
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError})))
	b.Cleanup(func() { slog.SetDefault(previous) })
	for _, n := range []int{100, 1000} {
		for _, kind := range []string{"source", "mixed", "vendor_filename", "cache_source", "tool_cache"} {
			changes := make([]transcript.Change, n)
			for i := range changes {
				path := fmt.Sprintf("src/feature-%05d/handler.go", i)
				switch kind {
				case "vendor_filename":
					path = fmt.Sprintf("web/widgets/%05d/react.js", i)
				case "cache_source":
					path = fmt.Sprintf("src/cache/feature-%05d/handler.go", i)
				case "tool_cache":
					path = fmt.Sprintf(".cache/feature-%05d/handler.go", i)
				case "mixed":
					switch i % 10 {
					case 0:
						path = fmt.Sprintf("docs/readme-%05d.md", i)
					case 1:
						path = fmt.Sprintf("src/feature-%05d/handler_test.go", i)
					case 2:
						path = fmt.Sprintf("cache/feature-%05d/handler.go", i)
					}
				}
				body := "package handlers\nfunc Handle(input string) string { return input }\n"
				changes[i] = transcript.Change{FilePath: path, AddedText: body, FullContent: body}
			}
			b.Run(fmt.Sprintf("%s_%d/plain", kind, n), func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					benchmarkChanges = Run(changes)
				}
				b.ReportMetric(float64(len(benchmarkChanges)), "reviewable/op")
			})
			b.Run(fmt.Sprintf("%s_%d/tracked", kind, n), func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					benchmarkChanges = RunWithDecisions(changes, wire.NewFileDecisions())
				}
				b.ReportMetric(float64(len(benchmarkChanges)), "reviewable/op")
			})
		}
	}
}
