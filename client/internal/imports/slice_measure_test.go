package imports

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
)

// What selective function pulling actually saves, measured over a real repository
// rather than a fixture — and, on the same pass, the line-number invariant checked
// against every file it slices.
//
// Run it against any checkout:
//
//	go test -run TestMeasureSliceSaving -v ./client/internal/imports/
//	LEOPREVENT_MEASURE_REPO=/path/to/repo go test -run TestMeasureSliceSaving -v ./client/internal/imports/
//
// It defaults to this repo (walking up for go.mod), which is a real Go + TypeScript
// codebase with a real import graph. Each sampled source file stands in for a turn
// that edited it: the file is FullContent, a trailing slice of it is AddedText, and
// Resolve does exactly what it does on a developer's machine. "Before" is the same
// resolved paths read whole — the behaviour this change replaced.
//
// Deliberately NOT an assertion on the saving: the number depends on the repo, and a
// threshold here would fail on somebody's checkout for no defect. The invariant
// checks below ARE assertions.
const (
	measureSampleTarget = 400  // turns to sample before stopping
	bytesPerToken       = 3.6  // code, Claude tokenizer, approximate
	selectUSDPerMTok    = 1.00 // leoprevent.SelectModel (Haiku 4.5) input
	judgeUSDPerMTok     = 3.00 // leoprevent.JudgeModel (Sonnet 4.6) input
)

func TestMeasureSliceSaving(t *testing.T) {
	root := measureRoot(t)
	corpus := measureCorpus(t, root)
	if len(corpus) == 0 {
		t.Skip("no source files to measure")
	}

	// Three configurations of the same resolver over the same turns, so the saving is
	// measured rather than estimated and each half of the change is priced separately.
	arms := []struct {
		name  string
		slice bool
		types bool
	}{
		{"A whole files (before)", false, false},
		{"B + skip type-only imports", false, true},
		{"C + slice function bodies", true, true},
	}

	turns, examined := measureTurns(t, root, corpus)
	if len(turns) == 0 {
		t.Skip("no turn in this repo resolves imported context")
	}

	results := make([]measureResult, len(arms))
	for i, arm := range arms {
		sliceBodies, skipTypeOnlyImports = arm.slice, arm.types
		results[i] = measureArm(t, root, turns)
	}
	sliceBodies, skipTypeOnlyImports = true, true

	base := results[0]
	t.Logf("repo: %s", root)
	t.Logf("turns: %d of %d examined resolve any imported context (%.0f%%) — the rest are self-contained and unaffected",
		len(turns), examined, 100*float64(len(turns))/float64(examined))
	t.Logf("%-28s %8s %8s %12s %9s", "configuration", "ctxfile", "sliced", "context B", "vs A")
	for i, arm := range arms {
		r := results[i]
		t.Logf("%-28s %8d %8d %12d %8.1f%%", arm.name, r.files, r.sliced, r.bytes, pct(base.bytes, r.bytes))
	}
	for _, k := range sortedKeys(base.byLang) {
		t.Logf("  by language %-6s A=%8d B=%8d C=%8d  saved %.1f%%", k,
			base.byLang[k], results[1].byLang[k], results[2].byLang[k], pct(base.byLang[k], results[2].byLang[k]))
	}

	// The share that matters for latency and spend is the WHOLE review payload, not
	// the context alone: the changed files travel unchanged, so a large saving on
	// context is a smaller saving on the request. Reported both ways.
	final := results[len(results)-1]
	changed := 0
	for _, ch := range turns {
		changed += len(ch.FullContent) + len(ch.AddedText)
	}
	payloadBefore := float64(changed+base.bytes) / float64(len(turns))
	payloadAfter := float64(changed+final.bytes) / float64(len(turns))
	perTurnBefore := float64(base.bytes) / float64(len(turns))
	perTurnAfter := float64(final.bytes) / float64(len(turns))
	tokBefore, tokAfter := payloadBefore/bytesPerToken, payloadAfter/bytesPerToken
	usd := (selectUSDPerMTok + judgeUSDPerMTok) / 1e6
	t.Logf("imported context per such turn: %.0f B -> %.0f B (%.0f%% less)", perTurnBefore, perTurnAfter, pct(base.bytes, final.bytes))
	t.Logf("whole review payload per such turn: %.0f B -> %.0f B (%.1f%% less) | ~%.0f -> ~%.0f input tokens per model pass",
		payloadBefore, payloadAfter, pct(changed+base.bytes, changed+final.bytes), tokBefore, tokAfter)
	t.Logf("per 1000 such reviews: ~$%.2f -> ~$%.2f input spend (select+judge, both see the same payload)",
		1000*tokBefore*usd, 1000*tokAfter*usd)
}

type measureResult struct {
	files, sliced, bytes int
	byLang               map[string]int
}

// measureArm resolves every sampled turn under the currently configured arm and
// totals the imported-context bytes that would be egressed. It also re-checks the
// line-number invariant on every slice it produces, against the file on disk.
func measureArm(t *testing.T, root string, turns []transcript.Change) measureResult {
	t.Helper()
	res := measureResult{byLang: map[string]int{}}
	for _, ch := range turns {
		for _, cf := range Resolve(root, []transcript.Change{ch}) {
			res.files++
			res.bytes += len(cf.Content)
			res.byLang[strings.TrimPrefix(filepath.Ext(ch.FilePath), ".")] += len(cf.Content)
			if len(cf.Lines) > 0 {
				res.sliced++
				if whole, ok := safeRead(root, cf.Path); ok {
					checkLines(t, whole, cf.Content, cf.Lines)
				}
			}
		}
	}
	return res
}

// measureTurns keeps the turns that actually resolve context under the SHIPPED
// configuration, so every arm is priced over the same set of turns.
func measureTurns(t *testing.T, root string, corpus []string) (turns []transcript.Change, examined int) {
	t.Helper()
	for _, rel := range corpus {
		if len(turns) >= measureSampleTarget {
			break
		}
		body, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			continue
		}
		ch := turnFor(rel, string(body))
		if ch.AddedText == "" {
			continue
		}
		examined++
		if len(Resolve(root, []transcript.Change{ch})) == 0 {
			continue
		}
		turns = append(turns, ch)
	}
	return turns, examined
}

func sortedKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func pct(before, after int) float64 {
	if before == 0 {
		return 0
	}
	return 100 * float64(before-after) / float64(before)
}

// turnFor builds the change a turn editing rel would produce: the whole file as
// context, and its trailing lines as the added code. Trailing, because that is
// where a body an agent just wrote tends to sit, and because the import block at
// the top must stay OUT of the added text — a diff that re-adds the imports would
// gate on every symbol in the file and measure nothing.
func turnFor(rel, body string) transcript.Change {
	lines := strings.Split(strings.TrimRight(body, "\n"), "\n")
	if len(lines) < 20 {
		return transcript.Change{}
	}
	start := len(lines) - 40
	if start < len(lines)/2 {
		start = len(lines) / 2
	}
	return transcript.Change{
		FilePath:    rel,
		FullContent: body,
		AddedText:   strings.Join(lines[start:], "\n"),
	}
}

func measureRoot(t *testing.T) string {
	t.Helper()
	if r := os.Getenv("LEOPREVENT_MEASURE_REPO"); r != "" {
		return r
	}
	dir, err := os.Getwd()
	if err != nil {
		t.Skip("no working directory")
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Skip("no repository root found")
	return ""
}

// measureCorpus lists the repo's reviewable source files, in the same spirit as the
// inert gate: no vendored trees, no tests (the gate drops those before review, so
// counting them would measure code this pipeline never sees).
func measureCorpus(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if p != root && (indexSkipDirs[d.Name()] || strings.HasPrefix(d.Name(), ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		if !indexExts[strings.ToLower(filepath.Ext(name))] {
			return nil
		}
		if strings.HasSuffix(name, "_test.go") || strings.Contains(name, ".test.") || strings.Contains(name, ".spec.") {
			return nil
		}
		if rel, err := filepath.Rel(root, p); err == nil {
			out = append(out, filepath.ToSlash(rel))
		}
		return nil
	})
	sort.Strings(out)
	return out
}
