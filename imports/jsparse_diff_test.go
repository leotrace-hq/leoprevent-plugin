package imports

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The differential harness LEO-378 asked for: run the token extractor (jsImportsOf) and
// the regex extractor it replaced (jsImportsRegex) over every JS/TS file of a real
// checkout, and log every file where they disagree, every file the lexer rejects (those
// fall back to the regex path), and every file whose slicer spans moved because the
// brace scan now runs on lexed code instead of stripCode. Run it with -v to read them:
//
//	go test -run TestJSExtractorDifferential -v ./imports/
//	LEOPREVENT_MEASURE_REPO=/path/to/repo go test -run TestJSExtractorDifferential -v ./imports/
//
// Like TestMeasureSliceSaving it defaults to this repository, where it reads the
// dashboard apps and shared packages, and it asserts nothing about the counts: whether a
// disagreement is a fix or a regression takes reading it, which is the point of logging
// each one. Its findings are summarised in the LEO-378 PR.
func TestJSExtractorDifferential(t *testing.T) {
	root := measureRoot(t)
	var dirs []string
	if os.Getenv("LEOPREVENT_MEASURE_REPO") != "" {
		dirs = []string{root}
	} else {
		for _, d := range []string{"web-customer", "web-internal", "packages"} {
			dirs = append(dirs, filepath.Join(root, d))
		}
	}
	var files []string
	for _, dir := range dirs {
		_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() && p != dir {
				name := d.Name()
				if name == "node_modules" || name == "dist" || name == "build" || strings.HasPrefix(name, ".") {
					return filepath.SkipDir
				}
				return nil
			}
			if d.IsDir() {
				return nil
			}
			if langOf(p) == langJS && !strings.HasSuffix(p, ".d.ts") {
				files = append(files, p)
			}
			return nil
		})
	}
	if len(files) == 0 {
		t.Skip("no JS/TS files to compare")
	}

	var lexFailed, importDiffs, spanDiffs int
	for _, p := range files {
		raw, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		src := string(raw)
		rel, _ := filepath.Rel(root, p)
		jsx := jsxAllowed(p)

		tok, ok := jsImportsOf(src, jsx)
		if !ok {
			_, lexErr := jsLex(src, jsx)
			lexFailed++
			t.Logf("LEX FAIL %s: %v (falls back to the regex path)", rel, lexErr)
			continue
		}
		onlyTok, onlyRe := diffSets(jsImportKeys(tok), jsImportKeys(jsImportsRegex(src)))
		if len(onlyTok)+len(onlyRe) > 0 {
			importDiffs++
			for _, k := range onlyTok {
				t.Logf("IMPORT %s: tokens only: %s", rel, k)
			}
			for _, k := range onlyRe {
				t.Logf("IMPORT %s: regex only:  %s", rel, k)
			}
		}

		if strings.TrimSpace(src) == "" {
			continue
		}
		lines := strings.Split(strings.TrimRight(src, "\n"), "\n")
		code := jsCodeLines(strings.Join(lines, "\n"), jsx)
		before := spanKeys(braceSpans(langJS, lines, nil))
		after := spanKeys(braceSpans(langJS, lines, code))
		gained, lost := diffSets(after, before)
		if len(gained)+len(lost) > 0 {
			spanDiffs++
			t.Logf("SPANS %s: +%d -%d gained=%v lost=%v", rel, len(gained), len(lost), gained, lost)
		}
	}
	t.Logf("%d JS/TS files: %d lexer rejections (regex fallback), %d with import disagreements, %d with span changes",
		len(files), lexFailed, importDiffs, spanDiffs)
}

// jsImportKeys renders each import site as what the resolver acts on: its kind, the
// specifier and the identifiers that gate it after the type-only filter.
func jsImportKeys(imps []jsImport) []string {
	var out []string
	for _, im := range imps {
		clause := im.clause
		if im.typed {
			clause = valueOnly(clause)
			if strings.TrimSpace(strings.Trim(clause, "{}, ")) == "" {
				continue
			}
		}
		ids := identsOf(clause)
		sort.Strings(ids)
		kind := im.mode
		switch {
		case im.reexport:
			kind = "reexport"
		case im.dynamic:
			kind = "dynamic"
		}
		out = append(out, fmt.Sprintf("%s %q gate=%v", kind, im.spec, ids))
	}
	return out
}

func spanKeys(spans []span) []string {
	var out []string
	for _, s := range spans {
		out = append(out, fmt.Sprintf("%s@%d-%d", s.name, s.start, s.end))
	}
	return out
}

// diffSets returns what is in a and not b, and in b and not a (as sets, sorted).
func diffSets(a, b []string) (onlyA, onlyB []string) {
	inA, inB := map[string]bool{}, map[string]bool{}
	for _, k := range a {
		inA[k] = true
	}
	for _, k := range b {
		inB[k] = true
	}
	for k := range inA {
		if !inB[k] {
			onlyA = append(onlyA, k)
		}
	}
	for k := range inB {
		if !inA[k] {
			onlyB = append(onlyB, k)
		}
	}
	sort.Strings(onlyA)
	sort.Strings(onlyB)
	return onlyA, onlyB
}
