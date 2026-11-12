package imports

import (
	"reflect"
	"strings"
	"testing"
)

// LEO-378: the gaps the regex extractor left after LEO-376, one test each. Every
// resolution test below fails on the regex path (force jsImportsOf to report ok=false
// to see it), except the fallback test, which pins that path.

// jsResolve runs the resolver for one changed JS/TS file and returns the sorted paths.
func jsResolve(t *testing.T, files map[string]string, changed, full, added string) []string {
	t.Helper()
	files[changed] = full
	root := writeRepo(t, files)
	return paths(resolve(t, root, Change{FilePath: changed, AddedText: added, FullContent: full}))
}

func wantPaths(t *testing.T, got []string, want ...string) {
	t.Helper()
	if len(want) == 0 {
		want = nil
	}
	if len(got) == 0 {
		got = nil
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("want %v, got %v", want, got)
	}
}

const sinkJS = "export function runCmd(n) { exec('tar ' + n) }\n"

// A comment inside a Prettier-wrapped clause: the character-class clause could not
// cross the `//`, so the whole import silently resolved nothing.
func TestJSCommentInsideClauseStillResolves(t *testing.T) {
	got := jsResolve(t, map[string]string{"src/sink.js": sinkJS}, "src/h.ts",
		"import {\n  other, // legacy, keep for v1 callers\n  /* the sink */ runCmd,\n} from './sink'\nrunCmd(req.query.name)\n",
		"runCmd(req.query.name)")
	wantPaths(t, got, "src/sink.js")
}

// A commented-out import is not an import: resolving it egressed a file the program
// never loads.
func TestJSCommentedOutImportDoesNotResolve(t *testing.T) {
	for name, full := range map[string]string{
		"line":  "// import { runCmd } from './sink'\nrunCmd(x)\n",
		"block": "/*\nimport { runCmd } from './sink'\n*/\nrunCmd(x)\n",
		"jsdoc": "/**\n * @example\n * const { runCmd } = require('./sink')\n */\nrunCmd(x)\n",
	} {
		t.Run(name, func(t *testing.T) {
			wantPaths(t, jsResolve(t, map[string]string{"src/sink.js": sinkJS}, "src/h.js", full, "runCmd(x)"))
		})
	}
}

// Nor is an import written inside a string or a template literal (a code generator, a
// test asserting on source text).
func TestJSImportInsideAStringDoesNotResolve(t *testing.T) {
	for name, full := range map[string]string{
		"string":   "const src = \"import { runCmd } from './sink'\"\nrunCmd(x)\n",
		"template": "const src = `\nimport { runCmd } from './sink'\n`\nrunCmd(x)\n",
		"require":  "emit('const { runCmd } = require(\"./sink\")')\nrunCmd(x)\n",
	} {
		t.Run(name, func(t *testing.T) {
			wantPaths(t, jsResolve(t, map[string]string{"src/sink.js": sinkJS}, "src/h.js", full, "runCmd(x)"))
		})
	}
}

// TypeScript's CommonJS import form, `import x = require('./y')`, gated on x.
func TestJSImportEqualsRequireResolves(t *testing.T) {
	files := map[string]string{"src/sink.ts": sinkJS}
	wantPaths(t, jsResolve(t, files, "src/h.ts", "import sink = require('./sink')\nsink.runCmd(x)\n", "sink.runCmd(x)"), "src/sink.ts")
	wantPaths(t, jsResolve(t, files, "src/h.ts", "import sink = require('./sink')\nother(x)\n", "other(x)"))
	// The type-only form is erased like any other type-only import.
	wantPaths(t, jsResolve(t, files, "src/h.ts", "import type sink = require('./sink')\nlet s: sink.T\n", "let s: sink.T"))
}

// A dynamic import assigned to a declaration gates on its binding, like a static one.
// One that binds nothing gates on the added code writing the specifier itself.
func TestJSDynamicImportResolves(t *testing.T) {
	files := map[string]string{"src/sink.js": sinkJS, "src/lazy.js": sinkJS}
	wantPaths(t, jsResolve(t, files, "src/h.js",
		"async function go(x) {\n  const { runCmd } = await import('./sink')\n  runCmd(x)\n}\n", "runCmd(x)"), "src/sink.js")
	wantPaths(t, jsResolve(t, files, "src/h.js",
		"async function go(x) {\n  const { runCmd } = await import('./sink')\n  runCmd(x)\n}\nother(y)\n", "other(y)"))
	wantPaths(t, jsResolve(t, files, "src/h.js",
		"const Lazy = lazy(() => import('./lazy'))\n", "const Lazy = lazy(() => import('./lazy'))"), "src/lazy.js")
	// A router full of lazy routes does not pull them all for an unrelated edit.
	wantPaths(t, jsResolve(t, files, "src/h.js",
		"const Lazy = lazy(() => import('./lazy'))\nother(y)\n", "other(y)"))
}

// Re-exports now come off the same token stream, including the `export * as ns` form
// the old pattern did not match, and a type-only re-export stays unresolved.
func TestJSReexportsResolve(t *testing.T) {
	files := map[string]string{"src/sink.js": sinkJS}
	for name, tc := range map[string]struct {
		full string
		want []string
	}{
		"named":     {"export { runCmd as run } from './sink'\n", []string{"src/sink.js"}},
		"star":      {"export * from './sink'\n", []string{"src/sink.js"}},
		"star-as":   {"export * as sink from './sink'\n", []string{"src/sink.js"}},
		"type-only": {"export type { Cmd } from './sink'\n", nil},
		"local":     {"export { runCmd }\nconst x = from('./sink')\n", nil},
	} {
		t.Run(name, func(t *testing.T) {
			wantPaths(t, jsResolve(t, files, "src/index.ts", tc.full+"x()\n", "x()"), tc.want...)
		})
	}
}

// A file the lexer rejects resolves exactly as it did before, through the regex path:
// a lexer gap must never resolve less.
func TestJSLexFailureFallsBackToTheRegexPath(t *testing.T) {
	full := "import { runCmd } from './sink'\nconst broken = 'unterminated\nrunCmd(x)\n"
	if _, ok := jsImportsOf(full, false); ok {
		t.Fatal("fixture should not lex")
	}
	wantPaths(t, jsResolve(t, map[string]string{"src/sink.js": sinkJS}, "src/h.js", full, "runCmd(x)"), "src/sink.js")
}

// The LEO-376 guard, on the token path: a side-effect import followed by code holding
// `from` must not glue into one clause, and a bare `let x` must not become the binding
// of the next statement's require.
func TestJSTokenClauseDoesNotSpanStatements(t *testing.T) {
	imps, ok := jsImportsOf("import './polyfill'\nconst runCmd = pick(x)\nexport { thing } from './wrong'\nrunCmd()\n", false)
	if !ok {
		t.Fatal("did not lex")
	}
	for _, im := range imps {
		if !im.reexport || im.spec != "./wrong" {
			t.Fatalf("unexpected import site %+v", im)
		}
	}
	imps, _ = jsImportsOf("require('./side')\nlet runCmd\nfoo = require('./y')\nconst x = require('./z')\n", false)
	if len(imps) != 1 || imps[0].clause != "x" || imps[0].spec != "./z" {
		t.Fatalf("want only x <- ./z, got %+v", imps)
	}
}

// The lexer's hard cases, each of which desyncs a line-oriented scanner.
func TestJSLexHardCases(t *testing.T) {
	cases := []struct {
		name, src string
		jsx       bool
	}{
		{"template with nested braces", "const s = `a ${ {k: `in ${x}`}.k } b`\nimport { a } from './a'\n", false},
		{"regex holding a quote and brace", "const re = /['{]/g\nimport { a } from './a'\n", false},
		{"regex after keyword", "function f(s) { return /\\/\\*/.test(s) }\nimport { a } from './a'\n", false},
		{"division is not a regex", "const r = total / count / 2 // it's fine\nimport { a } from './a'\n", false},
		{"postfix increment then division", "let i = 0; const q = i++ / 2; const w = 'x' // don't\nimport { a } from './a'\n", false},
		{"jsx text with apostrophes", "const C = () => <p className=\"x\">Don't {n > 1 ? <b>it's</b> : null} stop</p>\nimport { a } from './a'\n", true},
		{"jsx fragment and self-closing", "const C = () => (<>\n  <Row k={1} on={() => { go() }} />\n</>)\nimport { a } from './a'\n", true},
		{"tsx generic arrow", "const id = <T,>(x: T) => x\nimport { a } from './a'\n", true},
		{"ts type assertion", "const n = <number>value\nimport { a } from './a'\n", false},
		{"shift operator", "const m = 1<<s\nimport { a } from './a'\n", true},
		{"import.meta and member import", "const u = import.meta.url; obj.import('./b')\nimport { a } from './a'\n", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			imps, ok := jsImportsOf(tc.src, tc.jsx)
			if !ok {
				_, err := jsLex(tc.src, tc.jsx)
				t.Fatalf("did not lex: %v", err)
			}
			if len(imps) != 1 || imps[0].spec != "./a" {
				t.Fatalf("want the one import of ./a, got %+v", imps)
			}
		})
	}
}

// slice_lang.go's stripCode had no notion of a regex literal, so the brace in `/[{]/`
// opened a block that never closed and the function holding it got no span (its body
// could not be elided, and every span after it shifted). The lexed path keeps it.
func TestJSSliceSpanSurvivesARegexHoldingABrace(t *testing.T) {
	src := "export function parse(s) {\n  const re = /^[{]+/\n  return re.test(s)\n}\n\nexport function other() {\n  return 1\n}\n"
	lines := strings.Split(strings.TrimRight(src, "\n"), "\n")
	var names []string
	for _, sp := range funcSpans("lib/p.js", lines) {
		names = append(names, sp.name)
	}
	if !reflect.DeepEqual(names, []string{"parse", "other"}) {
		t.Fatalf("want spans [parse other], got %v", names)
	}
}

// jsCodeLines must keep line N on line N whatever it removes, or every span is
// misnumbered.
func TestJSCodeLinesKeepLineNumbers(t *testing.T) {
	src := "a /* one\ntwo */ b\nc = `x\ny ${ z } w`\nd // e\n"
	got := jsCodeLines(src, false)
	want := strings.Split(src, "\n")
	if len(got) != len(want) {
		t.Fatalf("line count %d, want %d: %q", len(got), len(want), got)
	}
	if strings.Contains(strings.Join(got, "\n"), "two") || got[4] != "d " {
		t.Fatalf("unexpected stripped lines %q", got)
	}
}
