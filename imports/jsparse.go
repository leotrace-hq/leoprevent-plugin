package imports

import "strings"

// jsImport is one import site read from a JS/TS file, before resolution.
type jsImport struct {
	// clause is the binding clause as space-joined tokens (`{ a , b as c }`, `* as ns`,
	// `type { A }`), the text identsOf and valueOnly read. "" when nothing binds: a
	// re-export, or a dynamic import whose result is not assigned to a declaration.
	clause string
	spec   string
	mode   string // "import" or "require": the package.json exports condition it resolves under
	// typed: the clause may carry TypeScript `type` modifiers, so valueOnly applies.
	typed bool
	// reexport: `export * from` / `export {...} from`, resolved ungated.
	reexport bool
	// dynamic: `import('<literal>')`.
	dynamic bool
}

// jsImportsOf extracts the import sites of one JS/TS file. ok=false means the file did
// not lex; the caller then uses jsImportsRegex, the extractor this replaced.
//
// It reads these shapes off the token stream (LEO-378):
//
//	import [type] <clause> from '<spec>'
//	import [type] <name> = require('<spec>')
//	export * [as <name>] from '<spec>'      export {...} from '<spec>'
//	const|let|var <pattern> = require('<spec>')
//	[const|let|var <pattern> = [await]] import('<spec>')
//
// Strings, comments and template literals are tokens, so a commented-out or quoted
// import is never matched, and a comment inside a clause is simply not a token. The
// shapes are matched wherever they occur rather than only at top level: a static
// import or export can only be top level anyway, and a lazy `require` inside a
// function is the common way to defer a load, which the regex path also resolved.
//
// A side-effect `import '<spec>'` is recognised and deliberately yields nothing, as
// before: nothing binds, so nothing in the change can be shown to call into it, and
// it is often a stylesheet.
func jsImportsOf(src string, jsx bool) ([]jsImport, bool) {
	l, err := jsLex(src, jsx)
	if err != nil {
		return nil, false
	}
	return jsImportsFromTokens(l.toks), true
}

func jsImportsFromTokens(toks []jsTok) []jsImport {
	var out []jsImport
	at := func(i int) jsTok {
		if i < 0 || i >= len(toks) {
			return jsTok{kind: jsPunct}
		}
		return toks[i]
	}
	is := func(i int, kind jsTokKind, text string) bool {
		t := at(i)
		return t.kind == kind && t.text == text
	}
	isIdent := func(i int, text string) bool { return is(i, jsIdent, text) }
	isPunct := func(i int, text string) bool { return is(i, jsPunct, text) }
	// requireCall matches `require ( '<spec>' )` at i.
	requireCall := func(i int) (string, bool) {
		if isIdent(i, "require") && isPunct(i+1, "(") && at(i+2).kind == jsString && isPunct(i+3, ")") {
			return at(i + 2).text, true
		}
		return "", false
	}

	for i := 0; i < len(toks); i++ {
		t := toks[i]
		if t.kind != jsIdent || isPunct(i-1, ".") || isPunct(i-1, "?.") {
			continue // a member named `import`/`export`/`const` is not a statement
		}
		switch t.text {
		case "import":
			switch {
			case isPunct(i+1, "("):
				// Dynamic import: only a literal specifier is resolvable.
				if at(i+2).kind == jsString && (isPunct(i+3, ")") || isPunct(i+3, ",")) {
					out = append(out, jsImport{clause: dynamicBinding(toks, i), spec: at(i + 2).text, mode: "import", dynamic: true})
				}
			case isPunct(i+1, "."), at(i+1).kind == jsString:
				// import.meta, or a side-effect import (see above).
			default:
				j := i + 1
				prefix := ""
				// `import type X ...`; but `import type from` and `import type, {...}`
				// bind a default named `type`, and `import type = require` binds `type`.
				if isIdent(j, "type") && !isIdent(j+1, "from") && !isPunct(j+1, ",") && !isPunct(j+1, "=") {
					prefix = "type "
					j++
				}
				if at(j).kind == jsIdent && isPunct(j+1, "=") {
					if spec, ok := requireCall(j + 2); ok {
						out = append(out, jsImport{clause: prefix + at(j).text, spec: spec, mode: "require", typed: true})
					}
					continue
				}
				clause, end, ok := jsClauseAt(toks, j, false)
				if ok && isIdent(end, "from") && at(end+1).kind == jsString {
					out = append(out, jsImport{clause: prefix + clause, spec: at(end + 1).text, mode: "import", typed: true})
				}
			}
		case "export":
			j := i + 1
			switch {
			case isPunct(j, "*"):
				j++
				if isIdent(j, "as") {
					j += 2 // `export * as ns from`: the name may be an identifier or a string
				}
			case isPunct(j, "{"):
				_, end, ok := jsClauseAt(toks, j, false)
				if !ok {
					continue
				}
				j = end
			default:
				continue // `export type {...} from` is type-only; anything else is a local export
			}
			if isIdent(j, "from") && at(j+1).kind == jsString {
				out = append(out, jsImport{spec: at(j + 1).text, mode: "import", reexport: true})
			}
		case "const", "let", "var":
			clause, end, ok := jsClauseAt(toks, i+1, true)
			if !ok || !isPunct(end, "=") {
				continue
			}
			if spec, ok := requireCall(end + 1); ok {
				out = append(out, jsImport{clause: clause, spec: spec, mode: "require"})
			}
		}
	}
	return out
}

// jsClauseAt reads a binding clause starting at toks[i]: identifiers, `*`, commas and
// one level or more of braces, until the first token that cannot be part of one, at
// bracket depth zero. A string inside braces (`{ "a-b" as ab }`) is skipped; only the
// local binding matters to the gate. A destructuring pattern (pattern=true) may also
// hold `:` renames and a `...rest`. It returns the clause text, the index of the token
// after it, and ok=false for an empty or unbalanced clause.
func jsClauseAt(toks []jsTok, i int, pattern bool) (string, int, bool) {
	var parts []string
	depth := 0
	j := i
	for ; j < len(toks); j++ {
		t := toks[j]
		if depth == 0 && len(parts) > 0 && t.kind == jsIdent && t.text == "from" && j+1 < len(toks) && toks[j+1].kind == jsString {
			break // `from '<spec>'` ends the clause; `{ from }` and `import from from` do not
		}
		switch {
		case t.kind == jsIdent:
			if depth == 0 && len(parts) > 0 && !strings.HasSuffix(parts[len(parts)-1], ",") && parts[len(parts)-1] != "*" && parts[len(parts)-1] != "as" && t.text != "as" {
				// Two bare names in a row at depth zero (`x from` aside) cannot both be
				// in a clause: the clause ended at the previous one.
				return strings.Join(parts, " "), j, true
			}
			parts = append(parts, t.text)
		case t.kind == jsString && depth > 0:
			continue
		case t.kind == jsPunct && t.text == "{":
			depth++
			parts = append(parts, "{")
		case t.kind == jsPunct && t.text == "}":
			if depth == 0 {
				return "", j, false
			}
			depth--
			parts = append(parts, "}")
		case t.kind == jsPunct && (t.text == "," || t.text == "*"):
			parts = append(parts, t.text)
		case t.kind == jsPunct && pattern && depth > 0 && (t.text == ":" || t.text == "..."):
			parts = append(parts, t.text)
		default:
			if depth > 0 {
				return "", j, false
			}
			return strings.Join(parts, " "), j, len(parts) > 0
		}
		if depth == 0 && parts[len(parts)-1] == "}" && pattern {
			return strings.Join(parts, " "), j + 1, true
		}
	}
	if depth > 0 || len(parts) == 0 {
		return "", j, false
	}
	return strings.Join(parts, " "), j, true
}

// dynamicBinding finds the declaration a dynamic import at toks[i] is assigned to:
// `const <pattern> = [await] import(...)`. "" when there is none (a `.then`, a lazy
// `() => import(...)`, a bare call), and the caller then gates on the specifier.
func dynamicBinding(toks []jsTok, i int) string {
	k := i - 1
	if k >= 0 && toks[k].kind == jsIdent && toks[k].text == "await" {
		k--
	}
	if k < 1 || toks[k].kind != jsPunct || toks[k].text != "=" {
		return ""
	}
	k--
	end := k + 1
	if toks[k].kind == jsPunct && toks[k].text == "}" {
		depth := 0
		for ; k >= 0; k-- {
			if toks[k].kind == jsPunct && toks[k].text == "}" {
				depth++
			} else if toks[k].kind == jsPunct && toks[k].text == "{" {
				depth--
				if depth == 0 {
					break
				}
			}
		}
		if k < 0 {
			return ""
		}
	} else if toks[k].kind != jsIdent {
		return ""
	}
	if k < 1 || toks[k-1].kind != jsIdent {
		return ""
	}
	switch toks[k-1].text {
	case "const", "let", "var":
	default:
		return ""
	}
	clause, stop, ok := jsClauseAt(toks, k, true)
	if !ok || stop != end {
		return ""
	}
	return clause
}
