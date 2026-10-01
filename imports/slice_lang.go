package imports

import (
	"regexp"
	"strings"
)

// Per-language span finders for the slicer. Every one of them is allowed to fail:
// a construct it does not recognise yields no span, and a line in no span is kept.
// So the worst a gap here can do is send more bytes than necessary.

// ---- Python (indentation-delimited) ----

var pyDefRe = regexp.MustCompile(`^([ \t]*)(?:async[ \t]+)?def[ \t]+([A-Za-z_]\w*)[ \t]*\(`)

func pySpans(lines []string) []span {
	var out []span
	inDoc := "" // open triple-quote delimiter, "" when not inside one
	for i := 0; i < len(lines); i++ {
		if d := pyDocShift(lines[i], inDoc); d != inDoc {
			inDoc = d
			continue
		}
		if inDoc != "" {
			continue
		}
		m := pyDefRe.FindStringSubmatch(lines[i])
		if m == nil {
			continue
		}
		indent := pyIndent(m[1])
		start := i + 1 // 1-based
		// Decorators immediately above at the same indent belong to the definition.
		for j := i - 1; j >= 0; j-- {
			t := strings.TrimSpace(lines[j])
			if t == "" || !strings.HasPrefix(t, "@") || pyIndent(leadingWS(lines[j])) != indent {
				break
			}
			start = j + 1
		}
		// Header runs to the line closing the signature (parens balanced, ends ':').
		headEnd := i + 1
		depth := 0
		for j := i; j < len(lines); j++ {
			depth += strings.Count(lines[j], "(") - strings.Count(lines[j], ")")
			if depth <= 0 && strings.HasSuffix(strings.TrimSpace(lines[j]), ":") {
				headEnd = j + 1
				break
			}
			headEnd = j + 1
		}
		// Body runs while lines are blank or indented deeper than the def.
		end := headEnd
		for j := headEnd; j < len(lines); j++ {
			if strings.TrimSpace(lines[j]) == "" {
				continue
			}
			if pyIndent(leadingWS(lines[j])) <= indent {
				break
			}
			end = j + 1
		}
		if end > headEnd {
			out = append(out, span{name: m[2], docStart: docStart(lines, start, true), start: start, headEnd: headEnd, end: end})
		}
		i = end - 1 // skip nested defs; they ride their parent's decision
	}
	return out
}

// pyDocShift toggles the triple-quote state for one line. It is a coarse guard
// against a `def` inside a docstring being read as a definition, not a Python
// lexer: a line opening AND closing a docstring leaves the state unchanged.
func pyDocShift(line, open string) string {
	if open != "" {
		if strings.Contains(line, open) {
			return ""
		}
		return open
	}
	for _, d := range []string{`"""`, "'''"} {
		if n := strings.Count(line, d); n > 0 && n%2 == 1 {
			return d
		}
	}
	return ""
}

// docStart walks back from a declaration over the comment block written directly
// above it — `//` lines, a `/* … */` or `/** … */` block, and `#` lines in Python —
// and returns the first line of it, or start when there is none.
//
// Contiguity is the whole rule: a blank line or any code ends the walk, so this
// attaches a doc to the ONE declaration it sits against and never sweeps up a
// section header separated from it. The doc then shares its span's fate.
//
// hash says whether `#` opens a comment. It does in Python; in JS and TypeScript it
// opens a PRIVATE CLASS FIELD (`#secret = …`), which is code, and reading those as
// a doc would elide a class's private state along with the next method's body.
func docStart(lines []string, start int, hash bool) int {
	first := start
	inBlock := false
	for j := start - 2; j >= 0; j-- { // start is 1-based; the line above it is index start-2
		t := strings.TrimSpace(lines[j])
		switch {
		case inBlock:
			first = j + 1
			if strings.HasPrefix(t, "/*") {
				inBlock = false
				if !strings.HasSuffix(t, "*/") {
					return first
				}
			}
			continue
		case strings.HasPrefix(t, "//"), hash && strings.HasPrefix(t, "#"):
			first = j + 1
			continue
		case strings.HasSuffix(t, "*/"):
			first = j + 1
			if strings.HasPrefix(t, "/*") {
				continue // a one-line block comment
			}
			inBlock = true
			continue
		default:
			return first
		}
	}
	return first
}

func leadingWS(s string) string {
	return s[:len(s)-len(strings.TrimLeft(s, " \t"))]
}

// pyIndent measures indentation with a tab worth 8 columns. Only relative depth
// within one file matters, so the exact tab width is irrelevant as long as it is
// consistent.
func pyIndent(ws string) int {
	n := 0
	for _, r := range ws {
		if r == '\t' {
			n += 8
		} else {
			n++
		}
	}
	return n
}

// ---- brace languages (Go, JS/TS, Java, C#) ----

var (
	goFuncRe = regexp.MustCompile(`^func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*[\(\[]`)

	jsFuncRe  = regexp.MustCompile(`^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)\s*\(`)
	jsArrowRe = regexp.MustCompile(`^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=]+)?=\s*(?:async\s*)?(?:function\b|\(|[A-Za-z_$][\w$]*\s*=>)`)

	// methodRe is the loose "name(args) {" shape shared by JS class/object methods,
	// Java and C#. It captures control-flow lines too ("if (x) {"), which
	// controlKeyword rejects — the same trade the server's defNameREs make.
	methodRe = regexp.MustCompile(`^\s*(?:[\w@<>\[\]?,.]+\s+)*([A-Za-z_$][\w$]*)\s*[<(]`)
)

// controlKeyword names the loose method pattern can capture from a control-flow or
// call line — never a definition. Mirrors the server's controlKeywords (they serve
// the same regex hazard on either side of the wire).
var controlKeyword = map[string]bool{
	"if": true, "for": true, "foreach": true, "while": true, "switch": true, "catch": true,
	"try": true, "do": true, "else": true, "return": true, "with": true, "when": true,
	"using": true, "lock": true, "synchronized": true, "await": true, "function": true,
	"new": true, "yield": true, "throw": true, "case": true, "typeof": true, "in": true,
}

func braceSpans(l lang, lines []string) []span {
	var out []span
	st := &scanState{}
	for i := 0; i < len(lines); i++ {
		// Track string/comment state across every line, so a brace inside a comment
		// or a string literal never opens or closes a span.
		code := stripCode(l, lines[i], st)
		name, isDecl := declName(l, lines[i], code)
		if !isDecl {
			continue
		}
		headEnd, end, ok := braceBody(l, lines, i, st)
		if !ok {
			continue // unbalanced or no body found → no span → the lines are kept
		}
		if end > headEnd {
			out = append(out, span{name: name, docStart: docStart(lines, i+1, false), start: i + 1, headEnd: headEnd, end: end})
		}
		i = end - 1 // skip nested closures; they ride their parent's decision
	}
	return out
}

func declName(l lang, raw, code string) (string, bool) {
	if strings.TrimSpace(code) == "" {
		return "", false
	}
	if l == langGo {
		if m := goFuncRe.FindStringSubmatch(code); m != nil {
			return m[1], true
		}
		return "", false
	}
	if l == langJS {
		if m := jsFuncRe.FindStringSubmatch(code); m != nil {
			return m[1], true
		}
		if m := jsArrowRe.FindStringSubmatch(code); m != nil {
			return m[1], true
		}
	}
	// Java / C# / JS methods: require the parens to CLOSE on this line and a body to
	// open, so a bare call or a multi-line signature is never mistaken for one.
	if !strings.Contains(code, ")") || !strings.Contains(code, "{") {
		return "", false
	}
	if strings.Contains(code, "=") && !strings.Contains(code, "==") {
		return "", false // an assignment, not a declaration
	}
	m := methodRe.FindStringSubmatch(code)
	if m == nil || controlKeyword[m[1]] {
		return "", false
	}
	return m[1], true
}

// braceBody finds the header end and body end of a declaration starting at the
// 0-based line i, by matching the opening brace. st is advanced through the span
// so the caller's cross-line string/comment state stays correct. ok=false when no
// brace opens within a short header window or the braces never balance (EOF) —
// both leave the lines unsliced.
func braceBody(l lang, lines []string, i int, st *scanState) (headEnd, end int, ok bool) {
	depth := 0
	opened := false
	for j := i; j < len(lines); j++ {
		var code string
		if j == i {
			// The declaration's own line was already stripped by the caller, so re-strip
			// it from a fresh state rather than advancing st twice.
			code = stripCode(l, lines[j], &scanState{})
		} else {
			code = stripCode(l, lines[j], st)
		}
		if !opened {
			// The brace that opens a BODY is the one that ENDS a line. Every other
			// brace on a signature belongs to the signature: a destructured parameter
			// (`function render({ rows, onPick }) {`) or a TypeScript object return
			// type (`): { events: Event[] } {`). Counting those opened the span on the
			// signature and closed it on the same line, so the span came out empty and
			// was discarded — which silently excluded the shapes React and TypeScript
			// are mostly written in. A one-line body is passed over by the same rule,
			// and has nothing worth eliding anyway.
			if !strings.HasSuffix(strings.TrimRight(code, " \t"), "{") {
				if j-i >= maxHeaderLines {
					return 0, 0, false
				}
				continue
			}
			opened, headEnd, depth = true, j+1, 1
			continue
		}
		for _, r := range code {
			switch r {
			case '{':
				depth++
			case '}':
				depth--
				if depth <= 0 {
					return headEnd, j + 1, true
				}
			}
		}
	}
	return 0, 0, false
}

// maxHeaderLines is how far past a declaration the opening brace may sit. A typed
// TypeScript or Java signature routinely puts each parameter on its own line, and a
// window of a few lines silently skipped exactly those — the long-signature
// functions, which are the large ones worth slicing.
const maxHeaderLines = 12

// scanState carries string/comment state across lines.
type scanState struct {
	inBlockComment bool
	inRaw          bool // Go raw string / JS template literal (backtick)
}

// stripCode blanks out string literals and comments in one line, advancing st.
// It is a lexer only to the depth this needs: a brace inside a string or comment
// must not count. A construct it mishandles (a JS regex literal holding a brace)
// unbalances the span, which braceBody rejects — the safe direction.
func stripCode(l lang, line string, st *scanState) string {
	var b strings.Builder
	runes := []rune(line)
	for i := 0; i < len(runes); i++ {
		c := runes[i]
		switch {
		case st.inBlockComment:
			if c == '*' && i+1 < len(runes) && runes[i+1] == '/' {
				st.inBlockComment = false
				i++
			}
		case st.inRaw:
			if c == '`' {
				st.inRaw = false
			}
		case c == '/' && i+1 < len(runes) && runes[i+1] == '/':
			return b.String()
		case c == '#' && l != langGo && l != langJS && l != langJava && l != langCSharp:
			return b.String()
		case c == '/' && i+1 < len(runes) && runes[i+1] == '*':
			st.inBlockComment = true
			i++
		case c == '`':
			st.inRaw = true
		case c == '"' || c == '\'':
			q := c
			for i++; i < len(runes); i++ {
				if runes[i] == '\\' {
					i++
					continue
				}
				if runes[i] == q {
					break
				}
			}
		default:
			b.WriteRune(c)
		}
	}
	return b.String()
}
