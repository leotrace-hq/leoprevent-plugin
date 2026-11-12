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

// braceSpans finds the brace-delimited function spans. code, when non-nil, is each
// line with its non-code already removed (jsCodeLines, for a JS/TS file that lexed);
// otherwise each line is stripped by stripCode as the scan reaches it.
func braceSpans(l lang, lines []string, code []string) []span {
	strip := func(j int, st *scanState) string {
		if code != nil {
			return code[j]
		}
		return stripCode(l, lines[j], st)
	}
	var out []span
	st := &scanState{}
	for i := 0; i < len(lines); i++ {
		// Track string/comment state across every line, so a brace inside a comment
		// or a string literal never opens or closes a span.
		code := strip(i, st)
		name, isDecl := declName(l, lines[i], code)
		if !isDecl {
			continue
		}
		headEnd, end, ok := braceBody(lines, i, st, strip)
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
func braceBody(lines []string, i int, st *scanState, strip func(int, *scanState) string) (headEnd, end int, ok bool) {
	depth := 0
	opened := false
	for j := i; j < len(lines); j++ {
		var code string
		if j == i {
			// The declaration's own line was already stripped by the caller, so re-strip
			// it from a fresh state rather than advancing st twice.
			code = strip(j, &scanState{})
		} else {
			code = strip(j, st)
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
// unbalances the span, which braceBody rejects, the safe direction. JS/TS reaches it
// only for a file jsCodeLines could not lex (LEO-378); Go, Java, C# and C/C++ always do.
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
		case c == '#' && l != langGo && l != langJS && l != langJava && l != langCSharp && l != langC:
			return b.String()
		case c == '/' && i+1 < len(runes) && runes[i+1] == '*':
			st.inBlockComment = true
			i++
		case c == '`' && l != langC: // no backtick strings in C or C++
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

// ---- C / C++ ----

// cScanned is what cScan learned about each line of a C or C++ file.
type cScanned struct {
	code []string // the line with comments, strings and preprocessor directives blanked
	top  []bool   // at declaration level: inside no brace but a namespace/class/struct/extern one
	enum []bool   // directly inside an enum body
	ok   bool     // the braces balance, and balance the same way in every #if branch
}

var (
	cContainerRe  = regexp.MustCompile(`\b(?:namespace|class|struct|union|extern)\b`)
	cEnumRe       = regexp.MustCompile(`\benum\b`)
	cNameRe       = regexp.MustCompile(`((?:[A-Za-z_]\w*\s*::\s*)*~?[A-Za-z_]\w*)\s*$`)
	cDeclPrefixRe = regexp.MustCompile(`^[\w\s*&:<>,~\[\]]*$`)
	// cReturnTypeRe is a GNU-style return type written on the line above the name:
	// `static int` over `foo (void)`.
	cReturnTypeRe = regexp.MustCompile(`^[A-Za-z_][\w\s*&:<>,]*$`)
)

// cKeyword names what a "name(" shape catches in C and C++ that is never a function.
var cKeyword = map[string]bool{
	"sizeof": true, "defined": true, "__attribute__": true, "alignof": true, "_Alignof": true,
	"decltype": true, "static_assert": true, "_Static_assert": true, "typedef": true,
	"goto": true, "delete": true, "operator": true, "noexcept": true, "alignas": true,
}

// cScan reads a C or C++ file once for the two things a brace count gets wrong there.
//
// A preprocessor directive is not code: a function-like macro's `\` continuations
// carry braces that belong to no scope, so directives are blanked (and always kept,
// since a line in no span is kept). And `#if`/`#else` branches that each open a brace
// (two signatures for one body) unbalance any count that reads both. Such a file is
// marked not ok, and the slicer sends it whole rather than guess which brace is real.
// An #if with no #else that opens a brace closed by a later #if (the `extern "C" {`
// guard every portable header carries) is balanced overall and stays ok.
func cScan(lines []string) cScanned {
	sc := cScanned{code: make([]string, len(lines)), top: make([]bool, len(lines)), enum: make([]bool, len(lines)), ok: true}
	type open struct{ container, enum bool }
	type cond struct {
		depth   int
		hadElse bool
	}
	var stack []open
	var conds []cond
	st := &scanState{}
	inDirective := false
	prev := ""
	for i, raw := range lines {
		sc.top[i] = true
		for _, o := range stack {
			sc.top[i] = sc.top[i] && o.container
		}
		sc.enum[i] = len(stack) > 0 && stack[len(stack)-1].enum
		trimmed := strings.TrimSpace(raw)
		if inDirective || (!st.inBlockComment && strings.HasPrefix(trimmed, "#")) {
			if !inDirective {
				d := strings.TrimSpace(strings.TrimPrefix(trimmed, "#"))
				switch {
				case strings.HasPrefix(d, "if"):
					conds = append(conds, cond{depth: len(stack)})
				case strings.HasPrefix(d, "el") && len(conds) > 0:
					if len(stack) != conds[len(conds)-1].depth {
						sc.ok = false
					}
					conds[len(conds)-1].hadElse = true
				case strings.HasPrefix(d, "endif") && len(conds) > 0:
					if c := conds[len(conds)-1]; c.hadElse && len(stack) != c.depth {
						sc.ok = false
					}
					conds = conds[:len(conds)-1]
				}
			}
			stripCode(langC, raw, st) // a directive can open a block comment
			inDirective = strings.HasSuffix(strings.TrimRight(raw, " \t"), `\`)
			continue
		}
		code := stripCode(langC, raw, st)
		sc.code[i] = code
		for k, r := range code {
			switch r {
			case '{':
				head := strings.TrimSpace(code[:k])
				if head == "" {
					head = prev // Allman: the brace sits under its declaration
				}
				stack = append(stack, open{
					container: cContainerRe.MatchString(head) && !strings.ContainsAny(head, "=("),
					enum:      cEnumRe.MatchString(head),
				})
			case '}':
				if len(stack) == 0 {
					sc.ok = false
					continue
				}
				stack = stack[:len(stack)-1]
			}
		}
		if t := strings.TrimSpace(code); t != "" {
			prev = t
		}
	}
	if len(stack) != 0 {
		sc.ok = false
	}
	return sc
}

// cSpans finds C and C++ function spans, and prototypes as spans with no body.
//
// A definition is found where the brace slicer's declName would miss it: the name may
// sit on its own line under its return type (GNU style), and the brace on the line
// under the parameters (Allman). C++ methods are found inside a class, a namespace or
// an `extern "C"` block, which are containers rather than spans, and an out-of-line
// `Foo::bar(` is named bar. K&R definitions (parameter declarations between the `)`
// and the `{`) are not recognised, so they are kept.
//
// A prototype is a span whose header is its whole extent. Its signature always
// travels; what it carries is the doc comment above it, which goes when nothing the
// change reaches names it. In a documented header that comment is most of the bytes.
func cSpans(lines []string) []span {
	sc := cScan(lines)
	if !sc.ok {
		return nil
	}
	strip := func(j int, _ *scanState) string { return sc.code[j] }
	var out []span
	for i := 0; i < len(lines); i++ {
		if !sc.top[i] {
			continue
		}
		name, isDecl := cDeclName(sc.code[i])
		if !isDecl {
			continue
		}
		start := i + 1
		if i > 0 && sc.top[i-1] {
			if t := strings.TrimSpace(sc.code[i-1]); cReturnTypeRe.MatchString(t) && !strings.HasSuffix(t, ":") {
				start = i // the return type above belongs to the header
			}
		}
		if end, ok := cPrototypeEnd(sc.code, i); ok {
			out = append(out, span{name: name, docStart: docStart(lines, start, false), start: start, headEnd: end, end: end})
			i = end - 1
			continue
		}
		headEnd, end, ok := braceBody(lines, i, &scanState{}, strip)
		if !ok || !cHeadOK(sc.code[i:headEnd]) {
			continue
		}
		if end > headEnd {
			out = append(out, span{name: name, docStart: docStart(lines, start, false), start: start, headEnd: headEnd, end: end})
		}
		i = end - 1
	}
	return out
}

// cDeclName reports the function a declaration line names: the identifier before its
// first parenthesis, preceded only by what a return type is made of.
func cDeclName(code string) (string, bool) {
	t := strings.TrimSpace(code)
	p := strings.IndexByte(t, '(')
	if p <= 0 {
		return "", false
	}
	pre := t[:p]
	m := cNameRe.FindStringSubmatchIndex(pre)
	if m == nil || !cDeclPrefixRe.MatchString(pre[:m[2]]) {
		return "", false
	}
	for _, w := range identRe.FindAllString(pre, -1) {
		if controlKeyword[w] || cKeyword[w] {
			return "", false
		}
	}
	name := pre[m[2]:m[3]]
	if k := strings.LastIndex(name, "::"); k >= 0 {
		name = name[k+2:]
	}
	name = strings.TrimLeft(strings.TrimSpace(name), "~")
	if cTypeWord[name] {
		return "", false // `int (*fp)(void)`: a function pointer, not a function named int
	}
	return name, true
}

var cTypeWord = map[string]bool{
	"void": true, "char": true, "short": true, "int": true, "long": true, "float": true,
	"double": true, "signed": true, "unsigned": true, "bool": true, "_Bool": true,
	"const": true, "volatile": true, "static": true, "inline": true, "auto": true,
}

// cPrototypeEnd returns the 1-based line on which a declaration starting at the
// 0-based line i ends with `;` before any brace: a prototype. ok=false for anything
// else, a definition included.
func cPrototypeEnd(code []string, i int) (int, bool) {
	depth := 0
	for j := i; j < len(code) && j-i < maxHeaderLines; j++ {
		for _, r := range code[j] {
			switch r {
			case '(':
				depth++
			case ')':
				depth--
			case '{', '}':
				return 0, false
			case ';':
				if depth <= 0 {
					return j + 1, true
				}
			}
		}
	}
	return 0, false
}

// cHeadOK checks the lines from a declaration to its opening brace. The parameter
// list must close, and nothing after it may open another: a line like
// `DECLARE_THING(x)` with no semicolon would otherwise take the NEXT function's body
// as its own, under a name nothing calls, and drop it. A semicolon or a closing brace
// means a statement came between (a K&R parameter list, a prototype). Each rejection
// leaves the lines in no span, so they are kept.
func cHeadOK(head []string) bool {
	depth := 0
	closed := false
	for _, c := range head {
		if strings.ContainsAny(c, ";}") || (closed && strings.Contains(c, "(")) {
			return false
		}
		depth += strings.Count(c, "(") - strings.Count(c, ")")
		if depth <= 0 && strings.Contains(c, ")") {
			closed = true
		}
	}
	return closed
}
