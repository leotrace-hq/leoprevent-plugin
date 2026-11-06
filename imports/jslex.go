package imports

import (
	"fmt"
	"path"
	"sort"
	"strings"
)

// A JavaScript/TypeScript tokenizer, to the depth the import extractor (jsparse.go) and
// the slicer's brace scanner (slice_lang.go) need and no further (LEO-378).
//
// Regexes over raw source cannot tell code from a comment, a string or a template
// literal, so a commented-out `// import { x } from './y'` resolved (egress for a file
// the program never loads), a comment inside a clause broke the import, and a regex
// literal holding a brace unbalanced the slicer's spans. A lexer settles all of those at
// once. It knows identifiers, punctuators, strings, template literals (with nested
// `${...}` handled by recursion), regex literals (decided from the previous significant
// token), numbers and comments, and it skips JSX elements in files that can hold them.
// It does not parse: jsparse.go reads a handful of statement shapes off the tokens.
//
// It fails loudly rather than guessing. An unterminated string, comment or template, a
// bracket that never closes or closes the wrong opener, or a malformed JSX element is an
// error, and every caller then falls back to the regex path it replaced, for that file
// only. Fail-open in the direction of resolving more, never less.
//
// Rejected alternatives (LEO-378): esbuild and typescript-go (a large dependency in the
// byte-reproducible plugin build for a few statement shapes), tree-sitter (cgo), goja
// (an interpreter, not a parser API). Stdlib only.

type jsTokKind uint8

const (
	jsIdent    jsTokKind = iota // identifiers and keywords, `#private` names
	jsPunct                     // operators and brackets
	jsString                    // '...' or "...": text is the raw body without quotes
	jsTemplate                  // one literal chunk of a template literal
	jsRegex                     // a regex literal
	jsNumber                    // a numeric literal
	jsJSX                       // marks the end of a whole JSX element (an expression)
)

type jsTok struct {
	kind jsTokKind
	text string
}

// jsLexError is the one error the lexer returns; the message is for the differential
// harness and debugging only, since every caller treats any error the same way.
type jsLexError struct {
	pos int
	msg string
}

func (e *jsLexError) Error() string { return fmt.Sprintf("js lex at byte %d: %s", e.pos, e.msg) }

// maxJSNesting bounds the lexer's recursion (template substitutions inside JSX inside
// template substitutions...). Real code never comes close; a pathological file falls
// back instead of growing the stack.
const maxJSNesting = 200

type jsLexer struct {
	src   string
	pos   int
	jsx   bool
	toks  []jsTok
	strip [][2]int // byte ranges that are not code: comments, string and template bodies, regexes, JSX text
	depth int
}

// jsxAllowed says whether a file may contain JSX. In a `.ts`/`.mts`/`.cts` file `<Foo>x`
// is a type assertion, so JSX detection is off there; every other JS/TS extension can
// hold JSX (`.js` in a React codebase routinely does).
func jsxAllowed(relpath string) bool {
	switch path.Ext(relpath) {
	case ".ts", ".mts", ".cts":
		return false
	}
	return true
}

// jsLex tokenizes a whole file.
func jsLex(src string, jsx bool) (*jsLexer, error) {
	l := &jsLexer{src: src, jsx: jsx}
	if strings.HasPrefix(l.src[l.pos:], "\uFEFF") {
		l.pos += len("\uFEFF")
	}
	if strings.HasPrefix(l.src[l.pos:], "#!") {
		start := l.pos
		for l.pos < len(l.src) && l.src[l.pos] != '\n' {
			l.pos++
		}
		l.strip = append(l.strip, [2]int{start, l.pos})
	}
	if err := l.run(false); err != nil {
		return nil, err
	}
	return l, nil
}

func (l *jsLexer) fail(msg string) error { return &jsLexError{pos: l.pos, msg: msg} }

func (l *jsLexer) emit(kind jsTokKind, text string) { l.toks = append(l.toks, jsTok{kind, text}) }

// run lexes code until end of input or, when nested, until the `}` that closes the
// substitution or JSX expression it was called for (which it consumes). Bracket
// balance is checked per level: that is the lexer's desync detector.
func (l *jsLexer) run(nested bool) error {
	l.depth++
	defer func() { l.depth-- }()
	if l.depth > maxJSNesting {
		return l.fail("nesting too deep")
	}
	var open []byte
	for {
		if err := l.skipSpace(); err != nil {
			return err
		}
		if l.pos >= len(l.src) {
			if nested || len(open) > 0 {
				return l.fail("unexpected end of input")
			}
			return nil
		}
		c := l.src[l.pos]
		switch {
		case c == '"' || c == '\'':
			if err := l.lexString(c); err != nil {
				return err
			}
		case c == '`':
			if err := l.lexTemplate(); err != nil {
				return err
			}
		case isJSIdentStart(c) || (c == '#' && l.pos+1 < len(l.src) && isJSIdentStart(l.src[l.pos+1])):
			start := l.pos
			l.pos++
			for l.pos < len(l.src) && isJSIdentPart(l.src[l.pos]) {
				l.pos++
			}
			l.emit(jsIdent, l.src[start:l.pos])
		case isDigit(c) || (c == '.' && l.pos+1 < len(l.src) && isDigit(l.src[l.pos+1])):
			l.lexNumber()
		case c == '/' && l.exprAllowed():
			if !l.lexRegex() {
				l.pos++
				l.emit(jsPunct, "/")
			}
		case c == '<' && l.jsx && l.exprAllowed() && l.jsxStart():
			if err := l.lexJSXElement(); err != nil {
				return err
			}
			l.emit(jsJSX, "")
		case c == '{' || c == '(' || c == '[':
			open = append(open, c)
			l.pos++
			l.emit(jsPunct, string(c))
		case c == '}' || c == ')' || c == ']':
			if len(open) == 0 {
				if nested && c == '}' {
					l.pos++
					l.emit(jsPunct, "}")
					return nil
				}
				return l.fail("unbalanced " + string(c))
			}
			if want := closerOf(open[len(open)-1]); want != c {
				return l.fail("mismatched " + string(c))
			}
			open = open[:len(open)-1]
			l.pos++
			l.emit(jsPunct, string(c))
		default:
			l.lexPunct()
		}
	}
}

// lexPunct reads one punctuator. Only the multi-character ones something downstream
// reads are joined: `...` (destructuring), `=>` and `?.` (so `?.import` is a member),
// `++`/`--` (a postfix one ends a value, so a following `/` divides), and `<<` (whose
// second `<` would otherwise be read in expression position as a JSX tag).
func (l *jsLexer) lexPunct() {
	for _, p := range []string{"...", "=>", "?.", "++", "--", "<<"} {
		if strings.HasPrefix(l.src[l.pos:], p) {
			l.pos += len(p)
			l.emit(jsPunct, p)
			return
		}
	}
	l.emit(jsPunct, l.src[l.pos:l.pos+1])
	l.pos++
}

func closerOf(c byte) byte {
	switch c {
	case '{':
		return '}'
	case '(':
		return ')'
	}
	return ']'
}

// skipSpace skips whitespace and comments, recording each comment as non-code.
func (l *jsLexer) skipSpace() error {
	for l.pos < len(l.src) {
		c := l.src[l.pos]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f':
			l.pos++
		case strings.HasPrefix(l.src[l.pos:], "\u00a0"), strings.HasPrefix(l.src[l.pos:], "\uFEFF"),
			strings.HasPrefix(l.src[l.pos:], "\u2028"), strings.HasPrefix(l.src[l.pos:], "\u2029"):
			_, size := decodeRuneAt(l.src, l.pos)
			l.pos += size
		case strings.HasPrefix(l.src[l.pos:], "//"):
			start := l.pos
			for l.pos < len(l.src) && l.src[l.pos] != '\n' && l.src[l.pos] != '\r' {
				l.pos++
			}
			l.strip = append(l.strip, [2]int{start, l.pos})
		case strings.HasPrefix(l.src[l.pos:], "/*"):
			end := strings.Index(l.src[l.pos+2:], "*/")
			if end < 0 {
				return l.fail("unterminated block comment")
			}
			l.strip = append(l.strip, [2]int{l.pos, l.pos + 2 + end + 2})
			l.pos += 2 + end + 2
		default:
			return nil
		}
	}
	return nil
}

func decodeRuneAt(s string, i int) (rune, int) {
	for _, r := range s[i:] {
		return r, len(string(r))
	}
	return 0, 1
}

// lexString reads a single- or double-quoted string. A raw newline ends it with an
// error: JS strings cannot span lines except by an escaped line break.
func (l *jsLexer) lexString(q byte) error {
	start := l.pos
	l.pos++
	for {
		if l.pos >= len(l.src) {
			return l.fail("unterminated string")
		}
		switch c := l.src[l.pos]; c {
		case '\\':
			l.pos += 2
			if l.pos < len(l.src) && l.src[l.pos-1] == '\r' && l.src[l.pos] == '\n' {
				l.pos++
			}
		case '\n', '\r':
			return l.fail("unterminated string")
		case q:
			l.pos++
			l.strip = append(l.strip, [2]int{start, l.pos})
			l.emit(jsString, l.src[start+1:l.pos-1])
			return nil
		default:
			l.pos++
		}
	}
}

// lexTemplate reads a template literal. Each `${...}` substitution is lexed as code by
// a nested run, which is what keeps a `}` inside a substitution's object literal from
// ending it early and lets an import() inside one be seen. For the slicer the whole
// literal, substitutions included, is non-code, as it was under stripCode: a
// substitution's code is an expression, never a declaration, and reading
// `${url.replace(...)}` as code turned `const url = ` into an arrow-function header.
func (l *jsLexer) lexTemplate() error {
	start := l.pos
	chunk := l.pos
	l.pos++
	for {
		if l.pos >= len(l.src) {
			return l.fail("unterminated template literal")
		}
		switch c := l.src[l.pos]; {
		case c == '\\':
			l.pos += 2
		case c == '`':
			l.pos++
			l.strip = append(l.strip, [2]int{start, l.pos})
			l.emit(jsTemplate, l.src[chunk:l.pos])
			return nil
		case c == '$' && l.pos+1 < len(l.src) && l.src[l.pos+1] == '{':
			l.pos += 2
			l.emit(jsTemplate, l.src[chunk:l.pos])
			l.emit(jsPunct, "${")
			if err := l.run(true); err != nil {
				return err
			}
			chunk = l.pos - 1 // the closing `}` belongs to the template, not to code
		default:
			l.pos++
		}
	}
}

func (l *jsLexer) lexNumber() {
	start := l.pos
	hex := strings.HasPrefix(l.src[l.pos:], "0x") || strings.HasPrefix(l.src[l.pos:], "0X")
	for l.pos < len(l.src) {
		c := l.src[l.pos]
		if isJSIdentPart(c) || c == '.' {
			l.pos++
			continue
		}
		if (c == '+' || c == '-') && !hex && (l.src[l.pos-1] == 'e' || l.src[l.pos-1] == 'E') {
			l.pos++
			continue
		}
		break
	}
	l.emit(jsNumber, l.src[start:l.pos])
}

// lexRegex reads a regex literal where one may start. A regex cannot span lines, so
// reaching a line end means the guess was wrong and the `/` was a division after all:
// it reports false and consumes nothing.
func (l *jsLexer) lexRegex() bool {
	start := l.pos
	i := l.pos + 1
	inClass := false
	for i < len(l.src) {
		switch c := l.src[i]; {
		case c == '\n' || c == '\r':
			return false
		case c == '\\':
			i += 2
			continue
		case c == '[':
			inClass = true
		case c == ']':
			inClass = false
		case c == '/' && !inClass:
			i++
			for i < len(l.src) && isJSIdentPart(l.src[i]) {
				i++
			}
			l.pos = i
			l.strip = append(l.strip, [2]int{start, l.pos})
			l.emit(jsRegex, l.src[start:l.pos])
			return true
		}
		i++
	}
	return false
}

// jsExprKeywords are the keywords after which an expression (so a regex or a JSX
// element) can begin. After any other identifier the next `/` divides.
var jsExprKeywords = map[string]bool{
	"return": true, "typeof": true, "instanceof": true, "in": true, "of": true, "new": true,
	"delete": true, "void": true, "throw": true, "case": true, "do": true, "else": true,
	"yield": true, "await": true, "default": true,
}

// exprAllowed decides regex-versus-division (and JSX-versus-less-than) the standard
// way, from the previous significant token. After a value (an identifier that is not a
// keyword, a literal, `)` or `]`, a postfix `++`/`--`, a JSX element) the next operator
// is binary; anywhere else an expression starts. `}` counts as a statement end.
func (l *jsLexer) exprAllowed() bool {
	if len(l.toks) == 0 {
		return true
	}
	t := l.toks[len(l.toks)-1]
	switch t.kind {
	case jsIdent:
		return jsExprKeywords[t.text]
	case jsPunct:
		switch t.text {
		case ")", "]", "++", "--":
			return false
		}
		return true
	}
	return false
}

// jsxStart reports whether the `<` at pos opens a JSX element: a fragment `<>` or a tag
// name. In a `.tsx` file `<T,>(...)` and `<T extends U>(...)` are generic arrow
// functions, not elements, and are left to the ordinary punctuator path.
func (l *jsLexer) jsxStart() bool {
	i := l.pos + 1
	if i >= len(l.src) {
		return false
	}
	if l.src[i] == '>' {
		return true
	}
	if !isJSIdentStart(l.src[i]) {
		return false
	}
	for i < len(l.src) && isJSIdentPart(l.src[i]) {
		i++
	}
	for i < len(l.src) && (l.src[i] == ' ' || l.src[i] == '\t') {
		i++
	}
	if i < len(l.src) && l.src[i] == ',' {
		return false
	}
	return !strings.HasPrefix(l.src[i:], "extends ")
}

// lexJSXElement skips one JSX element, opening tag through closing tag. Text children
// and quoted attribute values are non-code; `{...}` children and attribute values are
// lexed as code by a nested run, and nested elements recurse.
func (l *jsLexer) lexJSXElement() error {
	l.depth++
	defer func() { l.depth-- }()
	if l.depth > maxJSNesting {
		return l.fail("nesting too deep")
	}
	l.pos++ // '<'
	l.jsxName()
	for {
		if err := l.skipSpace(); err != nil {
			return err
		}
		if l.pos >= len(l.src) {
			return l.fail("unterminated JSX tag")
		}
		c := l.src[l.pos]
		switch {
		case strings.HasPrefix(l.src[l.pos:], "/>"):
			l.pos += 2
			return nil
		case c == '>':
			l.pos++
			return l.jsxChildren()
		case c == '{':
			if err := l.jsxExpression(); err != nil {
				return err
			}
		case isJSIdentStart(c):
			l.jsxName()
			if err := l.skipSpace(); err != nil {
				return err
			}
			if l.pos < len(l.src) && l.src[l.pos] == '=' {
				l.pos++
				if err := l.skipSpace(); err != nil {
					return err
				}
				if err := l.jsxAttrValue(); err != nil {
					return err
				}
			}
		default:
			return l.fail("unexpected character in JSX tag")
		}
	}
}

func (l *jsLexer) jsxName() {
	for l.pos < len(l.src) {
		c := l.src[l.pos]
		if isJSIdentPart(c) || c == '.' || c == ':' || c == '-' {
			l.pos++
			continue
		}
		return
	}
}

func (l *jsLexer) jsxAttrValue() error {
	if l.pos >= len(l.src) {
		return l.fail("unterminated JSX attribute")
	}
	switch c := l.src[l.pos]; c {
	case '"', '\'':
		// A JSX attribute string has no escapes and may span lines.
		end := strings.IndexByte(l.src[l.pos+1:], c)
		if end < 0 {
			return l.fail("unterminated JSX attribute string")
		}
		l.strip = append(l.strip, [2]int{l.pos, l.pos + 1 + end + 1})
		l.pos += 1 + end + 1
		return nil
	case '{':
		return l.jsxExpression()
	case '<':
		if err := l.lexJSXElement(); err != nil {
			return err
		}
		return nil
	}
	return l.fail("unexpected JSX attribute value")
}

// jsxExpression lexes `{...}` inside JSX as code. The `{` is emitted first so the
// expression's first token is read in expression position.
func (l *jsLexer) jsxExpression() error {
	l.pos++
	l.emit(jsPunct, "{")
	return l.run(true)
}

func (l *jsLexer) jsxChildren() error {
	for {
		start := l.pos
		for l.pos < len(l.src) && l.src[l.pos] != '<' && l.src[l.pos] != '{' {
			l.pos++
		}
		if l.pos > start {
			l.strip = append(l.strip, [2]int{start, l.pos})
		}
		if l.pos >= len(l.src) {
			return l.fail("unterminated JSX element")
		}
		if l.src[l.pos] == '{' {
			if err := l.jsxExpression(); err != nil {
				return err
			}
			continue
		}
		if strings.HasPrefix(l.src[l.pos:], "</") {
			end := strings.IndexByte(l.src[l.pos:], '>')
			if end < 0 {
				return l.fail("unterminated JSX closing tag")
			}
			l.pos += end + 1
			return nil
		}
		if err := l.lexJSXElement(); err != nil {
			return err
		}
	}
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// Any non-ASCII byte is read as part of an identifier: JS identifiers may be Unicode,
// and the whitespace exceptions are taken out in skipSpace first.
func isJSIdentStart(c byte) bool {
	return c == '_' || c == '$' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c >= 0x80
}

func isJSIdentPart(c byte) bool { return isJSIdentStart(c) || isDigit(c) }

// jsCodeLines returns src split into lines with every non-code range (comments, string
// and template bodies, regex literals, JSX text) removed, line breaks inside a removed
// range kept so line N stays line N. It replaces stripCode for JS/TS (slice_lang.go),
// which, scanning one line at a time with no notion of a regex literal, counted the
// brace in `/[{]/` and lost the span. nil when the file does not lex: the caller
// falls back to stripCode.
func jsCodeLines(src string, jsx bool) []string {
	l, err := jsLex(src, jsx)
	if err != nil {
		return nil
	}
	var b strings.Builder
	b.Grow(len(src))
	// A template literal's range is recorded when it closes, after the ranges inside
	// its substitutions, so order by start; a range inside one already removed is
	// skipped. Ranges never partially overlap.
	sort.SliceStable(l.strip, func(a, b int) bool { return l.strip[a][0] < l.strip[b][0] })
	at := 0
	for _, r := range l.strip {
		if r[0] < at {
			continue
		}
		b.WriteString(src[at:r[0]])
		for i := r[0]; i < r[1]; i++ {
			if src[i] == '\n' {
				b.WriteByte('\n')
			}
		}
		at = r[1]
	}
	b.WriteString(src[at:])
	return strings.Split(b.String(), "\n")
}
