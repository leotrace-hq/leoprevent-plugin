package transcript

import (
	"encoding/json"
	"path"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// Codex records an apply_patch edit in more than one shape, and the transcript fallback
// has to read them all (LEO-394). The plain one is a `custom_tool_call` named
// "apply_patch" whose input IS the patch. The others wrap it:
//
//   - CODE MODE: the model writes JavaScript that calls the tools, and the rollout
//     records the script, e.g. `text(await tools.apply_patch("*** Begin Patch\n..."))`.
//     The patch is a JS string literal, escaped, inside source code.
//   - a `function_call` whose `arguments` is a JSON document holding the patch.
//   - a shell call (`exec_command`, `local_shell_call`) running `apply_patch` with the
//     patch as an argument or a heredoc.
//
// A live Codex session in code mode edited a file this way and the fallback, which
// recognised only the plain shape, reported `no_change`. Codex documents the rollout as
// not a stable interface, so the reader below does not key on a wrapper's tool name: it
// looks for an apply_patch call itself and decodes the string literal holding its patch.
// Only a real call counts: a patch that merely appears in a string, a template literal
// or a comment (an example the script prints) is not an edit (see codexEdits).

const (
	beginPatch = "*** Begin Patch"
	endPatch   = "*** End Patch"
	// maxPatchDepth bounds the literal-in-literal recursion (a JSON string inside a JS
	// string inside a JSON field is three levels).
	maxPatchDepth = 4
)

// codexCallSources returns the text of a Codex tool-call entry that could carry a patch:
// the custom tool input, the function arguments (decoded when they are a JSON string)
// and the shell action. Nil for anything that is not a call.
func (e codexEntry) codexCallSources() []string {
	if e.Type != "response_item" || !strings.HasSuffix(e.Payload.Type, "_call") {
		return nil
	}
	var out []string
	if e.Payload.Input != "" {
		out = append(out, e.Payload.Input)
	}
	if len(e.Payload.Arguments) > 0 {
		var s string
		if json.Unmarshal(e.Payload.Arguments, &s) == nil {
			out = append(out, s)
		} else {
			out = append(out, string(e.Payload.Arguments))
		}
	}
	if len(e.Payload.Action) > 0 {
		out = append(out, string(e.Payload.Action))
	}
	return out
}

// codexPatches returns every apply_patch body one tool-call entry carries, in order.
func (e codexEntry) codexPatches() []string {
	patches, _ := e.codexEdits()
	return patches
}

// isCodexEditCall reports whether e is a tool call that edits files with apply_patch,
// whether or not its patch could be extracted. It is what lets the engine tell "the
// agent changed nothing" from "the agent changed something we could not read".
func (e codexEntry) isCodexEditCall() bool {
	_, edit := e.codexEdits()
	return edit
}

// codexEdits reads one tool-call entry: the patches it applies and whether it applies
// any at all.
//
// ⚠️ AN EDIT IS AN apply_patch CALL, NOT A PATCH-SHAPED STRING. A wrapper call counts
// only where it really invokes apply_patch: in code mode a code-level
// `apply_patch(...)` call (never one inside a string literal, a template literal or a
// comment, which is an example the script prints), in a shell command apply_patch at
// command position, in an argv the apply_patch program. Reading a mentioned patch as an
// edit made the no-baseline fallback review files the agent never touched.
func (e codexEntry) codexEdits() (patches []string, edit bool) {
	for _, src := range e.codexCallSources() {
		if e.Payload.Name == "apply_patch" {
			edit = true
			if !strings.Contains(src, beginPatch) {
				patches = append(patches, src) // the plain shape, read as it always was
				continue
			}
			patches = append(patches, extractPatches(src, 0)...)
			continue
		}
		var w editScan
		w.source(src, 0)
		patches = append(patches, w.patches...)
		edit = edit || w.edit
	}
	return patches, edit
}

// editScan collects the apply_patch calls found in a wrapper call's text.
type editScan struct {
	patches []string
	edit    bool
}

// source reads text that is either JSON (function arguments, a shell action) or code
// (a code-mode script).
func (w *editScan) source(src string, depth int) {
	if depth > maxPatchDepth || !strings.Contains(src, "apply_patch") {
		return
	}
	if t := strings.TrimSpace(src); strings.HasPrefix(t, "{") || strings.HasPrefix(t, "[") {
		var v any
		if json.Unmarshal([]byte(t), &v) == nil {
			w.value(v, false, depth+1)
			return
		}
	}
	w.code(src)
}

// value walks a decoded JSON value. A string under a "cmd" or "command" key is a shell
// command; any other string may be a code-mode script or more JSON.
func (w *editScan) value(v any, shell bool, depth int) {
	if depth > 4*maxPatchDepth {
		return
	}
	switch x := v.(type) {
	case string:
		if shell {
			w.shell(x)
		} else {
			w.source(x, depth)
		}
	case []any:
		for i := 0; i < len(x); i++ {
			if s, ok := x[i].(string); ok && shell && path.Base(s) == "apply_patch" {
				// argv: the apply_patch program, then its patch argument(s).
				w.edit = true
				for i+1 < len(x) {
					p, ok := x[i+1].(string)
					if !ok || !strings.HasPrefix(strings.TrimSpace(p), beginPatch) {
						break
					}
					w.patches = append(w.patches, rawPatches(p)...)
					i++
				}
				continue
			}
			w.value(x[i], shell, depth+1)
		}
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			w.value(x[k], shell || k == "cmd" || k == "command", depth+1)
		}
	}
}

// shell reads a shell command: apply_patch at command position (the start, or after a
// newline, ;, &, |, ( or {) runs it, and its patch is the first one after it, from a
// heredoc or an argument. A command that only searches for or prints the word does not.
func (w *editScan) shell(s string) {
	const word = "apply_patch"
	for off := 0; ; {
		i := strings.Index(s[off:], word)
		if i < 0 {
			return
		}
		i += off
		off = i + len(word)
		if !atCommandPosition(s, i) || (off < len(s) && !strings.ContainsRune(" \t\n<;", rune(s[off]))) {
			continue
		}
		w.edit = true
		if ps := rawPatches(s[off:]); len(ps) > 0 {
			w.patches = append(w.patches, ps[0])
		}
	}
}

func atCommandPosition(s string, i int) bool {
	for i--; i >= 0 && (s[i] == ' ' || s[i] == '\t'); i-- {
	}
	return i < 0 || strings.IndexByte("\n;&|({", s[i]) >= 0
}

// code scans a code-mode (JavaScript) script for code-level apply_patch(...) calls,
// stepping over comments, string literals and template literals as wholes. A call's
// patch is read when its first argument is a string literal holding one; a call with
// any other argument (a variable) is still an edit, just an unreadable one.
func (w *editScan) code(src string) {
	const word = "apply_patch"
	for i := 0; i < len(src); i++ {
		c := src[i]
		switch {
		case strings.HasPrefix(src[i:], "//"):
			nl := strings.IndexByte(src[i:], '\n')
			if nl < 0 {
				return
			}
			i += nl
		case strings.HasPrefix(src[i:], "/*"):
			end := strings.Index(src[i+2:], "*/")
			if end < 0 {
				return
			}
			i += 2 + end + 1
		case c == '"' || c == '\'' || c == '`':
			if lit, end, ok := decodeStringLiteral(src, i); ok {
				if k := keyBefore(src, i); k == "cmd" || k == "command" {
					w.shell(lit) // tools.exec_command({cmd: "apply_patch <<'EOF' ..."})
				}
				i = end
			} // else a stray quote: step past it alone
		case strings.HasPrefix(src[i:], word) && (i == 0 || !isIdentByte(src[i-1])):
			k := i + len(word)
			if k < len(src) && isIdentByte(src[k]) {
				i = k - 1 // apply_patches, apply_patch2: another name
				continue
			}
			j := skipSpace(src, k)
			if j >= len(src) || src[j] != '(' {
				i = k - 1 // a reference, not a call
				continue
			}
			w.edit = true
			j = skipSpace(src, j+1)
			i = j - 1
			if j < len(src) && (src[j] == '"' || src[j] == '\'' || src[j] == '`') {
				if lit, end, ok := decodeStringLiteral(src, j); ok {
					if strings.HasPrefix(strings.TrimSpace(lit), beginPatch) {
						w.patches = append(w.patches, rawPatches(lit)...)
					}
					i = end
				}
			}
		}
	}
}

// keyBefore returns the object key a literal at src[i] is the value of (`cmd: "..."`),
// or "" when it is not one.
func keyBefore(src string, i int) string {
	j := i - 1
	for j >= 0 && strings.IndexByte(" \t\r\n", src[j]) >= 0 {
		j--
	}
	if j < 0 || src[j] != ':' {
		return ""
	}
	for j--; j >= 0 && strings.IndexByte(" \t\r\n", src[j]) >= 0; j-- {
	}
	end := j + 1
	for j >= 0 && isIdentByte(src[j]) {
		j--
	}
	return src[j+1 : end]
}

func isIdentByte(c byte) bool {
	return c == '_' || c == '$' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c >= 0x80
}

func skipSpace(s string, i int) int {
	for i < len(s) && strings.IndexByte(" \t\r\n", s[i]) >= 0 {
		i++
	}
	return i
}

// extractPatches finds the apply_patch bodies in s. s is either a patch itself, or text
// (source code, JSON, a shell command) holding one inside a string literal, possibly
// several levels deep, or holding one verbatim (a heredoc).
func extractPatches(s string, depth int) []string {
	if depth > maxPatchDepth || !strings.Contains(s, beginPatch) {
		return nil
	}
	if strings.HasPrefix(strings.TrimSpace(s), beginPatch) {
		return rawPatches(s)
	}
	var out []string
	for i := 0; i < len(s); i++ {
		q := s[i]
		if q != '"' && q != '\'' && q != '`' {
			continue
		}
		lit, end, ok := decodeStringLiteral(s, i)
		if !ok {
			continue // a stray quote (an apostrophe in a comment): move past it
		}
		if strings.Contains(lit, beginPatch) {
			out = append(out, extractPatches(lit, depth+1)...)
		}
		i = end
	}
	if len(out) == 0 {
		// No literal held it: the patch sits in s verbatim (a heredoc, a template
		// literal body, a wrapper we have not seen).
		out = rawPatches(s)
	}
	return out
}

// rawPatches cuts each "*** Begin Patch" ... "*** End Patch" span out of s. A patch with
// no end marker runs to the end of s.
func rawPatches(s string) []string {
	var out []string
	for {
		i := strings.Index(s, beginPatch)
		if i < 0 {
			return out
		}
		s = s[i:]
		j := strings.Index(s, endPatch)
		if j < 0 {
			return append(out, s)
		}
		out = append(out, s[:j+len(endPatch)])
		s = s[j+len(endPatch):]
	}
}

// decodeStringLiteral decodes the JavaScript (or JSON, a subset) string literal whose
// opening quote is s[start], returning its value and the index of its closing quote.
// ok is false when the quote opens no valid literal: a single- or double-quoted string
// cannot contain a raw newline, so an apostrophe in prose or a comment ends at the line
// instead of swallowing the rest of the source. A template literal's ${...} is kept as
// text.
func decodeStringLiteral(s string, start int) (string, int, bool) {
	q := s[start]
	var b strings.Builder
	for i := start + 1; i < len(s); {
		c := s[i]
		switch {
		case c == q:
			return b.String(), i, true
		case c == '\n' && q != '`':
			return "", 0, false
		case c != '\\':
			b.WriteByte(c)
			i++
			continue
		}
		// An escape.
		if i+1 >= len(s) {
			return "", 0, false
		}
		e := s[i+1]
		i += 2
		switch e {
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		case 'b':
			b.WriteByte('\b')
		case 'f':
			b.WriteByte('\f')
		case 'v':
			b.WriteByte('\v')
		case '0':
			b.WriteRune(0)
		case '\n':
			// A line continuation: the backslash and the newline both vanish.
		case '\r':
			if i < len(s) && s[i] == '\n' {
				i++
			}
		case 'x':
			if i+2 <= len(s) {
				if v, err := strconv.ParseUint(s[i:i+2], 16, 8); err == nil {
					b.WriteRune(rune(v))
					i += 2
					continue
				}
			}
			b.WriteByte('x')
		case 'u':
			r, n := decodeUnicodeEscape(s[i:])
			if n == 0 {
				b.WriteByte('u')
				continue
			}
			i += n
			// A UTF-16 surrogate pair arrives as two \u escapes.
			if utf16.IsSurrogate(r) && strings.HasPrefix(s[i:], `\u`) {
				if r2, n2 := decodeUnicodeEscape(s[i+2:]); n2 > 0 {
					if p := utf16.DecodeRune(r, r2); p != utf8.RuneError {
						r = p
						i += 2 + n2
					}
				}
			}
			b.WriteRune(r)
		default:
			// \\, \", \', \`, \/ and any unknown escape stand for the character itself.
			b.WriteByte(e)
		}
	}
	return "", 0, false
}

// decodeUnicodeEscape reads the part of a \u escape after the "u": four hex digits, or
// {1-6 hex digits}. n is how many bytes it used, 0 when it is malformed.
func decodeUnicodeEscape(s string) (rune, int) {
	if strings.HasPrefix(s, "{") {
		end := strings.IndexByte(s, '}')
		if end < 2 || end > 7 {
			return 0, 0
		}
		v, err := strconv.ParseUint(s[1:end], 16, 32)
		if err != nil || v > utf8.MaxRune {
			return 0, 0
		}
		return rune(v), end + 1
	}
	if len(s) < 4 {
		return 0, 0
	}
	v, err := strconv.ParseUint(s[:4], 16, 16)
	if err != nil {
		return 0, 0
	}
	return rune(v), 4
}
