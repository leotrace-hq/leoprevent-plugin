package sweep

import (
	"fmt"
	"math"
	"regexp"
	"strings"
	"unicode"

	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

const maskContext = 2

var (
	referencePattern = regexp.MustCompile(`^(\$\{[A-Za-z_][A-Za-z0-9_]*\}|\$[A-Za-z_][A-Za-z0-9_]*|\{\{\s*[A-Za-z_][A-Za-z0-9_.]*\s*\}\})$`)
	keyPattern       = regexp.MustCompile(`^[A-Za-z_][A-Za-z_.-]{0,63}$`)
	pathPattern      = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]*(\.[A-Za-z_$][A-Za-z0-9_$]*)+$`)
	conditionPattern = regexp.MustCompile(`(==|!=|<|>|\b(case|if|elif|else|when|while|and|or|not|in|is|return)\b)`)
	referenceRoots   = map[string]bool{"process": true, "os": true, "env": true, "ENV": true, "config": true, "settings": true, "self": true, "this": true, "System": true, "Deno": true, "import": true, "secrets": true, "vars": true}
	tokenPattern     = regexp.MustCompile(`[A-Za-z0-9_+/=.~-]+`)
	placeholderWords = []string{"example", "placeholder", "changeme", "change_me", "change-me", "dummy", "fake", "sample", "your_", "your-", "xxx", "***", "redacted", "todo", "test", "<", ">"}
	commentWords     = []string{"example", "placeholder", "dummy", "fake", "sample", "test"}
)

func Excerpt(content string,
	spans []wire.SweepSpan) (string, int) {
	lines := strings.Split(content, "\n")
	keep := map[int]bool{}
	flagged := map[int]bool{}
	first, last := 0, 0
	for _, sp := range spans {
		for n := sp.Start; n <= max(sp.Start, sp.End); n++ {
			flagged[n] = true
		}
		for n := sp.Start - maskContext; n <= max(sp.Start, sp.End)+maskContext; n++ {
			if n < 1 || n > len(lines) {
				continue
			}
			keep[n] = true
			if first == 0 || n < first {
				first = n
			}
			last = max(last, n)
		}
	}
	if first == 0 {
		return "", 0
	}
	out := make([]string, 0, last-first+1)
	for n := first; n <= last; n++ {
		if keep[n] {
			out = append(out, maskLine(lines[n-1], flagged[n]))
		} else {
			out = append(out, "")
		}
	}
	excerpt := strings.Join(out, "\n")
	if strings.TrimSpace(excerpt) == "" {
		return "", 0
	}
	return excerpt, first
}

func maskLine(line string,
	strict bool) string {
	line = strings.TrimSuffix(line, "\r")
	var b, code strings.Builder
	flush := func() {
		b.WriteString(maskCode(code.String(), strict))
		code.Reset()
	}
	for i := 0; i < len(line); {
		c := line[i]
		if n := commentStart(line, i); n > 0 {
			flush()
			b.WriteString(line[i:i+n] + " " + describeComment(line[i+n:]))
			return b.String()
		}
		if c != '"' && c != '\'' && c != '`' {
			code.WriteByte(c)
			i++
			continue
		}
		flush()
		end := closingQuote(line, i)
		if end < 0 {
			b.WriteByte(c)
			b.WriteString(maskValue(line[i+1:]))
			return b.String()
		}
		value := line[i+1 : end]
		b.WriteByte(c)
		if isKey(line[:i], value, line[end+1:]) {
			b.WriteString(value)
		} else {
			b.WriteString(maskValue(value))
		}
		b.WriteByte(c)
		i = end + 1
	}
	flush()
	return b.String()
}

func closingQuote(line string,
	open int) int {
	q := line[open]
	for j := open + 1; j < len(line); j++ {
		switch line[j] {
		case '\\':
			j++
		case q:
			return j
		}
	}
	return -1
}

func commentStart(line string,
	i int) int {
	rest := line[i:]
	atBoundary := i == 0 || line[i-1] == ' ' || line[i-1] == '\t'
	switch {
	case strings.HasPrefix(rest, "<!--"):
		return 4
	case strings.HasPrefix(rest, "//"), strings.HasPrefix(rest, "/*"):
		return 2
	case strings.HasPrefix(rest, "#") && atBoundary:
		return 1
	case strings.HasPrefix(rest, "-- ") && atBoundary:
		return 2
	}
	return 0
}

func isKey(before string,
	value string,
	after string) bool {
	next := strings.TrimLeft(after, " \t")
	if next == "" || (next[0] != ':' && next[0] != '=') || strings.HasPrefix(next, "==") {
		return false
	}
	if strings.TrimSpace(strings.TrimLeft(next[1:], "=")) == "" {
		return false
	}
	if i := strings.LastIndexAny(before, ",{"); i >= 0 {
		before = before[i+1:]
	}
	return !conditionPattern.MatchString(before) && keyPattern.MatchString(value)
}

func referencePath(v string) bool {
	if !pathPattern.MatchString(v) {
		return false
	}
	return referenceRoots[strings.SplitN(v, ".", 2)[0]]
}

func maskCode(seg string,
	strict bool) string {
	at := assignment(seg)
	if at < 0 {
		return maskTokens(seg, strict)
	}
	head, rest := seg[:at], seg[at:]
	value := strings.TrimSpace(rest)
	value = strings.TrimRight(value, ",;")
	value = strings.TrimSpace(value)
	switch {
	case referencePattern.MatchString(value):
		return maskTokens(head, strict) + rest
	case strings.Trim(value, "{[(") == "", strings.Contains(value, "("), referencePath(value):
		return maskTokens(head, strict) + maskTokens(rest, strict)
	}
	lead := rest[:len(rest)-len(strings.TrimLeft(rest, " \t"))]
	tail := strings.TrimRight(rest, " \t")
	trailing := tail[len(strings.TrimRight(tail, ",;")):]
	return maskTokens(head, strict) + lead + maskValue(value) + trailing
}

func assignment(seg string) int {
	for i := 0; i < len(seg); i++ {
		switch seg[i] {
		case '=':
			if i+1 < len(seg) && (seg[i+1] == '=' || seg[i+1] == '>' || seg[i+1] == '~') {
				i++
				continue
			}
			if i > 0 && strings.ContainsRune("=!<>", rune(seg[i-1])) {
				continue
			}
			return i + 1
		case ':':
			if i+1 < len(seg) && seg[i+1] == ':' {
				i++
				continue
			}
			if i+1 < len(seg) && seg[i+1] == '=' {
				return i + 2
			}
			if i+1 == len(seg) || seg[i+1] == ' ' || seg[i+1] == '\t' {
				return i + 1
			}
		}
	}
	return -1
}

func maskTokens(s string,
	strict bool) string {
	var b strings.Builder
	prev := 0
	for _, loc := range tokenPattern.FindAllStringIndex(s, -1) {
		tok := s[loc[0]:loc[1]]
		b.WriteString(s[prev:loc[0]])
		if secretLike(tok, s[loc[1]:], strict) {
			b.WriteString(maskValue(tok))
		} else {
			b.WriteString(tok)
		}
		prev = loc[1]
	}
	b.WriteString(s[prev:])
	return b.String()
}

func secretLike(tok string,
	after string,
	strict bool) bool {
	if len(tok) >= 32 || (len(tok) >= 16 && strings.ContainsAny(tok, "0123456789")) {
		return true
	}
	if !strict || len(tok) < 6 || referencePath(tok) {
		return false
	}
	next := strings.TrimLeft(after, " \t")
	return next == "" || !strings.ContainsRune("(:=", rune(next[0]))
}

func maskValue(v string) string {
	if v == "" || referencePattern.MatchString(v) {
		return v
	}
	return "[masked: " + describe(v) + "]"
}

func describe(v string) string {
	var classes []string
	var upper, lower, digit, other bool
	for _, r := range v {
		switch {
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsLower(r):
			lower = true
		case unicode.IsDigit(r):
			digit = true
		default:
			other = true
		}
	}
	for _, c := range []struct {
		on   bool
		name string
	}{{upper, "upper"}, {lower, "lower"}, {digit, "digits"}, {other, "symbols"}} {
		if c.on {
			classes = append(classes, c.name)
		}
	}
	out := fmt.Sprintf("%d chars, %s, %.1f bits/char", len([]rune(v)), strings.Join(classes, "+"), entropy(v))
	if placeholder(v) {
		out += ", looks like a placeholder"
	}
	return out
}

func entropy(v string) float64 {
	counts := map[rune]int{}
	n := 0
	for _, r := range v {
		counts[r]++
		n++
	}
	h := 0.0
	for _, c := range counts {
		p := float64(c) / float64(n)
		h -= p * math.Log2(p)
	}
	return h
}

func placeholder(v string) bool {
	low := strings.ToLower(v)
	for _, w := range placeholderWords {
		if strings.Contains(low, w) {
			return true
		}
	}
	return len(v) >= 3 && strings.Count(v, v[:1]) == len(v)
}

func describeComment(text string) string {
	low := strings.ToLower(text)
	out := fmt.Sprintf("[comment masked: %d chars", len([]rune(strings.TrimSpace(text))))
	for _, w := range commentWords {
		if strings.Contains(low, w) {
			out += ", mentions " + w
			break
		}
	}
	return out + "]"
}
