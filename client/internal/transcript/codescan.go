package transcript

import (
	"encoding/json"
	"html"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	maxScanNodes   = 4096
	maxScanChanges = 64
	maxScanDepth   = 12
)

var (
	scanHTMLTag = regexp.MustCompile(`<[A-Za-z!/][^<>]*>`)
	scanCSSRule = regexp.MustCompile(`[^{};]+\{[^{}]*:[^{}]*\}`)
	scanJS      = regexp.MustCompile(`\beval\s*\(|\bnew\s+Function\b|\bfunction\s*[A-Za-z_$]*\s*\(|=>|\bdocument\.|\bwindow\.|\blocation\.|\binnerHTML\b|\baddEventListener\s*\(|\bfetch\s*\(|\bsetTimeout\s*\(|\bXMLHttpRequest\b|\bpostMessage\s*\(`)
	scanURLCode = regexp.MustCompile(`(?i)^\s*(javascript|vbscript|data:text/html)`)
)

var scanCodeKeys = map[string]string{
	"source_code":   ".js",
	"sourcecode":    ".js",
	"script":        ".js",
	"javascript":    ".js",
	"js":            ".js",
	"code":          "",
	"content":       "",
	"custom_code":   "",
	"embed":         ".html",
	"embed_code":    ".html",
	"html":          ".html",
	"markup":        ".html",
	"css":           ".css",
	"style_content": ".css",
}

type codeScanner struct {
	out     []Change
	prefix  string
	nodes   int
	emitted int
}

func appendCodeScan(
	out []Change,
	prefix string,
	input json.RawMessage,
) []Change {
	s := &codeScanner{out: out, prefix: prefix}
	s.walk(input, nil, 0)
	return s.out
}

func (s *codeScanner) walk(
	raw json.RawMessage,
	at []string,
	depth int,
) {
	if s.nodes >= maxScanNodes || depth > maxScanDepth {
		return
	}
	s.nodes++
	trimmed := strings.TrimSpace(string(raw))
	switch {
	case strings.HasPrefix(trimmed, "{"):
		var object map[string]json.RawMessage
		if json.Unmarshal(raw, &object) != nil {
			return
		}
		keys := make([]string, 0, len(object))
		for k := range object {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			s.walk(object[k], append(at[:len(at):len(at)], k), depth+1)
		}
	case strings.HasPrefix(trimmed, "["):
		var items []json.RawMessage
		if json.Unmarshal(raw, &items) != nil {
			return
		}
		if len(at) > 0 && strings.Contains(strings.ToLower(at[len(at)-1]), "attribute") {
			if markup := attributeMarkup(items); markup != "" {
				s.emit(at, markup, ".html")
				return
			}
		}
		for i, item := range items {
			s.walk(item, append(at[:len(at):len(at)], strconv.Itoa(i)), depth+1)
		}
	case strings.HasPrefix(trimmed, `"`):
		var value string
		if json.Unmarshal(raw, &value) != nil || strings.TrimSpace(value) == "" || len(at) == 0 {
			return
		}
		if ext, ok := classifyCode(at[len(at)-1], value); ok {
			if ext == ".url" {
				s.emit(at, `<a href="`+html.EscapeString(value)+`"></a>`, ".html")
				return
			}
			s.emit(at, value, ext)
		}
	}
}

func (s *codeScanner) emit(
	at []string,
	text string,
	ext string,
) {
	if s.emitted >= maxScanChanges {
		return
	}
	s.emitted++
	dir := s.prefix
	if len(at) > 1 {
		dir += pathSegment(strings.Join(at[:len(at)-1], "_")) + "/"
	}
	c := Change{FilePath: dir + pathSegment(at[len(at)-1]) + ext, AddedText: text, Virtual: true}
	for i := 1; i <= strings.Count(text, "\n")+1; i++ {
		c.AddedLines = append(c.AddedLines, i)
	}
	s.out = append(s.out, c)
}

func classifyCode(
	key string,
	value string,
) (string, bool) {
	if scanURLCode.MatchString(value) {
		return ".url", true
	}
	hint, hinted := scanCodeKeys[strings.ToLower(key)]
	if hinted && hint != "" {
		return hint, true
	}
	switch {
	case strings.Contains(value, "<") && scanHTMLTag.MatchString(value):
		return ".html", true
	case scanJS.MatchString(value):
		return ".js", true
	case strings.Contains(value, "{") && scanCSSRule.MatchString(value):
		return ".css", true
	}
	return "", false
}

func attributeMarkup(items []json.RawMessage) string {
	markup := "<div"
	n := 0
	for _, item := range items {
		var a struct {
			Name  *string `json:"name"`
			Value *string `json:"value"`
		}
		if json.Unmarshal(item, &a) != nil || a.Name == nil || a.Value == nil {
			return ""
		}
		name := strings.TrimSpace(*a.Name)
		if !validAttributeName(name) {
			continue
		}
		markup += " " + name + `="` + html.EscapeString(*a.Value) + `"`
		n++
	}
	if n == 0 {
		return ""
	}
	return markup + "></div>"
}

func validAttributeName(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == ':' || r == '.') {
			return false
		}
	}
	return true
}
