package pathgate

import (
	"strings"
)

const (
	MaxExcludedPaths      = 50
	MaxExcludedPathLength = 200
)

func NormaliseExcludedPath(pattern string) (string, bool) {
	p := strings.TrimSpace(strings.ReplaceAll(pattern, "\\", "/"))
	p = strings.TrimPrefix(p, "./")
	p = strings.TrimLeft(p, "/")
	if strings.HasSuffix(p, "/") {
		p += "**"
	}
	if p == "" || len(p) > MaxExcludedPathLength || strings.ContainsAny(p, "\x00\n\r") {
		return "", false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return "", false
		}
	}
	if strings.Trim(p, "*/") == "" {
		return "", false
	}
	return p, true
}

func ExcludedPath(patterns []string,
	path string) (string, bool) {
	p := strings.TrimLeft(strings.ReplaceAll(path, "\\", "/"), "/")
	if p == "" {
		return "", false
	}
	for _, raw := range patterns {
		pattern, ok := NormaliseExcludedPath(raw)
		if !ok {
			continue
		}
		if pathGlob(pattern, p) {
			return pattern, true
		}
	}
	return "", false
}

func pathGlob(p string,
	s string) bool {
	for len(p) > 0 {
		switch {
		case strings.HasPrefix(p, "**/"):
			rest := p[3:]
			if pathGlob(rest, s) {
				return true
			}
			for i := 0; i < len(s); i++ {
				if s[i] == '/' && pathGlob(rest, s[i+1:]) {
					return true
				}
			}
			return false
		case strings.HasPrefix(p, "**"):
			return true
		case p[0] == '*':
			rest := p[1:]
			for i := 0; i <= len(s); i++ {
				if pathGlob(rest, s[i:]) {
					return true
				}
				if i < len(s) && s[i] == '/' {
					return false
				}
			}
			return false
		case p[0] == '?':
			if len(s) == 0 || s[0] == '/' {
				return false
			}
			p, s = p[1:], s[1:]
		default:
			if len(s) == 0 || p[0] != s[0] {
				return false
			}
			p, s = p[1:], s[1:]
		}
	}
	return len(s) == 0
}
