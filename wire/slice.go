package wire

import (
	"strings"
	"unicode/utf8"
)

const TruncatedMarker = "… [truncated]\n"

func (c ChangedFile) StartLine() int {
	if c.BodyStartLine < 1 {
		return 1
	}
	return c.BodyStartLine
}

func SliceAround(full string,
	anchors []int,
	limit int) (string, int) {
	if len(full) <= limit {
		return full, 1
	}
	lines := strings.SplitAfter(full, "\n")
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	n := len(lines)
	lo, hi := -1, -1
	for _, a := range anchors {
		i := min(max(a-1, 0), n-1)
		if lo < 0 || i < lo {
			lo = i
		}
		if i > hi {
			hi = i
		}
	}
	if lo < 0 {
		lo, hi = 0, 0
	}
	size := 0
	for i := lo; i <= hi; i++ {
		size += len(lines[i])
	}
	if size > limit {
		hi, size = lo, len(lines[lo])
	}
	if size > limit {
		return capTop(full, limit), 1
	}
	for {
		grew := false
		if lo > 0 && size+len(lines[lo-1]) <= limit {
			lo--
			size += len(lines[lo])
			grew = true
		}
		if hi < n-1 && size+len(lines[hi+1]) <= limit {
			hi++
			size += len(lines[hi])
			grew = true
		}
		if !grew {
			break
		}
	}
	body := strings.Join(lines[lo:hi+1], "")
	if hi < n-1 {
		if !strings.HasSuffix(body, "\n") {
			body += "\n"
		}
		body += TruncatedMarker
	}
	return body, lo + 1
}

func capTop(s string,
	n int) string {
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "\n" + TruncatedMarker
}
