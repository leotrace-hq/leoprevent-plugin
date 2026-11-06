package wire

import (
	"strconv"
	"strings"
)

// Location is a finding location (`Finding.Location`, "app/main.py:42") parsed into
// its file path and the line it cites.
//
// It is the ONE parser for that string on the Go side, shared by both modules — the
// server's diff anchor, span validation, Aikido/Snyk matching and the unconfirmed sweep,
// and the client's re-wake and pull-request lane all used to carry their own split, and
// they disagreed on the edge cases (`path:abc`, `:5`, `path:0`, surrounding space).
//
// ⚠️ THE STRING STAYS THE IDENTITY. `Finding.Location` is still what the de-dup keys,
// the located credit sets and the client ledger compare; this type is how a caller READS
// it, never a replacement for it on the wire or in a record. Do not re-serialise a
// Location to build a key: `Path` is trimmed and a line-less location round-trips to its
// trimmed self, so a key built from it can differ from one built from the raw string.
type Location struct {
	// Path is the file part. When the location cites no usable line it is the whole
	// (trimmed) string, so a bare path — the transcript fallback, where the judge has no
	// line numbers — and a symbol citation (`app.py:fetch`) are both their own path.
	Path string
	// Line is the 1-based cited line, or 0 when there is none.
	Line int
}

// ParseLocation splits a `path:line` location on its LAST colon, so a path containing
// a colon (a Windows drive letter) keeps its head. A trailing segment counts as a line
// only when it is a whole number >= 1; anything else — no colon, a leading colon, a
// non-numeric or non-positive tail — yields the whole string as the path and Line 0.
// Callers read Line 0 as "don't point at anything", never as line zero.
func ParseLocation(loc string) Location {
	loc = strings.TrimSpace(loc)
	i := strings.LastIndexByte(loc, ':')
	if i <= 0 {
		return Location{Path: loc}
	}
	n, err := strconv.Atoi(strings.TrimSpace(loc[i+1:]))
	if err != nil || n < 1 {
		return Location{Path: loc}
	}
	return Location{Path: loc[:i], Line: n}
}

// HasLine reports whether the location cites a usable line.
func (l Location) HasLine() bool { return l.Line > 0 }
