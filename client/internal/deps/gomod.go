package deps

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// GoMod reads go.mod, which records the exact version of each module the build uses.
type GoMod struct{}

func (GoMod) Ecosystem() string { return "Go" }
func (GoMod) Files() []string   { return []string{"go.mod"} }

// Companions: go.sum, read only for a go.mod older than Go 1.17 (see Read).
func (GoMod) Companions() []string { return []string{"go.sum"} }

// Read reads go.mod (see readGoMod) and, when it's older than Go 1.17, fills in from go.sum.
// Since Go 1.17, go.mod lists every module the build uses; before, only the ones the main
// module's own code needs, so indirect modules can be missing. LeoPrevent never asks Go for the
// real list, so go.sum, when it's there, is the best evidence: every module it has code for (not
// just a go.mod) that go.mod doesn't name is added, at the highest version it lists, which is
// usually but not always the one built. A note says which of these applied; for Go 1.17 and
// later go.sum isn't needed, so a missing or unreadable one says nothing.
func (GoMod) Read(data []byte, companions Companions) (Reading, error) {
	deps, mod, err := readGoMod(data)
	if err != nil || mod.goVersionAtLeast(1, 17) {
		return Reading{Dependencies: deps}, err
	}
	sum, ok := companions["go.sum"]
	switch {
	case !ok:
		return Reading{Dependencies: deps, Notes: []Note{{Code: NoteGoPre117NoSum, File: "go.sum", Go: mod.goVersion}}}, nil
	case sum.Err != nil:
		return Reading{Dependencies: deps, Notes: []Note{{Code: NoteGoPre117SumUnreadable, File: "go.sum", Go: mod.goVersion, Reason: sum.Err.Error()}}}, nil
	}
	extra := fromGoSum(sum.Data, mod.known)
	return Reading{Dependencies: append(deps, extra...),
		Notes: []Note{{Code: NoteGoPre117FromSum, File: "go.sum", Go: mod.goVersion, Count: len(extra)}}}, nil
}

// goMod is what readGoMod learned about the file beyond its dependencies.
type goMod struct {
	goVersion string          // the go line, e.g. "1.16"
	known     map[string]bool // every module path go.mod names: required, replaced, or a replacement
}

func (m goMod) goVersionAtLeast(major, minor int) bool {
	var ma, mi int
	if n, _ := fmt.Sscanf(m.goVersion, "%d.%d", &ma, &mi); n < 2 {
		return false // no go line: Go treats the file as old
	}
	return ma > major || ma == major && mi >= minor
}

// fromGoSum lists the modules go.sum has code for ("path version h1:...", not
// "path version/go.mod h1:...", which only fed the module graph) that go.mod doesn't name, each
// at the highest such version, located at its go.sum line.
func fromGoSum(sum []byte, known map[string]bool) []Dependency {
	best := map[string]Dependency{}
	for n, line := range strings.Split(string(sum), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 || strings.HasSuffix(fields[1], "/go.mod") || known[fields[0]] {
			continue
		}
		if _, ok := parseGoVersion(fields[1]); !ok {
			continue
		}
		if have, ok := best[fields[0]]; ok && compareGoVersions(fields[1], have.Version) <= 0 {
			continue
		}
		best[fields[0]] = Dependency{Ecosystem: "Go", Name: fields[0], Version: fields[1],
			Location: fmt.Sprintf("go.sum:%d", n+1), Key: fields[0], Indirect: true}
	}
	out := make([]Dependency, 0, len(best))
	for _, d := range best {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// readGoMod returns every module go.mod requires, at the version the build uses:
//   - "require" lines, single and in ( ... ) blocks; "// indirect" lines are kept and marked;
//   - a "replace" to another module and version means that module is what gets built, so it is
//     returned instead, located at the replace line; a replace to a local directory (./x, ../x,
//     /x) is the repo's own code, and the module is left out;
//   - a replace with a version on the left ("a v1.2.3 => ...") applies only to that version;
//   - module, go, toolchain, exclude, retract, godebug and tool lines aren't dependencies.
func readGoMod(data []byte) ([]Dependency, goMod, error) {
	mod := goMod{known: map[string]bool{}}
	type replacement struct {
		fromVersion   string // "" when the replace covers every version
		path, version string // version "" means a local directory
		line          int
	}
	type require struct {
		path, version string
		indirect      bool
		line          int
	}
	var requires []require
	replaces := map[string][]replacement{}

	block := ""
	for n, raw := range strings.Split(string(data), "\n") {
		line := n + 1
		code, comment, _ := strings.Cut(raw, "//")
		// Go reads the comment "indirect", or "indirect;" followed by a note, as the marker.
		words := strings.Fields(comment)
		indirect := len(words) == 1 && words[0] == "indirect" || len(words) > 1 && words[0] == "indirect;"
		// Brackets are tokens of their own: "require(" opens a block just like "require (".
		code = strings.NewReplacer("(", " ( ", ")", " ) ").Replace(code)
		fields := strings.Fields(code)
		if len(fields) == 0 {
			continue
		}
		if block != "" {
			if fields[0] == ")" {
				block = ""
				continue
			}
			fields = append([]string{block}, fields...)
		} else if len(fields) == 2 && fields[1] == "(" {
			block = fields[0]
			continue
		}
		for i := range fields {
			if unq, err := strconv.Unquote(fields[i]); err == nil {
				fields[i] = unq // module paths may be quoted
			}
		}
		switch fields[0] {
		case "require":
			if len(fields) < 3 || fields[1] == "(" || fields[1] == ")" {
				return nil, mod, fmt.Errorf("go.mod line %d: malformed require", line)
			}
			requires = append(requires, require{fields[1], fields[2], indirect, line})
			mod.known[fields[1]] = true
		case "go":
			if len(fields) > 1 {
				mod.goVersion = fields[1]
			}
		case "replace":
			arrow := -1
			for i, f := range fields {
				if f == "=>" {
					arrow = i
				}
			}
			if arrow < 2 || arrow == len(fields)-1 {
				return nil, mod, fmt.Errorf("go.mod line %d: malformed replace", line)
			}
			r := replacement{path: fields[arrow+1], line: line}
			if arrow == 3 {
				r.fromVersion = fields[2]
			}
			if len(fields) > arrow+2 {
				r.version = fields[arrow+2]
			}
			replaces[fields[1]] = append(replaces[fields[1]], r)
			mod.known[fields[1]], mod.known[r.path] = true, true
		}
	}

	var out []Dependency
	for _, rq := range requires {
		d := Dependency{Ecosystem: "Go", Name: rq.path, Version: rq.version,
			Location: fmt.Sprintf("go.mod:%d", rq.line), Line: rq.line, Indirect: rq.indirect}
		var chosen *replacement
		for i, r := range replaces[rq.path] {
			// A version-specific replace wins over one for every version.
			if r.fromVersion == rq.version || r.fromVersion == "" && chosen == nil {
				chosen = &replaces[rq.path][i]
			}
		}
		if chosen != nil {
			if chosen.version == "" {
				continue // replaced by a local directory: the repo's own code
			}
			d.Name, d.Version, d.Line = chosen.path, chosen.version, chosen.line
			d.Location = fmt.Sprintf("go.mod:%d, replacing %s %s", chosen.line, rq.path, rq.version)
		}
		d.Key = d.Name
		out = append(out, d)
	}
	return out, mod, nil
}

// goVersion is a parsed Go module version, for choosing go.sum's highest. The plugin can't use
// the server's version package (the plugin module never imports the private root), so this is
// the small part go.sum needs: semver order, with a pseudo-version ordered as the pre-release it
// is, and +incompatible ignored.
type goVersion struct {
	nums [3]uint64
	pre  []string
}

func parseGoVersion(s string) (goVersion, bool) {
	s = strings.TrimPrefix(s, "v")
	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i]
	}
	var v goVersion
	if i := strings.IndexByte(s, '-'); i >= 0 {
		v.pre, s = strings.Split(s[i+1:], "."), s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return v, false
	}
	for i, p := range parts {
		n, err := strconv.ParseUint(p, 10, 64)
		if err != nil {
			return v, false
		}
		v.nums[i] = n
	}
	return v, true
}

// compareGoVersions orders two Go module versions; an unparseable one sorts first.
func compareGoVersions(a, b string) int {
	va, okA := parseGoVersion(a)
	vb, okB := parseGoVersion(b)
	switch {
	case !okA && !okB:
		return 0
	case !okA:
		return -1
	case !okB:
		return 1
	}
	for i := range va.nums {
		if va.nums[i] != vb.nums[i] {
			if va.nums[i] < vb.nums[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(va.pre) == 0 && len(vb.pre) == 0:
		return 0
	case len(va.pre) == 0:
		return 1
	case len(vb.pre) == 0:
		return -1
	}
	for i := 0; i < len(va.pre) && i < len(vb.pre); i++ {
		x, y := va.pre[i], vb.pre[i]
		if x == y {
			continue
		}
		xn, yn := isDigits(x), isDigits(y)
		switch {
		case xn && yn:
			if len(x) != len(y) {
				return compareInts(len(x), len(y))
			}
			return strings.Compare(x, y)
		case xn:
			return -1
		case yn:
			return 1
		}
		return strings.Compare(x, y)
	}
	return compareInts(len(va.pre), len(vb.pre))
}

func isDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return s != ""
}

func compareInts(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}
