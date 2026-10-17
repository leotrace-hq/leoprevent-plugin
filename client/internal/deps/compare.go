package deps

// How a turn changed a dependency, in the spelling the dependency check takes.
const (
	// Added: not in the file at the start of the turn.
	Added = "added"
	// Changed: its version, or how the project uses it (indirect, development only), differs from
	// the start of the turn.
	Changed = "changed"
	// Unchanged: as it was at the start of the turn.
	Unchanged = "unchanged"
)

// Marked is a dependency with how the turn changed it.
type Marked struct {
	Dependency
	// Change is Added, Changed or Unchanged; "" when there was nothing to compare with (Unmarked).
	Change string
	// Previous is the version at the start of the turn, when Change is Changed and the version
	// moved. A change of context alone leaves it empty.
	Previous string
	// Locations is every install folder this entry stands for, set by Collapse.
	Locations []string
}

// Comparison is a file's dependencies at the end of a turn against the start of it.
type Comparison struct {
	// Changes are what the turn added or changed: what's normally sent.
	Changes []Marked
	// Unchanged are the rest, sent too when the whole file is checked (Whole).
	Unchanged []Marked
	// Removed were in the file at the start of the turn and aren't now. Nothing to look up, so
	// they're never sent for a check; the fix check (LEO-513) uses them.
	Removed []Dependency
}

// Whole is every dependency in the file now, each marked: what's sent when the whole file is
// checked, the first time a session changes it.
func (c Comparison) Whole() []Marked {
	return append(append([]Marked{}, c.Changes...), c.Unchanged...)
}

// Compare matches the two readings of one file by Key. A dependency is Changed when its version
// moved, or when it moved between runtime and development or between direct and indirect, since
// either can change how it's checked. A file that didn't exist at the start of the turn is
// before = nil: everything is Added. The order of after is kept.
func Compare(before, after []Dependency) Comparison {
	was := make(map[string]Dependency, len(before))
	for _, d := range before {
		was[d.Key] = d
	}
	var c Comparison
	now := make(map[string]bool, len(after))
	for _, d := range after {
		now[d.Key] = true
		old, ok := was[d.Key]
		switch {
		case !ok:
			c.Changes = append(c.Changes, Marked{Dependency: d, Change: Added})
		case old.Version != d.Version:
			c.Changes = append(c.Changes, Marked{Dependency: d, Change: Changed, Previous: old.Version})
		case old.Indirect != d.Indirect || old.Dev != d.Dev:
			c.Changes = append(c.Changes, Marked{Dependency: d, Change: Changed})
		default:
			c.Unchanged = append(c.Unchanged, Marked{Dependency: d, Change: Unchanged})
		}
	}
	for _, d := range before {
		if !now[d.Key] {
			c.Removed = append(c.Removed, d)
		}
	}
	return c
}

// Unmarked is every dependency with no change known: what's sent when there is no start-of-turn
// copy of the file to compare with (no git baseline).
func Unmarked(after []Dependency) []Marked {
	out := make([]Marked, len(after))
	for i, d := range after {
		out[i] = Marked{Dependency: d}
	}
	return out
}

// changeRank orders how notable a change is, for Collapse: added, then changed, then unchanged,
// then unknown.
var changeRank = map[string]int{Added: 0, Changed: 1, Unchanged: 2, "": 3}

// Collapse merges the copies of one package at one version into one entry, for sending. A large
// npm tree installs the same release in many folders, and the check only needs it once: the
// server matches by name and version, so nothing is lost from the check. The copies are merged
// towards the strictest reading:
//   - runtime if any copy is runtime, direct if any copy is direct;
//   - the most notable change (changeRank). Previous is kept only when that is Changed, from the
//     first copy that has one: copies that moved from different versions say only one of them;
//   - a private copy is never merged with a public one. The same name from two sources is what
//     dependency confusion looks like, and a private copy is never sent at all, so merging would
//     either hide the public copy from the check or send the private one;
//   - Location, Key and Line are the first copy's, and Locations lists every copy's, so a notice
//     can still say where they are.
//
// Removed dependencies aren't collapsed: a package removed from one folder but still installed in
// another isn't gone, which the fix check (LEO-513) must tell by name, not by folder.
func Collapse(ms []Marked) []Marked {
	type id struct {
		ecosystem, name, version string
		private                  bool
	}
	index := map[id]int{}
	var out []Marked
	for _, m := range ms {
		k := id{m.Ecosystem, m.Name, m.Version, m.Private}
		i, ok := index[k]
		if !ok {
			m.Locations = []string{m.Location}
			index[k] = len(out)
			out = append(out, m)
			continue
		}
		c := &out[i]
		c.Locations = append(c.Locations, m.Location)
		c.Indirect = c.Indirect && m.Indirect
		c.Dev = c.Dev && m.Dev
		if c.Previous == "" {
			c.Previous = m.Previous
		}
		if changeRank[m.Change] < changeRank[c.Change] {
			c.Change = m.Change
		}
	}
	for i := range out {
		if out[i].Change != Changed {
			out[i].Previous = ""
		}
	}
	return out
}
