package deps

import (
	"reflect"
	"testing"
)

func marks(ms []Marked) map[string]string {
	out := map[string]string{}
	for _, m := range ms {
		out[m.Key] = m.Change + " " + m.Previous
	}
	return out
}

// What "go get github.com/jackc/pgx/v5@v5.7.1" leaves: pgx raised, two indirect lines added (so
// every line below moves), one indirect module promoted to a direct require, and one dropped.
func TestCompareAGoGet(t *testing.T) {
	before, err := GoMod{}.Read([]byte(`module m

go 1.23

require (
	github.com/jackc/pgx/v5 v5.5.0
	golang.org/x/crypto v0.31.0
	golang.org/x/text v0.20.0 // indirect
	example.com/gone v1.0.0 // indirect
)
`), nil)
	if err != nil {
		t.Fatal(err)
	}
	after, err := GoMod{}.Read([]byte(`module m

go 1.23

require (
	github.com/jackc/pgx/v5 v5.7.1
	golang.org/x/crypto v0.31.0
	golang.org/x/text v0.20.0
)

require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
)
`), nil)
	if err != nil {
		t.Fatal(err)
	}
	c := Compare(before.Dependencies, after.Dependencies)
	want := map[string]string{
		"github.com/jackc/pgx/v5":     "changed v5.5.0",
		"golang.org/x/text":           "changed ", // now direct: same version, new context
		"github.com/jackc/pgpassfile": "added ",
		"github.com/jackc/puddle/v2":  "added ",
	}
	if got := marks(c.Changes); !reflect.DeepEqual(got, want) {
		t.Errorf("changes = %v, want %v", got, want)
	}
	if got := marks(c.Unchanged); !reflect.DeepEqual(got, map[string]string{"golang.org/x/crypto": "unchanged "}) {
		t.Errorf("x/crypto moved line but nothing else, so it's unchanged: %v", got)
	}
	if len(c.Removed) != 1 || c.Removed[0].Name != "example.com/gone" {
		t.Errorf("removed = %+v", c.Removed)
	}
	if c.Changes[0].Line != 6 || c.Changes[0].Name != "github.com/jackc/pgx/v5" {
		t.Errorf("a change keeps the line in the file the agent left, in its order: %+v", c.Changes[0])
	}
	if len(c.Whole()) != 5 {
		t.Errorf("the whole file is every dependency now: %+v", c.Whole())
	}
}

// npm is matched by install folder: two copies of one package are two dependencies, and a
// package moving from development to runtime is a change though its version didn't move.
func TestCompareAnNPMInstall(t *testing.T) {
	before, err := NPM{}.Read([]byte(`{"lockfileVersion": 3, "packages": {
		"": {"dependencies": {"a": "^1.0.0"}, "devDependencies": {"jest-util": "^1.0.0"}},
		"node_modules/a": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz", "dependencies": {"ms": "^2.0.0"}},
		"node_modules/ms": {"version": "2.0.0", "resolved": "https://registry.npmjs.org/ms/-/ms-2.0.0.tgz"},
		"node_modules/jest-util": {"version": "1.0.0", "dev": true, "resolved": "https://registry.npmjs.org/jest-util/-/jest-util-1.0.0.tgz"}
	}}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	after, err := NPM{}.Read([]byte(`{"lockfileVersion": 3, "packages": {
		"": {"dependencies": {"a": "^1.0.0", "b": "^1.0.0", "jest-util": "^1.0.0"}},
		"node_modules/a": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz", "dependencies": {"ms": "^2.0.0"}},
		"node_modules/ms": {"version": "2.0.0", "resolved": "https://registry.npmjs.org/ms/-/ms-2.0.0.tgz"},
		"node_modules/b": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/b/-/b-1.0.0.tgz", "dependencies": {"ms": "^3.0.0"}},
		"node_modules/b/node_modules/ms": {"version": "3.0.0", "resolved": "https://registry.npmjs.org/ms/-/ms-3.0.0.tgz"},
		"node_modules/jest-util": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/jest-util/-/jest-util-1.0.0.tgz"}
	}}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	c := Compare(before.Dependencies, after.Dependencies)
	want := map[string]string{
		"node_modules/b":                 "added ",
		"node_modules/b/node_modules/ms": "added ",   // a second copy of ms
		"node_modules/jest-util":         "changed ", // now a runtime dependency
	}
	if got := marks(c.Changes); !reflect.DeepEqual(got, want) {
		t.Errorf("changes = %v, want %v", got, want)
	}
	if got := marks(c.Unchanged); len(got) != 2 || got["node_modules/ms"] == "" || got["node_modules/a"] == "" {
		t.Errorf("unchanged = %v", got)
	}
	for _, m := range c.Changes {
		if m.Key == "node_modules/jest-util" && (m.Dev || m.Indirect) {
			t.Errorf("the change carries the context now: %+v", m)
		}
	}
}

// A file the turn created has nothing before it: everything is added. With no start-of-turn copy
// at all, nothing is known about the change.
func TestCompareANewFileAndNoBaseline(t *testing.T) {
	deps := []Dependency{{Name: "a", Version: "1.0.0", Key: "a"}, {Name: "b", Version: "2.0.0", Key: "b"}}
	c := Compare(nil, deps)
	if len(c.Changes) != 2 || c.Changes[0].Change != Added || len(c.Unchanged)+len(c.Removed) != 0 {
		t.Errorf("a new file: %+v", c)
	}
	for _, m := range Unmarked(deps) {
		if m.Change != "" || m.Previous != "" {
			t.Errorf("no baseline: %+v", m)
		}
	}
}

func copyOf(loc, change string, indirect, dev bool) Marked {
	return Marked{Dependency: Dependency{Ecosystem: "npm", Name: "ms", Version: "2.0.0", Location: loc, Key: loc,
		Indirect: indirect, Dev: dev}, Change: change}
}

// Copies of one release become one entry, merged towards the strictest reading: runtime if any
// copy is, direct if any copy is, and the most notable change.
func TestCollapseMergesCopiesStrictest(t *testing.T) {
	got := Collapse([]Marked{
		copyOf("node_modules/a/node_modules/ms", Unchanged, true, true),
		{Dependency: Dependency{Ecosystem: "npm", Name: "other", Version: "1.0.0", Location: "node_modules/other"}, Change: Unchanged},
		copyOf("node_modules/b/node_modules/ms", Added, true, false),
		copyOf("node_modules/ms", Changed, false, true),
	})
	if len(got) != 2 || got[0].Name != "ms" || got[1].Name != "other" {
		t.Fatalf("one entry per release, in first-seen order: %+v", got)
	}
	ms := got[0]
	if ms.Indirect || ms.Dev || ms.Change != Added || len(ms.Locations) != 3 || ms.Location != "node_modules/a/node_modules/ms" {
		t.Errorf("merged = %+v", ms)
	}
}

// Previous survives only when the merged change is Changed.
func TestCollapseKeepsPreviousOnlyForAChange(t *testing.T) {
	moved := copyOf("node_modules/x/node_modules/ms", Changed, true, false)
	moved.Previous = "1.0.0"
	if got := Collapse([]Marked{copyOf("node_modules/ms", Unchanged, false, false), moved})[0]; got.Change != Changed || got.Previous != "1.0.0" {
		t.Errorf("changed: %+v", got)
	}
	if got := Collapse([]Marked{moved, copyOf("node_modules/ms", Added, false, false)})[0]; got.Change != Added || got.Previous != "" {
		t.Errorf("added wins, and an added package has no previous version: %+v", got)
	}
}

// Different versions, and a private copy of a public name, are never merged.
func TestCollapseKeepsVersionsAndSourcesApart(t *testing.T) {
	newer := copyOf("node_modules/b/node_modules/ms", Added, true, false)
	newer.Version = "3.0.0"
	private := copyOf("node_modules/c/node_modules/ms", Added, true, false)
	private.Private = true
	if got := Collapse([]Marked{copyOf("node_modules/ms", Unchanged, false, false), newer, private}); len(got) != 3 {
		t.Errorf("three distinct entries: %+v", got)
	}
}
