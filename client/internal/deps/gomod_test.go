package deps

import (
	"errors"
	"reflect"
	"testing"
)

func TestGoModReadsRequiresAndReplaces(t *testing.T) {
	mod := []byte(`module github.com/acme/app

go 1.23.4

toolchain go1.23.4

require golang.org/x/crypto v0.31.0

require (
	github.com/jackc/pgx/v5 v5.7.1
	github.com/acme/app/lib v0.0.0-20260101000000-abcdef123456
	golang.org/x/net v0.20.0 // indirect
	"example.com/quoted" v1.0.0
	example.com/old v1.0.0
	example.com/pinned v1.2.0
)

exclude golang.org/x/net v0.19.0
retract v1.0.1

replace github.com/acme/app/lib => ./lib

replace example.com/old => example.com/new v2.3.4+incompatible

replace (
	example.com/pinned v1.1.0 => example.com/fork v1.1.5
)
`)
	r, err := GoMod{}.Read(mod, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []Dependency{
		{Ecosystem: "Go", Name: "golang.org/x/crypto", Version: "v0.31.0", Location: "go.mod:7", Key: "golang.org/x/crypto", Line: 7},
		{Ecosystem: "Go", Name: "github.com/jackc/pgx/v5", Version: "v5.7.1", Location: "go.mod:10", Key: "github.com/jackc/pgx/v5", Line: 10},
		// github.com/acme/app/lib is replaced by ./lib, the repo's own code: left out.
		{Ecosystem: "Go", Name: "golang.org/x/net", Version: "v0.20.0", Location: "go.mod:12", Key: "golang.org/x/net", Line: 12, Indirect: true},
		{Ecosystem: "Go", Name: "example.com/quoted", Version: "v1.0.0", Location: "go.mod:13", Key: "example.com/quoted", Line: 13},
		// The replacement is what's built, so it's what's checked, at the replace line.
		{Ecosystem: "Go", Name: "example.com/new", Version: "v2.3.4+incompatible", Location: "go.mod:23, replacing example.com/old v1.0.0", Key: "example.com/new", Line: 23},
		// The replace for example.com/pinned covers v1.1.0 only, so v1.2.0 is checked as is.
		{Ecosystem: "Go", Name: "example.com/pinned", Version: "v1.2.0", Location: "go.mod:15", Key: "example.com/pinned", Line: 15},
	}
	if !reflect.DeepEqual(r.Dependencies, want) {
		t.Errorf("got\n%+v\nwant\n%+v", r.Dependencies, want)
	}
	if len(r.Notes) != 0 {
		t.Errorf("go 1.23: go.mod is complete, no notes: %v", r.Notes)
	}
}

// Go's own syntax rules, which hand-edited go.mod files use: a block opened with no space
// ("require("), and an indirect comment followed by a note ("// indirect; ...").
func TestGoModSyntaxEdgeCases(t *testing.T) {
	r, err := GoMod{}.Read([]byte("module m\n\ngo 1.21\n\nrequire(\n\ta.com/x v1.0.0\n)\n\nrequire b.com/y v1.2.0 // indirect; needed by tests\nrequire c.com/z v1.0.0 // indirectly used\n"), nil)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, d := range r.Dependencies {
		got[d.Name] = d.Indirect
	}
	if ind, ok := got["a.com/x"]; !ok || ind {
		t.Errorf("require( block: %v", r.Dependencies)
	}
	if !got["b.com/y"] {
		t.Error(`"// indirect; note" is indirect`)
	}
	if got["c.com/z"] {
		t.Error(`"// indirectly used" isn't the indirect marker`)
	}
	for _, bad := range []string{"require golang.org/x/crypto\n", "module m\nrequire (a.com/x v1.0.0)\n", "replace a.com/x =>\n"} {
		if _, err := (GoMod{}).Read([]byte(bad), nil); err == nil {
			t.Errorf("%q isn't valid go.mod and should be an error", bad)
		}
	}
}

// Before Go 1.17, go.mod doesn't list every module the build uses. With go.sum beside it, the
// modules it has code for (not just a go.mod) and go.mod doesn't name are read as a best effort,
// at the highest version listed, and the reading says so.
func TestGoModFillsInFromGoSumBefore117(t *testing.T) {
	mod := []byte("module m\n\ngo 1.16\n\nrequire a.com/x v1.0.0\nreplace b.com/r => b.com/r2 v1.0.0\n")
	sum := []byte(`a.com/x v1.0.0 h1:aaa=
a.com/x v1.0.0/go.mod h1:bbb=
golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9 h1:c1=
golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9/go.mod h1:c2=
golang.org/x/crypto v0.0.0-20201216223049-8b5274cf687f h1:c3=
golang.org/x/crypto v0.0.0-20201216223049-8b5274cf687f/go.mod h1:c4=
golang.org/x/crypto v0.1.0/go.mod h1:c5=
only.graph/m v1.2.0/go.mod h1:g=
b.com/r v1.0.0 h1:r=
`)
	got, err := GoMod{}.Read(mod, Companions{"go.sum": {Data: sum}})
	if err != nil {
		t.Fatal(err)
	}
	c, ok := byName(got.Dependencies)["golang.org/x/crypto"]
	if !ok || c.Version != "v0.0.0-20201216223049-8b5274cf687f" || c.Location != "go.sum:5" || !c.Indirect {
		t.Errorf("x/crypto from go.sum, at the highest version it has code for: %+v", c)
	}
	for _, skip := range []string{"only.graph/m", "b.com/r"} {
		if _, ok := byName(got.Dependencies)[skip]; ok {
			t.Errorf("%s isn't built (go.mod only, or replaced)", skip)
		}
	}
	if want := (Note{Code: NoteGoPre117FromSum, File: "go.sum", Go: "1.16", Count: 1}); len(got.Notes) != 1 || got.Notes[0] != want {
		t.Errorf("notes: %+v, want %+v", got.Notes, want)
	}
	alone, _ := GoMod{}.Read(mod, nil)
	if len(alone.Dependencies) != 1 || len(alone.Notes) != 1 || alone.Notes[0].Code != NoteGoPre117NoSum {
		t.Errorf("without go.sum: %+v", alone)
	}
	refused, _ := GoMod{}.Read(mod, Companions{"go.sum": {Err: errors.New("a symlink, not read")}})
	if len(refused.Notes) != 1 || refused.Notes[0].Code != NoteGoPre117SumUnreadable || refused.Notes[0].Reason != "a symlink, not read" {
		t.Errorf("go.sum there but unreadable is its own note, never \"no go.sum\": %+v", refused.Notes)
	}
	noLine, _ := GoMod{}.Read([]byte("module m\n\nrequire a.com/x v1.0.0\n"), nil)
	if len(noLine.Notes) != 1 || noLine.Notes[0].Go != "" || noLine.Notes[0].Code != NoteGoPre117NoSum {
		t.Errorf("no go line reads as before 1.17: %+v", noLine.Notes)
	}
}

func TestGoVersionOrder(t *testing.T) {
	order := []string{"v0.0.0-20200622213623-75b288015ac9", "v0.0.0-20201216223049-8b5274cf687f", "v0.1.0",
		"v1.2.4-0.20230101120000-abcdef123456", "v1.2.4", "v1.10.0", "v2.0.0+incompatible"}
	for i := 1; i < len(order); i++ {
		if compareGoVersions(order[i-1], order[i]) != -1 || compareGoVersions(order[i], order[i-1]) != 1 {
			t.Errorf("%s should sort before %s", order[i-1], order[i])
		}
	}
	if compareGoVersions("v2.0.0+incompatible", "v2.0.0") != 0 {
		t.Error("+incompatible is ignored when comparing")
	}
}
