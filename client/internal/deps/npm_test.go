package deps

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

func readNPM(t *testing.T, lock string) []Dependency {
	t.Helper()
	r, err := NPM{}.Read([]byte(lock), nil)
	if err != nil {
		t.Fatal(err)
	}
	return r.Dependencies
}

func byName(ds []Dependency) map[string]Dependency {
	out := map[string]Dependency{}
	for _, d := range ds {
		out[d.Name] = d
	}
	return out
}

func TestNPMReadsWhatWasInstalled(t *testing.T) {
	got := byName(readNPM(t, `{"lockfileVersion": 3, "packages": {
		"": {"name": "app", "dependencies": {"axios": "^0.21.1", "alias": "npm:real-pkg@^3"}, "devDependencies": {"@scope/pkg": "1.0.0"}},
		"node_modules/axios": {"version": "0.21.1", "resolved": "https://registry.npmjs.org/axios/-/axios-0.21.1.tgz"},
		"node_modules/follow-redirects": {"version": "1.16.1"},
		"node_modules/@scope/pkg": {"version": "1.0.0", "dev": true},
		"node_modules/a/node_modules/b": {"version": "2.0.0"},
		"node_modules/alias": {"name": "real-pkg", "version": "3.0.0"},
		"node_modules/web": {"link": true, "resolved": "packages/web"},
		"node_modules/fromgit": {"version": "1.0.0", "resolved": "git+ssh://git@github.com/x/y.git#abc"}
	}}`))
	want := map[string]struct {
		version       string
		indirect, dev bool
	}{
		"axios":            {"0.21.1", false, false},
		"follow-redirects": {"1.16.1", true, false},
		"@scope/pkg":       {"1.0.0", false, true},  // a direct developer-only dependency
		"b":                {"2.0.0", true, false},  // nested: name after the last node_modules/
		"real-pkg":         {"3.0.0", false, false}, // installed under the alias "alias"
	}
	if len(got) != len(want) {
		t.Fatalf("got %v (a workspace link and a git checkout are left out)", got)
	}
	for n, w := range want {
		d := got[n]
		if d.Version != w.version || d.Indirect != w.indirect || d.Dev != w.dev || d.Ecosystem != "npm" || d.Line != 0 {
			t.Errorf("%s: got %+v, want %+v", n, d, w)
		}
	}
}

// npm marks a package reached only through development or optional dependencies "devOptional":
// nothing needs it at runtime, but an install without development dependencies still installs it,
// so it's DevOptional, not Dev. An entry marked both is read as Dev.
func TestNPMDevOptional(t *testing.T) {
	got := byName(readNPM(t, `{"lockfileVersion": 3, "packages": {
		"": {"name": "app", "dependencies": {"auth": "1"}, "devDependencies": {"vitest": "3"}},
		"node_modules/auth": {"version": "1.0.0", "peerDependencies": {"vitest": "3"}},
		"node_modules/vitest": {"version": "3.2.7", "devOptional": true},
		"node_modules/both": {"version": "1.0.0", "dev": true, "devOptional": true}
	}}`))
	if v := got["vitest"]; v.Dev || !v.DevOptional {
		t.Errorf("vitest: %+v, want DevOptional only", v)
	}
	if b := got["both"]; !b.Dev || b.DevOptional {
		t.Errorf("both: %+v, want Dev only", b)
	}
	if a := got["auth"]; a.Dev || a.DevOptional {
		t.Errorf("auth: %+v, want runtime", a)
	}
}

// Only the public registry's packages count as public. Another registry, a company mirror and an
// entry with no recorded source are all private, but still read.
func TestNPMPrivatePackages(t *testing.T) {
	data, err := os.ReadFile("testdata/private-package-lock.json")
	if err != nil {
		t.Fatal(err)
	}
	r, err := NPM{}.Read(data, nil)
	if err != nil {
		t.Fatal(err)
	}
	private := 0
	for _, d := range r.Dependencies {
		if d.Private {
			private++
		}
	}
	if len(r.Dependencies) == 0 || private == 0 {
		t.Errorf("expected public and private packages, got %+v", r.Dependencies)
	}
	got := byName(readNPM(t, `{"lockfileVersion": 3, "packages": {
		"": {"name": "app", "dependencies": {"a": "1", "b": "1", "c": "1", "d": "1", "e": "1", "f": "1"}},
		"node_modules/a": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz"},
		"node_modules/b": {"version": "1.0.0", "resolved": "https://registry.yarnpkg.com/b/-/b-1.0.0.tgz"},
		"node_modules/c": {"version": "1.0.0", "resolved": "https://npm.pkg.github.com/download/@acme/c/1.0.0/0123abcd"},
		"node_modules/d": {"version": "1.0.0", "resolved": "https://artifactory.acme.com/api/npm/npm-virtual/d/-/d-1.0.0.tgz"},
		"node_modules/e": {"version": "1.0.0"},
		"node_modules/f": {"version": "1.0.0", "resolved": "https://registry.npmjs.org.evil.example/f/-/f-1.0.0.tgz"}
	}}`))
	for name, want := range map[string]bool{"a": false, "b": false, "c": true, "d": true, "e": true, "f": true} {
		if got[name].Private != want {
			t.Errorf("%s: private = %v, want %v", name, got[name].Private, want)
		}
	}
}

// A lockfile with no "packages" section (lockfileVersion 1) must be an error, never an empty
// result that reads as clean.
func TestNPMRefusesWhatItCantRead(t *testing.T) {
	v1 := `{"lockfileVersion": 1, "dependencies": {"lodash": {"version": "4.17.11"}}}`
	if _, err := (NPM{}).Read([]byte(v1), nil); err == nil || !strings.Contains(err.Error(), "npm 6 or earlier") || !strings.Contains(err.Error(), "npm install") {
		t.Errorf("v1: %v, want the lockfileVersion 1 error saying how to upgrade", err)
	}
	if _, err := (NPM{}).Read([]byte(`{"lockfileVersion": 3}`), nil); err == nil {
		t.Error("no packages section should be an error")
	}
	if _, err := (NPM{}).Read([]byte(`not json`), nil); err == nil {
		t.Error("a file that isn't JSON should be an error")
	}
	if got := readNPM(t, `{"lockfileVersion": 3, "packages": {"": {"name": "app"}}}`); len(got) != 0 {
		t.Errorf("a project with no dependencies: %v", got)
	}
}

// A package is direct when an importer's requirement resolves to that copy, as Node would load
// it: a workspace that lists a package gets its own nested copy if it has one, and the root's
// otherwise.
func TestNPMDirectFollowsNodesResolution(t *testing.T) {
	ds := readNPM(t, `{"lockfileVersion": 3, "packages": {
		"": {"name": "app", "dependencies": {"express": "4.17.1"}, "peerDependencies": {"peerish": "1"}, "workspaces": ["packages/*"]},
		"packages/web": {"name": "web", "dependencies": {"lodash": "^4.17.21", "ms": "^2.1.0"}},
		"packages/web/node_modules/lodash": {"version": "4.17.21"},
		"node_modules/express": {"version": "4.17.1", "dependencies": {"lodash": "4.17.11"}},
		"node_modules/lodash": {"version": "4.17.11"},
		"node_modules/ms": {"version": "2.1.3"},
		"node_modules/peerish": {"version": "1.0.0"}
	}}`)
	want := map[string]bool{ // location -> indirect
		"node_modules/express":             false,
		"packages/web/node_modules/lodash": false,
		"node_modules/lodash":              true,  // only express asks for this copy
		"node_modules/ms":                  false, // web lists it and has no copy of its own
		"node_modules/peerish":             true,  // a peer: the project expects it, but doesn't install it itself
	}
	for _, d := range ds {
		if w, ok := want[d.Location]; !ok || d.Indirect != w {
			t.Errorf("%s: indirect = %v, want %v (listed %v)", d.Location, d.Indirect, w, ok)
		}
	}
}

// A real npm 7+ lockfile: 184 entries, a workspace, an alias, developer-only packages and nested
// copies.
func TestNPMWorkspaceLockfile(t *testing.T) {
	r, _, err := All.ReadFile("testdata/workspace/package-lock.json")
	if err != nil {
		t.Fatal(err)
	}
	at := map[string]Dependency{}
	for _, d := range r.Dependencies {
		at[d.Location] = d
	}
	for loc, want := range map[string]Dependency{
		"node_modules/express":                    {Name: "express", Version: "4.17.1"},
		"node_modules/lodash":                     {Name: "lodash", Version: "4.17.15"},
		"node_modules/lodash-old":                 {Name: "lodash", Version: "4.17.11"}, // the alias's real package
		"packages/web/node_modules/lodash":        {Name: "lodash", Version: "4.17.21"}, // the workspace's own
		"node_modules/mocha":                      {Name: "mocha", Version: "5.2.0", Dev: true},
		"node_modules/express/node_modules/debug": {Name: "debug", Version: "2.6.9", Indirect: true},
	} {
		d, ok := at[loc]
		if !ok || d.Name != want.Name || d.Version != want.Version || d.Indirect != want.Indirect || d.Dev != want.Dev {
			t.Errorf("%s = %+v (found %v), want %+v", loc, d, ok, want)
		}
	}
	if len(r.Dependencies) < 150 {
		t.Errorf("read %d packages, want every installed one", len(r.Dependencies))
	}
}

// Only the project and its workspaces are importers. A folder outside node_modules that is
// neither, a stale entry nothing links to (Mattermost's "../compass-components/lib", left by
// `npm link`) or a `file:` dependency's folder, doesn't make what it lists direct.
func TestNPMOnlyTheProjectAndItsWorkspacesListDirectDependencies(t *testing.T) {
	indirect := func(ds []Dependency) map[string]bool {
		out := map[string]bool{}
		for _, d := range ds {
			out[d.Location] = d.Indirect
		}
		return out
	}

	stale := indirect(readNPM(t, `{"lockfileVersion": 2, "packages": {
		"": {"name": "webapp", "dependencies": {"@mattermost/compass-components": "^0.2.12"}},
		"../compass-components/lib": {"version": "0.2.1", "dependencies": {"axios": "^0.21.1"}},
		"node_modules/@mattermost/compass-components": {"version": "0.2.12", "resolved": "https://registry.npmjs.org/@mattermost/compass-components/-/compass-components-0.2.12.tgz", "dependencies": {"axios": "^0.21.1"}},
		"node_modules/axios": {"version": "0.21.1", "resolved": "https://registry.npmjs.org/axios/-/axios-0.21.1.tgz"}
	}}`))
	if !stale["node_modules/axios"] || stale["node_modules/@mattermost/compass-components"] {
		t.Errorf("stale entry: %v (axios comes in through compass-components)", stale)
	}

	fileDep := readNPM(t, `{"lockfileVersion": 3, "packages": {
		"": {"name": "app", "dependencies": {"shared": "file:../shared"}},
		"node_modules/shared": {"resolved": "../shared", "link": true},
		"../shared": {"name": "shared", "version": "1.0.0", "dependencies": {"lodash": "4.17.11"}},
		"node_modules/lodash": {"version": "4.17.11", "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.11.tgz"}
	}}`)
	if got := indirect(fileDep); !got["node_modules/lodash"] || len(got) != 1 {
		t.Errorf("file: dependency: %v (lodash is shared's, and the local folder itself is never checked)", got)
	}

	linkedOnly := indirect(readNPM(t, `{"lockfileVersion": 3, "packages": {
		"": {"name": "app"},
		"node_modules/web": {"resolved": "packages/web", "link": true},
		"packages/web": {"name": "web", "dependencies": {"ms": "^2.1.0"}},
		"packages/old": {"name": "old", "dependencies": {"debug": "^4.0.0"}},
		"node_modules/ms": {"version": "2.1.3", "resolved": "https://registry.npmjs.org/ms/-/ms-2.1.3.tgz"},
		"node_modules/debug": {"version": "4.3.4", "resolved": "https://registry.npmjs.org/debug/-/debug-4.3.4.tgz"}
	}}`))
	if linkedOnly["node_modules/ms"] || !linkedOnly["node_modules/debug"] {
		t.Errorf("workspaces: %v (a linked folder is one with no pattern; a folder nothing links to isn't)", linkedOnly)
	}
}

// The reading carries the lockfile's lockfileVersion, for the server's advice on which npm to run.
func TestNPMReadsTheLockfileVersion(t *testing.T) {
	for _, v := range []int{2, 3} {
		r, err := NPM{}.Read([]byte(fmt.Sprintf(`{"lockfileVersion": %d, "packages": {"": {}}}`, v)), nil)
		if err != nil {
			t.Fatal(err)
		}
		if r.LockfileVersion != v {
			t.Errorf("lockfileVersion %d read as %d", v, r.LockfileVersion)
		}
	}
}
