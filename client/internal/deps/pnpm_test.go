package deps

import (
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func readPNPM(t *testing.T, lock string, companions Companions) []Dependency {
	t.Helper()
	r, err := PNPM{}.Read([]byte(lock), companions)
	if err != nil {
		t.Fatal(err)
	}
	if r.LockfileVersion != 0 {
		t.Errorf("LockfileVersion = %d, want 0: it's npm's, and the server words npm's advice by it", r.LockfileVersion)
	}
	return r.Dependencies
}

type pnpmWant struct {
	version       string
	indirect, dev bool
	location      string
}

func checkPNPM(t *testing.T, got []Dependency, want map[string]pnpmWant) {
	t.Helper()
	by := byName(got)
	if len(by) != len(want) {
		t.Fatalf("got %d packages %v, want %d", len(by), got, len(want))
	}
	for name, w := range want {
		d, ok := by[name]
		if !ok {
			t.Errorf("%s: missing", name)
			continue
		}
		if d.Version != w.version || d.Indirect != w.indirect || d.Dev != w.dev || d.Location != w.location ||
			d.Ecosystem != "npm" || d.Key != name+"@"+w.version || d.Private || d.DevOptional {
			t.Errorf("%s: got %+v, want %+v", name, d, w)
		}
	}
}

// The same project in each format pnpm has written: axios (direct) brings in follow-redirects,
// vitest is a direct development dependency, real-pkg is installed under the alias "alias", and
// react-dom carries a peer suffix. Every format reads the same.
var pnpmSameProject = map[string]pnpmWant{
	"axios":            {"0.21.1", false, false, "axios@0.21.1"},
	"follow-redirects": {"1.14.1", true, false, "axios@0.21.1 > follow-redirects@1.14.1"},
	"vitest":           {"0.34.6", false, true, "vitest@0.34.6"},
	"tinypool":         {"0.7.0", true, true, "vitest@0.34.6 > tinypool@0.7.0"},
	"real-pkg":         {"3.0.0", false, false, "real-pkg@3.0.0"},
	"react-dom":        {"18.2.0", false, false, "react-dom@18.2.0"},
	"react":            {"18.2.0", false, false, "react@18.2.0"},
}

func TestPNPMLockfile5(t *testing.T) {
	checkPNPM(t, readPNPM(t, `lockfileVersion: 5.4

specifiers:
  axios: ^0.21.1
  alias: npm:real-pkg@^3
  react: ^18
  react-dom: ^18
  vitest: ^0.34.0

dependencies:
  alias: /real-pkg/3.0.0
  axios: 0.21.1
  react: 18.2.0
  react-dom: 18.2.0_react@18.2.0

devDependencies:
  vitest: 0.34.6

packages:

  /axios/0.21.1:
    resolution: {integrity: sha512-a}
    dependencies:
      follow-redirects: 1.14.1
    dev: false

  /follow-redirects/1.14.1:
    resolution: {integrity: sha512-b}
    dev: false

  /real-pkg/3.0.0:
    resolution: {integrity: sha512-c}
    dev: false

  /react/18.2.0:
    resolution: {integrity: sha512-d}
    dev: false

  /react-dom/18.2.0_react@18.2.0:
    resolution: {integrity: sha512-e}
    peerDependencies:
      react: ^18.2.0
    dependencies:
      react: 18.2.0
    dev: false

  /vitest/0.34.6:
    resolution: {integrity: sha512-f}
    dependencies:
      tinypool: 0.7.0
    dev: true

  /tinypool/0.7.0:
    resolution: {integrity: sha512-g}
    dev: true
`, nil), pnpmSameProject)
}

func TestPNPMLockfile6(t *testing.T) {
	checkPNPM(t, readPNPM(t, `lockfileVersion: '6.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

dependencies:
  alias:
    specifier: npm:real-pkg@^3
    version: /real-pkg@3.0.0
  axios:
    specifier: ^0.21.1
    version: 0.21.1
  react:
    specifier: ^18
    version: 18.2.0
  react-dom:
    specifier: ^18
    version: 18.2.0(react@18.2.0)

devDependencies:
  vitest:
    specifier: ^0.34.0
    version: 0.34.6

packages:

  /axios@0.21.1:
    resolution: {integrity: sha512-a}
    dependencies:
      follow-redirects: 1.14.1
    dev: false

  /follow-redirects@1.14.1:
    resolution: {integrity: sha512-b}
    dev: false

  /real-pkg@3.0.0:
    resolution: {integrity: sha512-c}
    dev: false

  /react@18.2.0:
    resolution: {integrity: sha512-d}
    dev: false

  /react-dom@18.2.0(react@18.2.0):
    resolution: {integrity: sha512-e}
    peerDependencies:
      react: ^18.2.0
    dependencies:
      react: 18.2.0
    dev: false

  /vitest@0.34.6:
    resolution: {integrity: sha512-f}
    dependencies:
      tinypool: 0.7.0
    dev: true

  /tinypool@0.7.0:
    resolution: {integrity: sha512-g}
    dev: true
`, nil), pnpmSameProject)
}

func TestPNPMLockfile9(t *testing.T) {
	checkPNPM(t, readPNPM(t, `lockfileVersion: '9.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

importers:

  .:
    dependencies:
      alias:
        specifier: npm:real-pkg@^3
        version: real-pkg@3.0.0
      axios:
        specifier: ^0.21.1
        version: 0.21.1
      react:
        specifier: ^18
        version: 18.2.0
      react-dom:
        specifier: ^18
        version: 18.2.0(react@18.2.0)
    devDependencies:
      vitest:
        specifier: ^0.34.0
        version: 0.34.6

packages:

  axios@0.21.1:
    resolution: {integrity: sha512-a}

  follow-redirects@1.14.1:
    resolution: {integrity: sha512-b}

  real-pkg@3.0.0:
    resolution: {integrity: sha512-c}

  react@18.2.0:
    resolution: {integrity: sha512-d}

  react-dom@18.2.0:
    resolution: {integrity: sha512-e}
    peerDependencies:
      react: ^18.2.0

  vitest@0.34.6:
    resolution: {integrity: sha512-f}

  tinypool@0.7.0:
    resolution: {integrity: sha512-g}

snapshots:

  axios@0.21.1:
    dependencies:
      follow-redirects: 1.14.1

  follow-redirects@1.14.1: {}

  real-pkg@3.0.0: {}

  react@18.2.0: {}

  react-dom@18.2.0(react@18.2.0):
    dependencies:
      react: 18.2.0

  vitest@0.34.6:
    dependencies:
      tinypool: 0.7.0

  tinypool@0.7.0: {}
`, nil), pnpmSameProject)
}

// A workspace's packages are found from its own importer, named on its path, and a link to
// another workspace is the project's own code, never read as a package. A package both a runtime
// and a development path reach is runtime; one pnpm keeps a copy of per set of peers is one
// release.
func TestPNPMWorkspace(t *testing.T) {
	got := readPNPM(t, `lockfileVersion: '9.0'

importers:

  .:
    devDependencies:
      typescript:
        specifier: ^5
        version: 5.4.5
      lodash:
        specifier: ^4
        version: 4.17.15

  packages/web:
    dependencies:
      shared:
        specifier: workspace:*
        version: link:../shared
      express:
        specifier: ^4
        version: 4.17.1
      ui-kit:
        specifier: ^1
        version: 1.0.0(react@18.2.0)
      other-kit:
        specifier: ^1
        version: 1.0.0(react@17.0.2)

  packages/shared:
    dependencies:
      lodash:
        specifier: ^4
        version: 4.17.15

packages:

  typescript@5.4.5:
    resolution: {integrity: sha512-a}
  lodash@4.17.15:
    resolution: {integrity: sha512-b}
  express@4.17.1:
    resolution: {integrity: sha512-c}
  qs@6.7.0:
    resolution: {integrity: sha512-d}
  ui-kit@1.0.0:
    resolution: {integrity: sha512-e}
  other-kit@1.0.0:
    resolution: {integrity: sha512-f}
  react@18.2.0:
    resolution: {integrity: sha512-g}
  react@17.0.2:
    resolution: {integrity: sha512-h}

snapshots:

  typescript@5.4.5: {}
  lodash@4.17.15: {}
  express@4.17.1:
    dependencies:
      qs: 6.7.0
  qs@6.7.0: {}
  ui-kit@1.0.0(react@18.2.0):
    dependencies:
      react: 18.2.0
  other-kit@1.0.0(react@17.0.2):
    dependencies:
      ui-kit: 1.0.0(react@17.0.2)
  ui-kit@1.0.0(react@17.0.2):
    dependencies:
      react: 17.0.2
  react@18.2.0: {}
  react@17.0.2: {}
`, nil)
	checkPNPM(t, got, map[string]pnpmWant{
		"typescript": {"5.4.5", false, true, "typescript@5.4.5"},
		// The root's devDependencies and packages/shared's dependencies both list it: runtime.
		"lodash":    {"4.17.15", false, false, "lodash@4.17.15"},
		"express":   {"4.17.1", false, false, "packages/web: express@4.17.1"},
		"qs":        {"6.7.0", true, false, "packages/web: express@4.17.1 > qs@6.7.0"},
		"ui-kit":    {"1.0.0", false, false, "packages/web: ui-kit@1.0.0"},
		"other-kit": {"1.0.0", false, false, "packages/web: other-kit@1.0.0"},
		// Two versions of react: byName keeps the later key, 18.2.0; 17.0.2 is checked below.
		"react": {"18.2.0", true, false, "packages/web: ui-kit@1.0.0 > react@18.2.0"},
	})
	for _, d := range got {
		if d.Key == "react@17.0.2" && (d.Location != "packages/web: other-kit@1.0.0 > ui-kit@1.0.0 > react@17.0.2" || !d.Indirect || d.Dev) {
			t.Errorf("react@17.0.2: %+v", d)
		}
	}
}

// Each version of a package is its own entry, and one with no registry version (git, a local
// directory, a file: tarball) isn't read at all.
func TestPNPMReleasesAndSources(t *testing.T) {
	got := readPNPM(t, `lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      a:
        specifier: ^1
        version: 1.0.0
      b:
        specifier: ^2
        version: 2.0.0
      fromgit:
        specifier: github:x/fromgit
        version: https://codeload.github.com/x/fromgit/tar.gz/abc
      local:
        specifier: file:../local
        version: file:../local

packages:

  a@1.0.0:
    resolution: {integrity: sha512-a}
  b@2.0.0:
    resolution: {integrity: sha512-b}
  a@2.0.0:
    resolution: {integrity: sha512-c}
  fromgit@https://codeload.github.com/x/fromgit/tar.gz/abc:
    resolution: {type: git, repo: https://github.com/x/fromgit, commit: abc}
    version: 1.0.0

snapshots:

  a@1.0.0: {}
  b@2.0.0:
    dependencies:
      a: 2.0.0
  a@2.0.0: {}
  fromgit@https://codeload.github.com/x/fromgit/tar.gz/abc: {}
`, nil)
	var keys []string
	for _, d := range got {
		keys = append(keys, d.Key+" "+d.Location)
	}
	want := []string{"a@1.0.0 a@1.0.0", "a@2.0.0 b@2.0.0 > a@2.0.0", "b@2.0.0 b@2.0.0"}
	if strings.Join(keys, "|") != strings.Join(want, "|") {
		t.Errorf("got %q, want %q", keys, want)
	}
}

// What may be a company's own package is marked private and never sent: a tarball from another
// host, and any package in the project's own npm scope. A package with only an integrity hash
// came from the configured registry, which the lockfile doesn't name, so it counts as public.
func TestPNPMPrivatePackages(t *testing.T) {
	lock := `lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      '@acme/ui':
        specifier: ^1
        version: 1.0.0
      '@acmecorp/other':
        specifier: ^1
        version: 1.0.0
      '@types/node':
        specifier: ^20
        version: 20.0.0
      mirrored:
        specifier: ^1
        version: 1.0.0
      public-tarball:
        specifier: ^1
        version: 1.0.0

packages:

  '@acme/ui@1.0.0':
    resolution: {integrity: sha512-a}
  '@acmecorp/other@1.0.0':
    resolution: {integrity: sha512-b}
  '@types/node@20.0.0':
    resolution: {integrity: sha512-c}
  mirrored@1.0.0:
    resolution: {integrity: sha512-d, tarball: https://npm.acme.internal/mirrored/-/mirrored-1.0.0.tgz}
  public-tarball@1.0.0:
    resolution: {integrity: sha512-e, tarball: https://registry.npmjs.org/public-tarball/-/public-tarball-1.0.0.tgz}

snapshots:

  '@acme/ui@1.0.0': {}
  '@acmecorp/other@1.0.0': {}
  '@types/node@20.0.0': {}
  mirrored@1.0.0: {}
  public-tarball@1.0.0: {}
`
	private := func(c Companions) map[string]bool {
		out := map[string]bool{}
		for _, d := range readPNPM(t, lock, c) {
			out[d.Name] = d.Private
		}
		return out
	}
	scoped := Companions{"package.json": {Data: []byte(`{"name": "@acme/app"}`)}}
	for name, want := range map[string]bool{"@acme/ui": true, "@acmecorp/other": false, "@types/node": false, "mirrored": true, "public-tarball": false} {
		if got := private(scoped)[name]; got != want {
			t.Errorf("with the project named @acme/app, %s: private = %v, want %v", name, got, want)
		}
	}
	// No package.json, an unscoped name, a refused or unreadable one: no scope to go on.
	for label, c := range map[string]Companions{
		"none":       nil,
		"unscoped":   {"package.json": {Data: []byte(`{"name": "app"}`)}},
		"refused":    {"package.json": {Err: fs.ErrPermission}},
		"unreadable": {"package.json": {Data: []byte(`{`)}},
	} {
		if private(c)["@acme/ui"] {
			t.Errorf("%s: @acme/ui is private with no project scope to go on", label)
		}
	}
}

// What can't be read is an error, never an empty reading, which would report the project clean.
func TestPNPMRefusesWhatItCantRead(t *testing.T) {
	for label, lock := range map[string]string{
		"not yaml":       "lockfileVersion: [",
		"no version":     "importers: {}\n",
		"future version": "lockfileVersion: '10.0'\n",
		"never released": "lockfileVersion: '8.0'\n",
		"too old":        "lockfileVersion: 3.9\n",
	} {
		if _, err := (PNPM{}).Read([]byte(lock), nil); err == nil {
			t.Errorf("%s: no error", label)
		}
	}
}

// A path the server would refuse (over its 1024 bytes) is sent as the package itself.
func TestPNPMLongPathFallsBack(t *testing.T) {
	var b strings.Builder
	b.WriteString("lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      p0:\n        specifier: '1'\n        version: 1.0.0\npackages:\n")
	const depth = 120
	for i := 0; i < depth; i++ {
		b.WriteString("  p" + strconv.Itoa(i) + "@1.0.0:\n    resolution: {integrity: x}\n")
	}
	b.WriteString("snapshots:\n")
	for i := 0; i < depth; i++ {
		if i == depth-1 {
			b.WriteString("  p" + strconv.Itoa(i) + "@1.0.0: {}\n")
			continue
		}
		b.WriteString("  p" + strconv.Itoa(i) + "@1.0.0:\n    dependencies:\n      p" + strconv.Itoa(i+1) + ": 1.0.0\n")
	}
	last := byName(readPNPM(t, b.String(), nil))["p"+strconv.Itoa(depth-1)]
	if last.Location != last.Key || len(last.Location) > maxPNPMLocation {
		t.Errorf("deepest package's location = %q, want its key", last.Location)
	}
}

// pnpm-lock.yaml is picked by name like any other dependency file, and package.json beside it is
// read as its companion, from the same copy (now, or at the start of the turn).
func TestPNPMIsADependencyFile(t *testing.T) {
	if r, ok := All.For(filepath.Join("web", "pnpm-lock.yaml")); !ok || r.Ecosystem() != "npm" {
		t.Fatalf("pnpm-lock.yaml: reader %v, %v", r, ok)
	}
	files := map[string]string{
		filepath.Join("web", "pnpm-lock.yaml"): "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      '@acme/ui':\n        specifier: '1'\n        version: 1.0.0\npackages:\n  '@acme/ui@1.0.0':\n    resolution: {integrity: x}\nsnapshots:\n  '@acme/ui@1.0.0': {}\n",
		filepath.Join("web", "package.json"):   `{"name": "@acme/web"}`,
	}
	open := func(p string) ([]byte, error) {
		if s, ok := files[p]; ok {
			return []byte(s), nil
		}
		return nil, fs.ErrNotExist
	}
	got, _, err := All.ReadWith(filepath.Join("web", "pnpm-lock.yaml"), open)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Dependencies) != 1 || !got.Dependencies[0].Private {
		t.Errorf("got %+v, want @acme/ui private from package.json's scope", got.Dependencies)
	}
}

// pnpm can write two YAML documents (pnpm.io/lockfile): an env document with the pnpm version the
// project resolved, then the lockfile. The lockfile is the last one. Reading only the first found no
// dependencies, which would have reported the project clean.
func TestPNPMReadsTheLastDocument(t *testing.T) {
	checkPNPM(t, readPNPM(t, `---
lockfileVersion: '9.0'

importers:

  .:
    configDependencies: {}
    packageManagerDependencies:
      pnpm:
        specifier: 10.20.0
        version: 10.20.0

packages:

  pnpm@10.20.0:
    resolution: {integrity: sha512-env}

snapshots:

  pnpm@10.20.0: {}
---
lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      axios:
        specifier: ^0.21.1
        version: 0.21.1

packages:

  axios@0.21.1:
    resolution: {integrity: sha512-a}

snapshots:

  axios@0.21.1: {}
`, nil), map[string]pnpmWant{"axios": {"0.21.1", false, false, "axios@0.21.1"}})
	if _, err := (PNPM{}).Read(nil, nil); err == nil {
		t.Error("an empty file read without an error")
	}
}

// What else a 9.0 lockfile writes: an optional dependency (installed at runtime, so not
// development-only), a copy with several peer groups, a patched copy (patch_hash) and a catalog
// specifier. Each is the release it names.
func TestPNPMOptionalPeersPatchesAndCatalogs(t *testing.T) {
	checkPNPM(t, readPNPM(t, `lockfileVersion: '9.0'

catalogs:
  default:
    react:
      specifier: ^18.2.0
      version: 18.2.0

patchedDependencies:
  lodash@4.17.15:
    hash: abc123
    path: patches/lodash@4.17.15.patch

importers:

  .:
    dependencies:
      react:
        specifier: 'catalog:'
        version: 18.2.0
      ui:
        specifier: ^1
        version: 1.0.0(@types/react@18.2.0)(react@18.2.0)
      lodash:
        specifier: 4.17.15
        version: 4.17.15(patch_hash=abc123)
    optionalDependencies:
      fsevents:
        specifier: ^2
        version: 2.3.3

packages:

  react@18.2.0:
    resolution: {integrity: sha512-a}
  '@types/react@18.2.0':
    resolution: {integrity: sha512-b}
  ui@1.0.0:
    resolution: {integrity: sha512-c}
  lodash@4.17.15:
    resolution: {integrity: sha512-d}
  fsevents@2.3.3:
    resolution: {integrity: sha512-e}
    os: [darwin]
  bindings@1.5.0:
    resolution: {integrity: sha512-f}

snapshots:

  react@18.2.0: {}
  '@types/react@18.2.0': {}
  ui@1.0.0(@types/react@18.2.0)(react@18.2.0):
    dependencies:
      react: 18.2.0
    optionalDependencies:
      bindings: 1.5.0
  lodash@4.17.15(patch_hash=abc123): {}
  fsevents@2.3.3: {}
  bindings@1.5.0: {}
`, nil), map[string]pnpmWant{
		"react":    {"18.2.0", false, false, "react@18.2.0"},
		"ui":       {"1.0.0", false, false, "ui@1.0.0"},
		"lodash":   {"4.17.15", false, false, "lodash@4.17.15"},
		"fsevents": {"2.3.3", false, false, "fsevents@2.3.3"},
		"bindings": {"1.5.0", true, false, "ui@1.0.0 > bindings@1.5.0"},
	})
}

// 5.x's other peer suffixes, a hash ("_7b3d9c2a1f") and a scoped peer written with "+"
// ("_@types+react@18.0.0"), and a scoped package's key ("/@babel/core/7.22.0").
func TestPNPMLockfile5PeerSuffixes(t *testing.T) {
	checkPNPM(t, readPNPM(t, `lockfileVersion: 5.4

specifiers:
  styled: ^5
  rdom: ^18
  '@babel/core': ^7

dependencies:
  styled: 5.3.0_7b3d9c2a1f
  rdom: 18.2.0_@types+react@18.0.0
  '@babel/core': 7.22.0

packages:

  /styled/5.3.0_7b3d9c2a1f:
    resolution: {integrity: sha512-a}
    dev: false

  /rdom/18.2.0_@types+react@18.0.0:
    resolution: {integrity: sha512-b}
    dev: false

  /@babel/core/7.22.0:
    resolution: {integrity: sha512-c}
    dependencies:
      '@babel/parser': 7.22.4
    dev: false

  /@babel/parser/7.22.4:
    resolution: {integrity: sha512-d}
    dev: false
`, nil), map[string]pnpmWant{
		"styled":        {"5.3.0", false, false, "styled@5.3.0"},
		"rdom":          {"18.2.0", false, false, "rdom@18.2.0"},
		"@babel/core":   {"7.22.0", false, false, "@babel/core@7.22.0"},
		"@babel/parser": {"7.22.4", true, false, "@babel/core@7.22.0 > @babel/parser@7.22.4"},
	})
}

// A 6.0 workspace: importers in the {specifier, version} form, a link to another workspace left
// out, and each workspace's packages found from its own importer.
func TestPNPMLockfile6Workspace(t *testing.T) {
	checkPNPM(t, readPNPM(t, `lockfileVersion: '6.0'

importers:

  .:
    devDependencies:
      typescript:
        specifier: ^5
        version: 5.4.5

  apps/web:
    dependencies:
      shared:
        specifier: workspace:*
        version: link:../../packages/shared
      express:
        specifier: ^4
        version: 4.17.1

  packages/shared: {}

packages:

  /typescript@5.4.5:
    resolution: {integrity: sha512-a}
    dev: true

  /express@4.17.1:
    resolution: {integrity: sha512-b}
    dependencies:
      qs: 6.7.0
    dev: false

  /qs@6.7.0:
    resolution: {integrity: sha512-c}
    dev: false
`, nil), map[string]pnpmWant{
		"typescript": {"5.4.5", false, true, "typescript@5.4.5"},
		"express":    {"4.17.1", false, false, "apps/web: express@4.17.1"},
		"qs":         {"6.7.0", true, false, "apps/web: express@4.17.1 > qs@6.7.0"},
	})
}

// pnpm 9's alphas wrote 7.0, whose layout isn't documented: it's read as 9.0 when it has snapshots
// and as 6.0 otherwise, so either way what the direct dependencies bring in is found. Read the other
// way round, a 9.0-shaped file would have given axios alone.
func TestPNPMLockfile7IsReadByWhatItHolds(t *testing.T) {
	want := map[string]pnpmWant{
		"axios":            {"0.21.1", false, false, "axios@0.21.1"},
		"follow-redirects": {"1.14.1", true, false, "axios@0.21.1 > follow-redirects@1.14.1"},
	}
	checkPNPM(t, readPNPM(t, `lockfileVersion: '7.0'

importers:

  .:
    dependencies:
      axios:
        specifier: ^0.21.1
        version: 0.21.1

packages:

  axios@0.21.1:
    resolution: {integrity: sha512-a}

  follow-redirects@1.14.1:
    resolution: {integrity: sha512-b}

snapshots:

  axios@0.21.1:
    dependencies:
      follow-redirects: 1.14.1

  follow-redirects@1.14.1: {}
`, nil), want)
	checkPNPM(t, readPNPM(t, `lockfileVersion: '7.0'

dependencies:
  axios:
    specifier: ^0.21.1
    version: 0.21.1

packages:

  /axios@0.21.1:
    resolution: {integrity: sha512-a}
    dependencies:
      follow-redirects: 1.14.1
    dev: false

  /follow-redirects@1.14.1:
    resolution: {integrity: sha512-b}
    dev: false
`, nil), want)
}
