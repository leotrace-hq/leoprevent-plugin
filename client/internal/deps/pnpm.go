package deps

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// PNPM reads pnpm-lock.yaml: what pnpm installed (LEO-762). pnpm installs from the npm registry,
// so its packages are OSV's npm ecosystem and are checked exactly as npm's are.
type PNPM struct{}

func (PNPM) Ecosystem() string { return "npm" }
func (PNPM) Files() []string   { return []string{"pnpm-lock.yaml"} }

// Companions: package.json, read only for the project's own npm scope (see pnpmScope).
//
// ⚠️ NEVER .npmrc. It would say which registry each scope comes from, but it's a secret file
// (pathgate: it often holds registry tokens), and the plugin never reads one.
func (PNPM) Companions() []string { return []string{"package.json"} }

// Read returns every installed registry package in the lockfile, with direct ones marked. pnpm's
// releases since pnpm 7 have written three formats, and each is read (the format's number isn't
// pnpm's version):
//   - 5.x (pnpm 7): packages keyed "/name/1.2.3_peer", references "1.2.3_peer" or "/real/1.2.3";
//   - 6.0 (pnpm 8): packages keyed "/name@1.2.3(peer@1)", importer entries {specifier, version};
//   - 9.0 (pnpm 9, 10): packages keyed "name@1.2.3" (resolution) and snapshots keyed
//     "name@1.2.3(peer@1)" (dependencies).
//
// pnpm 9's alphas wrote 7.0, whose layout isn't documented, so it's read by what it holds: as 9.0
// when it has a snapshots section, otherwise as 6.0. No release has written 8.0.
//
// A package is direct when an importer (the project, or one of its workspaces) lists it, and
// development-only when nothing but an importer's devDependencies reach it. Its Location is the
// shortest path to it from an importer ("express@4.17.1 > qs@6.7.0", under "packages/web: " for a
// workspace), which is how the agent is told where an indirect copy comes from.
//
// What isn't sent, as private (Private), or isn't read at all:
//   - a local workspace, `link:` or `file:` entry, or a git or directory source: no registry
//     version, left out;
//   - a tarball from a host other than the public registry: private;
//   - a package in the project's own npm scope (pnpmScope): private;
//   - a package with only an integrity hash came from the project's configured registry, which
//     the lockfile doesn't name, and counts as public. A private registry configured only in
//     .npmrc can't be told apart (docs/egress.md).
//
// An unknown format is an error, never an empty reading: that would report the project clean.
func (PNPM) Read(data []byte, companions Companions) (Reading, error) {
	lock, err := pnpmLockDocument(data)
	if err != nil {
		return Reading{}, err
	}
	format, err := pnpmFormat(lock.LockfileVersion.Value, len(lock.Snapshots) > 0)
	if err != nil {
		return Reading{}, err
	}
	importers := lock.Importers
	if len(importers) == 0 {
		importers = map[string]pnpmImporter{".": lock.pnpmImporter} // a project with no workspaces (5.x, 6.0)
	}
	g := pnpmGraph(format, lock)
	scope := pnpmScope(companions)

	// Walk from every importer, nearest first, so each package gets its shortest path, whether
	// it's direct, and whether anything at runtime needs it.
	type visit struct {
		id   string
		path []string
		dev  bool
	}
	direct, runtime := map[string]bool{}, map[string]bool{}
	where := map[string]string{}
	seen := map[[2]string]bool{} // (id, "dev"|"run"): each node walked once per kind
	var queue []visit
	for _, name := range sortedKeys(importers) {
		imp := importers[name]
		prefix := ""
		if name != "." && name != "" {
			prefix = name + ": "
		}
		for _, sec := range []struct {
			deps map[string]pnpmRef
			dev  bool
		}{{imp.Dependencies, false}, {imp.OptionalDependencies, false}, {imp.DevDependencies, true}} {
			for _, dep := range sortedKeys(sec.deps) {
				id, ok := pnpmRefID(format, dep, sec.deps[dep].Version)
				if !ok || g[id] == nil {
					continue
				}
				direct[id] = true
				queue = append(queue, visit{id, []string{prefix + g[id].label()}, sec.dev})
			}
		}
	}
	for len(queue) > 0 {
		v := queue[0]
		queue = queue[1:]
		kind := "run"
		if v.dev {
			kind = "dev"
		}
		if seen[[2]string{v.id, kind}] {
			continue
		}
		seen[[2]string{v.id, kind}] = true
		if !v.dev {
			runtime[v.id] = true
		}
		if _, ok := where[v.id]; !ok {
			where[v.id] = strings.Join(v.path, " > ")
		}
		n := g[v.id]
		for _, dep := range sortedKeys(n.requires) {
			id, ok := pnpmRefID(format, dep, n.requires[dep])
			if !ok || g[id] == nil {
				continue
			}
			path := append(append([]string{}, v.path...), g[id].label())
			queue = append(queue, visit{id, path, v.dev})
		}
	}

	// One entry per package and version: pnpm keeps a copy per set of peers ("react-dom@18.2.0
	// (react@18.2.0)"), which is one release to check. Direct and runtime if any copy is.
	type release struct{ name, version string }
	merged := map[release]*Dependency{}
	for id := range where {
		n := g[id]
		if !n.registry || n.version == "" {
			continue
		}
		k := release{n.name, n.version}
		d, ok := merged[k]
		if !ok {
			d = &Dependency{Ecosystem: "npm", Name: n.name, Version: n.version, Key: n.name + "@" + n.version,
				Location: where[id], Indirect: true, Dev: true, Private: n.private || scope.owns(n.name)}
			merged[k] = d
		}
		if direct[id] {
			d.Indirect = false
		}
		if runtime[id] {
			d.Dev = false
		}
		if len(where[id]) < len(d.Location) {
			d.Location = where[id]
		}
	}
	var out []Dependency
	for _, d := range merged {
		if len(d.Location) > maxPNPMLocation {
			d.Location = d.Key // the server refuses a longer one; the name and version still say what it is
		}
		out = append(out, *d)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Key < out[b].Key })
	return Reading{Dependencies: out}, nil
}

// pnpmLockDocument is the lockfile proper: the last YAML document in the file.
//
// ⚠️ A pnpm-lock.yaml CAN HOLD TWO DOCUMENTS (pnpm.io/lockfile): an "env" document first, with the
// pnpm version and config dependencies the project resolved, then "---" and the lockfile. Reading
// only the first, as yaml.Unmarshal does, reads the env document and finds no dependencies, which
// pnpm's docs warn is how a tool comes to report a project clean. pnpm says to take the last one.
func pnpmLockDocument(data []byte) (pnpmLock, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var last pnpmLock
	found := false
	for {
		var doc pnpmLock
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return pnpmLock{}, err
		}
		last, found = doc, true
	}
	if !found {
		return pnpmLock{}, errors.New("empty file, so nothing to check")
	}
	return last, nil
}

// maxPNPMLocation is the server's MaxDependencyPathLength, which the plugin can't import.
const maxPNPMLocation = 1024

type pnpmLock struct {
	LockfileVersion yaml.Node               `yaml:"lockfileVersion"`
	Importers       map[string]pnpmImporter `yaml:"importers"`
	pnpmImporter    `yaml:",inline"`        // a project with no workspaces lists its dependencies at the top (5.x, 6.0)
	Packages        map[string]pnpmPackage  `yaml:"packages"`
	Snapshots       map[string]pnpmSnapshot `yaml:"snapshots"` // 9.0: each copy's dependencies
}

type pnpmImporter struct {
	Dependencies         map[string]pnpmRef `yaml:"dependencies"`
	DevDependencies      map[string]pnpmRef `yaml:"devDependencies"`
	OptionalDependencies map[string]pnpmRef `yaml:"optionalDependencies"`
}

// pnpmRef is an importer's entry for one dependency: the version alone (5.x), or {specifier,
// version} (6.0 and 9.0).
type pnpmRef struct{ Version string }

func (r *pnpmRef) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		r.Version = n.Value
		return nil
	}
	var v struct {
		Version string `yaml:"version"`
	}
	if err := n.Decode(&v); err != nil {
		return err
	}
	r.Version = v.Version
	return nil
}

type pnpmPackage struct {
	Name       string `yaml:"name"`    // set when the key doesn't say it (a tarball or git source)
	Version    string `yaml:"version"` // likewise
	Resolution struct {
		Integrity string `yaml:"integrity"`
		Tarball   string `yaml:"tarball"`
		Type      string `yaml:"type"` // "git" or "directory": no registry version
	} `yaml:"resolution"`
	Dependencies         map[string]string `yaml:"dependencies"`
	OptionalDependencies map[string]string `yaml:"optionalDependencies"`
}

type pnpmSnapshot struct {
	Dependencies         map[string]string `yaml:"dependencies"`
	OptionalDependencies map[string]string `yaml:"optionalDependencies"`
}

// pnpmNode is one installed copy: a package at a version, with one set of peers.
type pnpmNode struct {
	name, version     string
	registry, private bool
	// requires is what it depends on, by name, as the lockfile writes the reference.
	requires map[string]string
}

func (n *pnpmNode) label() string { return n.name + "@" + n.version }

// pnpmFormat is the layout to read the lockfile by: 5, 6 or 9. The 7.0 of pnpm 9's alphas is read
// by whether it has snapshots (9.0's split of packages from their dependencies), since its layout
// isn't documented; reading a 9.0-shaped file as 6.0 would find the direct dependencies but none of
// what they bring in.
func pnpmFormat(raw string, snapshots bool) (int, error) {
	major, _, _ := strings.Cut(strings.TrimSpace(raw), ".")
	v, err := strconv.Atoi(major)
	switch {
	case err != nil:
		return 0, fmt.Errorf("lockfileVersion %q isn't one pnpm writes", raw)
	case v == 5:
		return 5, nil
	case v == 6:
		return 6, nil
	case v == 7 && snapshots:
		return 9, nil
	case v == 7:
		return 6, nil
	case v == 9:
		return 9, nil
	}
	return 0, fmt.Errorf("lockfileVersion %s isn't supported (pnpm 7 to 10 write 5.x, 6.0 and 9.0)", raw)
}

// pnpmGraph is every installed copy, by its id: the package key without 5.x and 6.0's leading
// slash. In 9.0 a copy is a snapshot, and its name, version and source are its package's.
func pnpmGraph(format int, lock pnpmLock) map[string]*pnpmNode {
	g := map[string]*pnpmNode{}
	add := func(id string, p pnpmPackage, requires ...map[string]string) {
		name, version := pnpmNameVersion(format, id)
		if p.Name != "" {
			name = p.Name
		}
		if p.Version != "" {
			version = p.Version
		}
		n := &pnpmNode{name: name, version: version, registry: true, requires: map[string]string{}}
		switch {
		case p.Resolution.Type != "": // git, or a local directory
			n.registry = false
		case p.Resolution.Tarball != "":
			n.registry = !strings.HasPrefix(p.Resolution.Tarball, "file:")
			n.private = !public(p.Resolution.Tarball)
		}
		for _, r := range requires {
			for k, v := range r {
				n.requires[k] = v
			}
		}
		g[id] = n
	}
	if format == 9 {
		for id, s := range lock.Snapshots {
			add(id, lock.Packages[pnpmBase(id)], s.Dependencies, s.OptionalDependencies)
		}
		return g
	}
	for key, p := range lock.Packages {
		add(strings.TrimPrefix(key, "/"), p, p.Dependencies, p.OptionalDependencies)
	}
	return g
}

// pnpmRefID turns a dependency reference into the id of the copy it points to. A reference is a
// version ("1.2.3", with 5.x's "_peer" or later formats' "(peer@1)"), an alias's own id
// ("/real/1.2.3" in 5.x, "/real@1.2.3" in 6.0, "real@1.2.3" in 9.0), or a local link. ok is false
// for a local link or file: the project's own code, never checked.
func pnpmRefID(format int, name, ref string) (string, bool) {
	if ref == "" || strings.HasPrefix(ref, "link:") || strings.HasPrefix(ref, "file:") || strings.HasPrefix(ref, "workspace:") {
		return "", false
	}
	if strings.HasPrefix(ref, "/") {
		return ref[1:], true // 5.x and 6.0: another package's id (an alias, or a tarball source)
	}
	switch format {
	case 5:
		return name + "/" + ref, true
	case 9:
		if base := pnpmBase(ref); strings.LastIndexByte(base, '@') > 0 && !strings.Contains(base, "://") {
			return ref, true // an alias: the real package's id
		}
	}
	return name + "@" + ref, true
}

// pnpmBase is an id without its peers: "react-dom@18.2.0(react@18.2.0)" is "react-dom@18.2.0".
func pnpmBase(id string) string {
	base, _, _ := strings.Cut(id, "(")
	return base
}

// pnpmNameVersion splits an id: "@scope/name/1.2.3_peer" (5.x) or "@scope/name@1.2.3(peer)" (6.0,
// 9.0). Peers are dropped: they choose a copy, not a version. A source that isn't a version (a git
// or tarball id) gives what the package entry's own name and version replace.
func pnpmNameVersion(format int, id string) (name, version string) {
	if format == 5 {
		i := strings.LastIndexByte(id, '/')
		if i <= 0 {
			return id, ""
		}
		version, _, _ = strings.Cut(id[i+1:], "_")
		return id[:i], version
	}
	base := pnpmBase(id)
	if i := strings.LastIndexByte(base, '@'); i > 0 {
		return base[:i], base[i+1:]
	}
	return base, ""
}

// pnpmOwnScope is the project's own npm scope ("@acme"), from its package.json name ("@acme/app"),
// or "" when it has none. A package in it is the company's own, published to a registry the
// lockfile doesn't name, so it's never sent. A package.json that's missing, refused or unreadable
// gives no scope: the lockfile's own signals still apply.
type pnpmOwnScope string

func pnpmScope(companions Companions) pnpmOwnScope {
	c, ok := companions["package.json"]
	if !ok || c.Err != nil {
		return ""
	}
	var pkg struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(c.Data, &pkg) != nil || !strings.HasPrefix(pkg.Name, "@") {
		return ""
	}
	scope, _, ok := strings.Cut(pkg.Name, "/")
	if !ok {
		return ""
	}
	return pnpmOwnScope(scope)
}

func (s pnpmOwnScope) owns(name string) bool {
	return s != "" && strings.HasPrefix(name, string(s)+"/")
}

// sortedKeys is m's keys in order, so a walk (and the shortest path it finds) is the same every run.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
