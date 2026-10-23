package deps

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// NPM reads package-lock.json (and npm-shrinkwrap.json, the same format published with a
// package): what npm installed.
type NPM struct{}

func (NPM) Ecosystem() string    { return "npm" }
func (NPM) Files() []string      { return []string{"package-lock.json", "npm-shrinkwrap.json"} }
func (NPM) Companions() []string { return nil }

// publicRegistries are the hosts whose packages are known to be public npm packages. Anything
// else (another registry, a company mirror that proxies npm, no recorded source) may hold
// private packages. A mirror can't be told apart from a private registry by its URL, so it
// counts as private: that fails safe.
var publicRegistries = []string{"https://registry.npmjs.org/", "https://registry.yarnpkg.com/"}

func public(resolved string) bool {
	for _, r := range publicRegistries {
		if strings.HasPrefix(resolved, r) {
			return true
		}
	}
	return false
}

// fromRegistry says whether an entry has a registry version worth checking: anything but a git
// checkout or a local file. Registries lay out tarball URLs differently (GitHub Packages uses
// /download/<name>/<version>/<hash>), so the URL's shape isn't checked.
func fromRegistry(resolved string) bool {
	return !strings.HasPrefix(resolved, "git") && !strings.HasPrefix(resolved, "file:")
}

// Read returns every installed registry package in the lockfile, with direct ones marked:
//   - the name is the text after the last "node_modules/" in the entry's key, so scoped
//     (node_modules/@scope/pkg) and nested (node_modules/a/node_modules/b) entries work, and an
//     entry installed under an npm alias carries the real package in "name";
//   - "link": true entries are the repo's own workspace packages, and entries resolved from git
//     or a local file have no registry version: both are left out;
//   - a package is direct when an importer (the root, or a workspace folder) lists it and it
//     resolves to that copy, as Node would load it;
//   - a package not downloaded from the public registry is marked private.
//
// A lockfile with no "packages" section (lockfileVersion 1, npm 6 and earlier) is an error:
// reading it as empty would report a vulnerable project as clean.
func (NPM) Read(data []byte, _ Companions) (Reading, error) {
	g, err := readNPMGraph(data)
	if err != nil {
		return Reading{}, err
	}
	direct := map[string]bool{}
	for _, n := range g {
		if !n.importer {
			continue
		}
		for _, r := range n.requires {
			if r.kind != "peer" && r.location != "" {
				direct[r.location] = true
			}
		}
	}
	var out []Dependency
	for _, n := range g {
		if n.importer || !n.registry || n.version == "" {
			continue
		}
		out = append(out, Dependency{Ecosystem: "npm", Name: n.name, Version: n.version, Location: n.location, Key: n.location,
			Indirect: !direct[n.location], Dev: n.dev, DevOptional: n.devOptional, Private: n.private})
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Location < out[b].Location })
	return Reading{Dependencies: out}, nil
}

// npmNode is one installed copy of a package, or an importer: the project itself ("") or one of
// its workspaces.
type npmNode struct {
	location, name, version string
	importer, dev           bool
	devOptional             bool
	registry, private       bool
	requires                []npmRequirement
}

// npmRequirement is one dependency a node declares, and the copy it resolves to ("" when none is
// installed: a skipped optional or peer dependency).
type npmRequirement struct {
	name, kind, location string
}

type npmEntry struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Resolved             string            `json:"resolved"`
	Link                 bool              `json:"link"`
	Dev                  bool              `json:"dev"`         // npm: only reached through devDependencies
	DevOptional          bool              `json:"devOptional"` // npm: only reached through devDependencies or optionalDependencies
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
}

// readNPMGraph builds who-requires-whom from the lockfile. Only an importer's devDependencies
// count: a package's own devDependencies are never installed.
func readNPMGraph(data []byte) (map[string]*npmNode, error) {
	var lock struct {
		LockfileVersion int                 `json:"lockfileVersion"`
		Packages        map[string]npmEntry `json:"packages"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}
	if lock.Packages == nil {
		if lock.LockfileVersion == 1 {
			return nil, fmt.Errorf(`lockfileVersion 1 isn't supported (written by npm 6 or earlier); running "npm install" with npm 7 or later upgrades it`)
		}
		return nil, fmt.Errorf(`no "packages" section, so nothing to check (lockfileVersion %d)`, lock.LockfileVersion)
	}
	g := map[string]*npmNode{}
	for key, p := range lock.Packages {
		if p.Link {
			continue // a link to a workspace folder; the folder has its own entry
		}
		n := &npmNode{location: key, dev: p.Dev, devOptional: p.DevOptional && !p.Dev, registry: fromRegistry(p.Resolved), private: !public(p.Resolved)}
		sections := []struct {
			kind string
			deps map[string]string
		}{{"prod", p.Dependencies}, {"optional", p.OptionalDependencies}, {"peer", p.PeerDependencies}}
		if i := strings.LastIndex(key, "node_modules/"); i >= 0 {
			n.name = key[i+len("node_modules/"):] // the folder name: what it's required under
			if p.Name != "" {
				n.name = p.Name // installed under an npm alias: the real package
			}
			n.version = p.Version
		} else {
			n.importer, n.name = true, p.Name
			sections = append(sections, struct {
				kind string
				deps map[string]string
			}{"dev", p.DevDependencies})
		}
		for _, sec := range sections {
			for name := range sec.deps {
				n.requires = append(n.requires, npmRequirement{name: name, kind: sec.kind})
			}
		}
		sort.Slice(n.requires, func(a, b int) bool { return n.requires[a].name < n.requires[b].name })
		g[key] = n
	}
	for _, n := range g {
		for i, r := range n.requires {
			n.requires[i].location = resolveNPM(g, n.location, r.name)
		}
	}
	return g, nil
}

// resolveNPM finds the copy of name that the package (or importer) at from gets, by Node's rule:
// node_modules/<name> in from's own folder, then in each folder above it, up to the project
// root. Folders named node_modules are skipped (they hold packages, not a node_modules of their
// own). "" when no copy is installed.
func resolveNPM(g map[string]*npmNode, from, name string) string {
	for dir := from; ; {
		if dir == "" || !strings.HasSuffix(dir, "node_modules") {
			loc := "node_modules/" + name
			if dir != "" {
				loc = dir + "/" + loc
			}
			if _, ok := g[loc]; ok {
				return loc
			}
		}
		if dir == "" {
			return ""
		}
		if i := strings.LastIndexByte(dir, '/'); i >= 0 {
			dir = dir[:i]
		} else {
			dir = ""
		}
	}
}
