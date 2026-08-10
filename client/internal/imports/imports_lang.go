package imports

import (
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

// Each <lang>Context returns repo-relative candidate paths the changed file
// imports AND references in its added code. Candidates need not exist — safeRead
// (in Resolve) Lstat-checks and drops anything missing/secret/symlinked — so the
// parsers stay generous and simple. Gating (a brought-in symbol must appear in the
// added code's identifier set `refs`) is what keeps self-contained turns free.

// ---- Python ----

var (
	pyFromRe   = regexp.MustCompile(`(?m)^[ \t]*from[ \t]+(\.*[\w.]*)[ \t]+import[ \t]+(.+)$`)
	pyImportRe = regexp.MustCompile(`(?m)^[ \t]*import[ \t]+([\w.]+)(?:[ \t]+as[ \t]+(\w+))?`)
)

func pythonContext(root, relpath, src string, refs map[string]bool) []string {
	dir := path.Dir(norm(relpath))
	var out []string

	for _, m := range pyFromRe.FindAllStringSubmatch(src, -1) {
		module, namesClause := m[1], m[2]
		names := pyNames(namesClause)
		if len(names) == 0 || !anyRef(refs, names...) {
			continue // `import *` (no names) or nothing referenced → skip
		}
		base, rest := pyResolveBase(root, dir, module)
		if rest == "" {
			// `from <pkg> import x`: x is a name in the package OR a submodule.
			out = append(out, join(base, "__init__.py"), base+".py")
			for _, n := range names {
				out = append(out, join(base, n+".py"), join(base, n, "__init__.py"))
			}
		} else {
			modpath := join(base, rest)
			out = append(out, modpath+".py", join(modpath, "__init__.py"))
			for _, n := range names {
				out = append(out, join(modpath, n+".py"))
			}
		}
	}

	for _, m := range pyImportRe.FindAllStringSubmatch(src, -1) {
		module, alias := m[1], m[2]
		segs := strings.Split(module, ".")
		gate := alias
		if gate == "" {
			gate = segs[len(segs)-1] // `import a.b.c` used as `c.func()`; also `a` below
		}
		if !anyRef(refs, gate, segs[0]) {
			continue
		}
		p := strings.Join(segs, "/")
		out = append(out, p+".py", join(p, "__init__.py"))
	}
	return out
}

// pyResolveBase maps a (possibly dotted/relative) Python module spec to a base
// repo-relative dir and the remaining dotted path. Relative specs (leading dots)
// resolve against the changed file's package dir; absolute against the repo root.
func pyResolveBase(root, dir, module string) (base, rest string) {
	if !strings.HasPrefix(module, ".") {
		return "", strings.ReplaceAll(module, ".", "/") // absolute: base is repo root
	}
	dots := len(module) - len(strings.TrimLeft(module, "."))
	base = dir
	for i := 1; i < dots; i++ { // one dot = current package; each extra dot goes up
		base = path.Dir(base)
	}
	rest = strings.ReplaceAll(strings.TrimLeft(module, "."), ".", "/")
	return base, rest
}

func pyNames(clause string) []string {
	clause = strings.TrimSpace(clause)
	clause = strings.Trim(clause, "()")
	if strings.Contains(clause, "*") {
		return nil
	}
	var out []string
	for _, part := range strings.Split(clause, ",") {
		f := strings.Fields(strings.TrimSpace(part)) // "x" or "x as y"
		if len(f) > 0 {
			out = append(out, f[0]) // the imported name (gates the submodule/name file)
			if len(f) == 3 && f[1] == "as" {
				out = append(out, f[2]) // the alias (what the added code actually calls)
			}
		}
	}
	return out
}

// ---- JavaScript / TypeScript ----

var (
	jsImportFromRe = regexp.MustCompile(`(?m)\bimport\s+(.+?)\s+from\s*['"]([^'"]+)['"]`)
	jsExportFromRe = regexp.MustCompile(`(?m)\bexport\s+(?:\*|{[^}]*})\s+from\s*['"]([^'"]+)['"]`)
	jsRequireRe    = regexp.MustCompile(`(?m)\b(?:const|let|var)\s+(.+?)\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)`)
)

var jsExts = []string{".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"}

func jsContext(root, relpath, src string, refs map[string]bool) []string {
	dir := path.Dir(norm(relpath))
	var out []string
	add := func(clause, spec string) {
		if !isRelativeSpec(spec) {
			return // bare specifier → node_modules / built-in, not local
		}
		if clause != "" && !anyRef(refs, identsOf(clause)...) {
			return
		}
		out = append(out, jsCandidates(dir, spec)...)
	}
	for _, m := range jsImportFromRe.FindAllStringSubmatch(src, -1) {
		add(m[1], m[2])
	}
	for _, m := range jsRequireRe.FindAllStringSubmatch(src, -1) {
		add(m[1], m[2])
	}
	for _, m := range jsExportFromRe.FindAllStringSubmatch(src, -1) {
		add("", m[1]) // re-export: no local binding to gate on; include if referenced downstream
	}
	return out
}

func jsCandidates(dir, spec string) []string {
	p := join(dir, spec)
	out := []string{p}
	for _, e := range jsExts {
		out = append(out, p+e)
	}
	for _, e := range jsExts {
		out = append(out, join(p, "index"+e))
	}
	return out
}

func isRelativeSpec(spec string) bool {
	return strings.HasPrefix(spec, "./") || strings.HasPrefix(spec, "../") || strings.HasPrefix(spec, "/")
}

// identsOf pulls the identifiers out of a JS import/require binding clause —
// `Foo`, `{ a, b as c }`, `* as ns`, `Foo, { a }` — minus the `as`/`from` keywords.
func identsOf(clause string) []string {
	var out []string
	for _, t := range identRe.FindAllString(clause, -1) {
		if t != "as" && t != "from" {
			out = append(out, t)
		}
	}
	return out
}

// ---- Java ----

var javaImportRe = regexp.MustCompile(`(?m)^\s*import\s+(static\s+)?([\w.]+)\s*;`)

func javaContext(idx *repoIndex, src string, refs map[string]bool) []string {
	if idx == nil || !idx.ok {
		return nil
	}
	var out []string
	for _, m := range javaImportRe.FindAllStringSubmatch(src, -1) {
		static, fqcn := m[1] != "", m[2]
		segs := strings.Split(fqcn, ".")
		if len(segs) < 2 {
			continue
		}
		// non-static `a.b.Foo` → class Foo; static `a.b.Foo.bar` → class Foo (secondlast), member bar.
		classIdx := len(segs) - 1
		member := ""
		if static {
			classIdx = len(segs) - 2
			member = segs[len(segs)-1]
		}
		class := segs[classIdx]
		if !anyRef(refs, class, member) {
			continue
		}
		suffix := strings.Join(segs[:classIdx+1], "/") + ".java"
		out = append(out, idx.endsWith(suffix)...)
	}
	return out
}

// ---- Go ----

var (
	goSingleImportRe = regexp.MustCompile(`(?m)^\s*import\s+(?:([\w.]+)\s+)?"([^"]+)"`)
	goImportBlockRe  = regexp.MustCompile(`(?s)\bimport\s*\(\s*(.*?)\)`)
	goBlockLineRe    = regexp.MustCompile(`(?m)^\s*(?:([\w.]+)\s+)?"([^"]+)"`)
)

func goContext(idx *repoIndex, src string, refs map[string]bool) []string {
	if idx == nil || !idx.ok || idx.goModule == "" {
		return nil
	}
	type imp struct{ alias, pathSpec string }
	var imps []imp
	for _, m := range goSingleImportRe.FindAllStringSubmatch(src, -1) {
		imps = append(imps, imp{m[1], m[2]})
	}
	for _, blk := range goImportBlockRe.FindAllStringSubmatch(src, -1) {
		for _, m := range goBlockLineRe.FindAllStringSubmatch(blk[1], -1) {
			imps = append(imps, imp{m[1], m[2]})
		}
	}

	var out []string
	for _, im := range imps {
		if im.pathSpec != idx.goModule && !strings.HasPrefix(im.pathSpec, idx.goModule+"/") {
			continue // third-party / stdlib
		}
		pkgName := im.alias
		if pkgName == "" || pkgName == "." {
			pkgName = path.Base(im.pathSpec) // import name defaults to last path segment
		}
		if pkgName != "_" && pkgName != "." && !refs[pkgName] {
			continue
		}
		dir := strings.TrimPrefix(im.pathSpec, idx.goModule)
		dir = strings.TrimPrefix(dir, "/")
		out = append(out, idx.goPackageFiles(dir)...)
	}
	return out
}

// ---- C# ----

var (
	csUsingRe = regexp.MustCompile(`(?m)^\s*using\s+(?:static\s+)?[\w.]+\s*;`)
	csTypeRe  = regexp.MustCompile(`\b([A-Z][A-Za-z0-9_]*)\b`)
)

// C# namespaces don't map structurally to files, so this is best-effort: when the
// changed file is namespaced (`using …;` present), pull the conventionally-named
// file `<Type>.cs` for each PascalCase type the added code references. One class
// per file named after the class is the dominant C# convention.
func csContext(idx *repoIndex, src string, refs map[string]bool) []string {
	if idx == nil || !idx.ok || !csUsingRe.MatchString(src) {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for t := range refs {
		if seen[t] || len(t) == 0 || t[0] < 'A' || t[0] > 'Z' {
			continue // gate already used refs; here we only need the PascalCase subset
		}
		if !csTypeRe.MatchString(t) {
			continue
		}
		seen[t] = true
		out = append(out, idx.byBase(t+".cs")...)
	}
	return out
}

// ---- repo index (Java / Go / C#) ----

// repoIndex is a one-time listing of in-repo source files, built lazily the first
// time an index-based language (Java/Go/C#) needs it. ok=false when the tree is
// pathologically large (> maxIndexFiles) — those languages then resolve nothing
// rather than walk forever (graceful degradation, never a hang on the dev's path).
type repoIndex struct {
	ok       bool
	files    []string // repo-relative, slash form
	goModule string
}

var indexSkipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, "__pycache__": true,
	".venv": true, "venv": true, "dist": true, "build": true, "target": true,
	"bin": true, "obj": true, ".next": true, "out": true,
}

var indexExts = map[string]bool{
	".py": true, ".js": true, ".jsx": true, ".mjs": true, ".cjs": true,
	".ts": true, ".tsx": true, ".java": true, ".go": true, ".cs": true,
}

func buildIndex(root string) *repoIndex {
	idx := &repoIndex{ok: true}
	if mod := readGoModule(root); mod != "" {
		idx.goModule = mod
	}
	n := 0
	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if p != root && indexSkipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !indexExts[strings.ToLower(filepath.Ext(d.Name()))] {
			return nil
		}
		n++
		if n > maxIndexFiles {
			idx.ok = false
			return filepath.SkipAll
		}
		if rel, err := filepath.Rel(root, p); err == nil {
			idx.files = append(idx.files, filepath.ToSlash(rel))
		}
		return nil
	})
	if !idx.ok {
		idx.files = nil
	}
	return idx
}

func readGoModule(root string) string {
	b, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "module ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "module "))
		}
	}
	return ""
}

func (i *repoIndex) endsWith(suffix string) []string {
	var out []string
	for _, f := range i.files {
		if f == suffix || strings.HasSuffix(f, "/"+suffix) {
			out = append(out, f)
		}
	}
	return out
}

func (i *repoIndex) byBase(base string) []string {
	var out []string
	for _, f := range i.files {
		if path.Base(f) == base {
			out = append(out, f)
		}
	}
	return out
}

func (i *repoIndex) goPackageFiles(dir string) []string {
	dir = strings.Trim(dir, "/")
	var out []string
	for _, f := range i.files {
		if path.Dir(f) != dir || filepath.Ext(f) != ".go" || strings.HasSuffix(f, "_test.go") {
			continue
		}
		out = append(out, f)
	}
	return out
}

// join builds a slash repo-relative path, cleaning ".." segments.
func join(elems ...string) string {
	return path.Clean(path.Join(elems...))
}
