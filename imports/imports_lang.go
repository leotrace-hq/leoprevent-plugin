package imports

import (
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/leotrace-hq/leoprevent-plugin/pathgate"
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

func pythonContext(source Source, relpath, src string, refs map[string]bool) []candidate {
	dir := path.Dir(norm(relpath))
	var out []candidate

	for _, m := range pyFromRe.FindAllStringSubmatch(src, -1) {
		module, namesClause := m[1], m[2]
		names := pyNames(namesClause)
		if len(names) == 0 || !anyRef(refs, names...) {
			continue // `import *` (no names) or nothing referenced → skip
		}
		base, rest := pyResolveBase(dir, module)
		if rest == "" {
			// `from <pkg> import x`: x is a name in the package OR a submodule.
			out = append(out, namedCandidates(join(base, "__init__.py"), base+".py")...)
			for _, n := range names {
				out = append(out, namedCandidates(join(base, n+".py"), join(base, n, "__init__.py"))...)
			}
		} else {
			modpath := join(base, rest)
			out = append(out, namedCandidates(modpath+".py", join(modpath, "__init__.py"))...)
			for _, n := range names {
				out = append(out, namedCandidates(join(modpath, n+".py"))...)
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
		// `import pkg.mod` names a MODULE, not a symbol in it.
		out = append(out, moduleCandidates(p+".py", join(p, "__init__.py"))...)
	}
	return out
}

// pyResolveBase maps a (possibly dotted/relative) Python module spec to a base
// repo-relative dir and the remaining dotted path. Relative specs (leading dots)
// resolve against the changed file's package dir; absolute against the repo root.
func pyResolveBase(dir, module string) (base, rest string) {
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

// jsClause is a binding clause — `Foo`, `{ a, b as c }`, `* as ns`, `type { A }` — and
// is deliberately a CHARACTER CLASS rather than `.+?`. It has to cross newlines, because
// a Prettier-formatted codebase breaks any import of three or more names across lines and
// `.` stops at one (LEO-376: every multi-line import went unresolved, so a helper's guards
// never reached the judge and the call into it was flagged as unguarded, turn after turn).
// It must NOT cross statements, and no quote, `;`, `=` or paren can appear in a clause,
// so bounding it this way is what keeps a side-effect import from gluing onto the next
// line's `from`.
//
// Since LEO-378 these three patterns are only the fallback for a file the lexer rejects
// (jsImportsRegex); jsImportsOf reads imports off tokens.
const jsClause = `([\w$*{},\s]+?)`

var (
	jsImportFromRe = regexp.MustCompile(`\bimport\s+` + jsClause + `\s+from\s*['"]([^'"]+)['"]`)
	jsExportFromRe = regexp.MustCompile(`(?m)\bexport\s+(?:\*|{[^}]*})\s+from\s*['"]([^'"]+)['"]`)
	jsRequireRe    = regexp.MustCompile(`\b(?:const|let|var)\s+` + jsClause + `\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)`)
)

var jsExts = []string{".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"}

// inlineTypeRe matches a per-binding `type` modifier inside a named import clause —
// `{ type Event, loadRecords }` — so only the value bindings gate the file.
var inlineTypeRe = regexp.MustCompile(`\btype\s+[A-Za-z_$][\w$]*\s*,?`)

func jsContext(source Source, relpath, src, added string, refs map[string]bool, workspaces *workspaceResolver) []candidate {
	dir := path.Dir(norm(relpath))
	var config *tsConfig
	var out []candidate
	add := func(clause, spec, mode string) {
		if clause != "" && !anyRef(refs, identsOf(clause)...) {
			return
		}
		if !isRelativeSpec(spec) {
			if config == nil {
				loaded := nearestTSConfig(source, dir)
				config = &loaded
			}
			candidates := config.candidates(source, spec)
			if len(candidates) == 0 && !config.matches(spec) {
				candidates = workspaces.candidates(dir, spec, mode, identsOf(clause)...)
			}
			out = append(out, labelled(clause != "", candidates)...)
			return
		}
		// A binding clause names symbols; a bare `export * from` does not.
		out = append(out, labelled(clause != "", jsCandidates(source, dir, spec))...)
	}
	imps, ok := jsImportsOf(src, jsxAllowed(relpath))
	if !ok {
		imps = jsImportsRegex(src) // the file did not lex: resolve as before rather than less
	}
	for _, im := range imps {
		switch {
		case im.reexport:
			add("", im.spec, im.mode) // re-export: no local binding to gate on; include if referenced downstream
		case im.dynamic && im.clause == "":
			// An unassigned `import('./x')` (a lazy route, a `.then`) binds nothing to
			// gate on. It resolves only when the added code wrote the specifier itself,
			// the literal reading of "referenced in the added code"; otherwise every
			// turn touching a router would pull every lazy route behind it.
			if strings.Contains(added, im.spec) {
				add("", im.spec, im.mode)
			}
		case im.typed:
			if clause := valueOnly(im.clause); strings.TrimSpace(strings.Trim(clause, "{}, ")) != "" {
				add(clause, im.spec, im.mode)
			}
		default:
			add(im.clause, im.spec, im.mode)
		}
	}
	return out
}

// valueOnly drops the TypeScript type-only bindings from an import clause.
func valueOnly(clause string) string {
	// A TYPE-ONLY import brings nothing into the running program: TypeScript
	// erases it, so the changed code cannot call through it and the file behind
	// it cannot hold a sink this diff reaches. Dropping those bindings is the
	// same gate the resolver already applies, applied to a binding that provably
	// cannot be reached, not a guess about relevance. It matters because a
	// TypeScript codebase's types live in big declaration modules: pulling one to
	// judge a change that merely names a shape is the single most expensive thing
	// this resolver used to do, and there is no vulnerability to find in it.
	//
	// `import type { A } from …` drops whole; `import { type A, b } from …` keeps
	// b and drops A. A clause that ends up empty is not resolved at all.
	if !skipTypeOnlyImports {
		return clause
	}
	c := strings.TrimSpace(clause)
	if c == "type" || strings.HasPrefix(c, "type ") || strings.HasPrefix(c, "type{") {
		return ""
	}
	return inlineTypeRe.ReplaceAllString(clause, "")
}

// jsImportsRegex is the regex extractor jsImportsOf replaced (LEO-378), kept as the
// fallback for a file the lexer rejects, so a lexer gap never resolves less than before.
// It cannot tell code from a comment or a string, which is why it is no longer first.
func jsImportsRegex(src string) []jsImport {
	var out []jsImport
	for _, m := range jsImportFromRe.FindAllStringSubmatch(src, -1) {
		out = append(out, jsImport{clause: m[1], spec: m[2], mode: "import", typed: true})
	}
	for _, m := range jsRequireRe.FindAllStringSubmatch(src, -1) {
		out = append(out, jsImport{clause: m[1], spec: m[2], mode: "require"})
	}
	for _, m := range jsExportFromRe.FindAllStringSubmatch(src, -1) {
		out = append(out, jsImport{spec: m[1], mode: "import", reexport: true})
	}
	return out
}

// jsSiblingExts maps an EMITTED JavaScript extension to the TypeScript extensions that
// compile to it. TypeScript's NodeNext/ESM convention is that the SOURCE carries the
// emitted specifier — `./authorize.js` for a file that is `authorize.ts` on disk — and
// tsc rewrites nothing, so in any `"module": "nodenext"` project the path the specifier
// names does not exist. Appending extensions cannot recover it: that yields
// `authorize.js.ts`. The specifier's own extension has to be swapped instead.
var jsSiblingExts = map[string][]string{
	".js":  {".ts", ".tsx"},
	".jsx": {".tsx"},
	".mjs": {".mts"},
	".cjs": {".cts"},
}

func jsCandidates(source Source, dir, spec string) []string {
	p := join(dir, spec)
	out := []string{p}
	for _, e := range jsExts {
		out = append(out, p+e)
	}
	// Only when the literal path resolves to nothing. Pass 2 reads EVERY candidate that
	// exists rather than stopping at the first, so an unguarded remap would pull both
	// `x.js` and `x.ts` wherever a repo holds the two side by side — spending egress on a
	// file the changed code provably does not run.
	if siblings, ok := jsSiblingExts[path.Ext(p)]; ok {
		if _, exists := source.Read(p); !exists {
			stem := strings.TrimSuffix(p, path.Ext(p))
			for _, e := range siblings {
				out = append(out, stem+e)
			}
		}
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

func javaContext(idx *repoIndex, src string, refs map[string]bool) []candidate {
	if idx == nil || !idx.ok {
		return nil
	}
	var out []candidate
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
		out = append(out, namedCandidates(idx.endsWith(suffix)...)...)
	}
	return out
}

// ---- Go ----

var (
	goSingleImportRe = regexp.MustCompile(`(?m)^\s*import\s+(?:([\w.]+)\s+)?"([^"]+)"`)
	goImportBlockRe  = regexp.MustCompile(`(?s)\bimport\s*\(\s*(.*?)\)`)
	goBlockLineRe    = regexp.MustCompile(`(?m)^\s*(?:([\w.]+)\s+)?"([^"]+)"`)
)

func goContext(idx *repoIndex, src string, refs map[string]bool) []candidate {
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

	var out []candidate
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
		// A Go import names a PACKAGE and pulls every file in it, so no individual
		// file here was claimed to define anything the added code wrote.
		out = append(out, moduleCandidates(idx.goPackageFiles(dir)...)...)
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
func csContext(idx *repoIndex, src string, refs map[string]bool) []candidate {
	if idx == nil || !idx.ok || !csUsingRe.MatchString(src) {
		return nil
	}
	var out []candidate
	seen := map[string]bool{}
	for t := range refs {
		if seen[t] || len(t) == 0 || t[0] < 'A' || t[0] > 'Z' {
			continue // gate already used refs; here we only need the PascalCase subset
		}
		if !csTypeRe.MatchString(t) {
			continue
		}
		seen[t] = true
		out = append(out, namedCandidates(idx.byBase(t+".cs")...)...)
	}
	return out
}

// ---- C / C++ ----

var cIncludeRe = regexp.MustCompile(`(?m)^[ \t]*#[ \t]*include[ \t]*([<"])([^>"\n]+)[>"]`)

// cSourceExts are where a header's definitions live, tried in this order.
var cSourceExts = []string{".c", ".cc", ".cpp", ".cxx", ".c++"}

// cHeaderExts are the headers that DECLARE and leave the definitions to a source
// file. An .inl or .ipp holds inline definitions itself, so it has no sibling to find.
var cHeaderExts = map[string]bool{".h": true, ".hh": true, ".hpp": true, ".hxx": true, ".h++": true}

// An #include names a file, never a symbol, so the gate cannot be read off the
// include line the way Java's class name or Python's imported name is. Each in-repo
// header is read for what it DECLARES (prototypes, macros, tags, typedefs, enum
// constants, externs) and pulled only when the added code writes one of those names.
//
// A header holds declarations, and the sink is usually in the definition. So when the
// added code names a FUNCTION the header declares, the file defining it rides along,
// found by file name alone:
//   - the source file beside the header (foo.h → foo.c), or else the one file anywhere
//     in the repository with that base name (include/lib/foo.h → src/foo.c); an
//     ambiguous base name resolves to nothing rather than to a guess;
//   - a source file named after the function itself (ares_init → ares_init.c), the
//     nearest one when several match.
//
// There is deliberately no search by symbol: no file's contents are read to find a
// definition. That is the posture of every other language here (Java's class path,
// C#'s type file name, Go's package directory), and LEO-723 measured what it costs
// on call sites in real C (definitions located by cSpans and, separately, by ctags):
// 98% found in libming, 89-92% in libjpeg-turbo, but 44-57% in c-ares and 17-18% in
// gpac, where one umbrella header is implemented across a directory no file name
// points to. Those misses are accepted rather than paid for with a symbol index.
//
// Copied-in libraries (third_party/, external/, deps/ …) are dropped through
// pathgate.IsVendored: a header the repository carries for someone else's library is
// not ours to send.
func cContext(source Source, getIdx func() *repoIndex, relpath, src string, refs map[string]bool) []candidate {
	dir := path.Dir(norm(relpath))
	var out []candidate
	seen := map[string]bool{}
	for _, m := range cIncludeRe.FindAllStringSubmatch(src, -1) {
		hdr := cResolveInclude(source, getIdx, dir, m[1] == `"`, strings.TrimSpace(m[2]))
		if hdr == "" || seen[hdr] || pathgate.IsVendored(hdr) {
			continue
		}
		seen[hdr] = true
		body, ok := source.Read(hdr)
		if !ok {
			continue
		}
		names, funcs := cDeclared(body)
		if !anyRef(refs, names...) {
			continue
		}
		out = append(out, namedCandidates(hdr)...)
		if !anyRef(refs, funcs...) {
			continue // a macro or a type was named: the header is the whole answer
		}
		if def := cDefinitionFile(source, getIdx, hdr); def != "" && !pathgate.IsVendored(def) {
			out = append(out, namedCandidates(def)...)
		}
		for _, fn := range funcs {
			if !refs[fn] {
				continue
			}
			if def := cFunctionFile(getIdx, dir, fn); def != "" && !pathgate.IsVendored(def) {
				out = append(out, namedCandidates(def)...)
			}
		}
	}
	return out
}

// cFunctionFile returns the source file named after function fn, nearest to dir, or "".
func cFunctionFile(getIdx func() *repoIndex, dir, fn string) string {
	idx := getIdx()
	if idx == nil || !idx.ok {
		return ""
	}
	var found []string
	for _, e := range cSourceExts {
		found = append(found, idx.byBase(fn+e)...)
	}
	return nearest(found, dir)
}

// cResolveInclude maps an include to a repo-relative header, or "". A quoted include
// is tried next to the including file first, as the compiler does. Otherwise (an
// angle include, or a quoted one found through an -I path) the repo index is matched
// by path suffix, which stands in for the -I paths a build would pass: a system header
// is not in the repository, so it matches nothing.
func cResolveInclude(source Source, getIdx func() *repoIndex, dir string, quoted bool, spec string) string {
	if spec == "" {
		return ""
	}
	if quoted {
		if p := join(dir, spec); source.Exists(p) {
			return p
		}
	}
	idx := getIdx()
	if idx == nil || !idx.ok {
		return ""
	}
	return nearest(idx.endsWith(norm(spec)), dir)
}

// cDefinitionFile returns the source file that defines what header hdr declares, or "".
func cDefinitionFile(source Source, getIdx func() *repoIndex, hdr string) string {
	ext := path.Ext(hdr)
	if !cHeaderExts[strings.ToLower(ext)] {
		return ""
	}
	stem := strings.TrimSuffix(hdr, ext)
	for _, e := range cSourceExts {
		if source.Exists(stem + e) {
			return stem + e
		}
	}
	idx := getIdx()
	if idx == nil || !idx.ok {
		return ""
	}
	var found []string
	for _, e := range cSourceExts {
		found = append(found, idx.byBase(path.Base(stem)+e)...)
	}
	if len(found) != 1 {
		return ""
	}
	return found[0]
}

// nearest picks the candidate closest to dir: the most leading directories shared,
// then the shortest path, then the first by name. A suffix like config.h can match
// one file per subproject, and the one beside the including file is the one it means.
func nearest(cands []string, dir string) string {
	best, bestShared := "", -1
	for _, c := range cands {
		shared := sharedDirs(path.Dir(c), dir)
		switch {
		case shared > bestShared,
			shared == bestShared && len(c) < len(best),
			shared == bestShared && len(c) == len(best) && c < best:
			best, bestShared = c, shared
		}
	}
	return best
}

func sharedDirs(a, b string) int {
	if a == "." || b == "." {
		return 0
	}
	as, bs := strings.Split(a, "/"), strings.Split(b, "/")
	n := 0
	for n < len(as) && n < len(bs) && as[n] == bs[n] {
		n++
	}
	return n
}

var (
	cDefineRe     = regexp.MustCompile(`(?m)^[ \t]*#[ \t]*define[ \t]+([A-Za-z_]\w*)`)
	cTagRe        = regexp.MustCompile(`\b(?:struct|union|enum|class|namespace)\s+([A-Za-z_]\w*)`)
	cTypedefEndRe = regexp.MustCompile(`}\s*([A-Za-z_]\w*)\s*[;,\[]`)
	cTypedefRe    = regexp.MustCompile(`\btypedef\b[^;{]*?([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*;`)
	cFuncPtrRe    = regexp.MustCompile(`\(\s*\*\s*([A-Za-z_]\w*)\s*\)`)
	cEnumConstRe  = regexp.MustCompile(`^\s*([A-Za-z_]\w*)\s*(?:=|,|$)`)
	cExternRe     = regexp.MustCompile(`^\s*extern\b[^(;]*?([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*;`)
)

// cDeclared returns the names a header declares, and the subset that are functions.
//
// It reads code, not comments, and only the declaration level of the file: names used
// inside an inline function's body or written as a struct's field are not things the
// header provides, and gating on them would pull a header for every `len` or `memcpy`.
// It is still generous where it cannot tell (a macro call in a prototype's position
// reads as a function), and the judge prunes context that turns out unrelated.
func cDeclared(body string) (names, funcs []string) {
	lines := strings.Split(body, "\n")
	sc := cScan(lines)
	add := func(dst *[]string, n string) {
		if n != "" && !controlKeyword[n] && !cKeyword[n] {
			*dst = append(*dst, n)
		}
	}
	for _, m := range cDefineRe.FindAllStringSubmatch(body, -1) {
		add(&names, m[1])
	}
	for i, code := range sc.code {
		if strings.TrimSpace(code) == "" {
			continue
		}
		for _, m := range cTagRe.FindAllStringSubmatch(code, -1) {
			add(&names, m[1])
		}
		for _, m := range cTypedefEndRe.FindAllStringSubmatch(code, -1) {
			add(&names, m[1])
		}
		if strings.Contains(code, "typedef") {
			for _, m := range cTypedefRe.FindAllStringSubmatch(code, -1) {
				add(&names, m[1])
			}
			for _, m := range cFuncPtrRe.FindAllStringSubmatch(code, -1) {
				add(&names, m[1])
			}
		}
		switch {
		case sc.enum[i]:
			if m := cEnumConstRe.FindStringSubmatch(code); m != nil {
				add(&names, m[1])
			}
		case sc.top[i]:
			if m := cExternRe.FindStringSubmatch(code); m != nil {
				add(&names, m[1])
			}
			if n, ok := cDeclName(code); ok {
				add(&funcs, n)
			}
		}
	}
	return append(names, funcs...), funcs
}

// ---- repo index (Java / Go / C#, and the C/C++ fallback) ----

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
	".c": true, ".h": true, ".cc": true, ".cpp": true, ".cxx": true, ".c++": true,
	".hh": true, ".hpp": true, ".hxx": true, ".h++": true, ".inl": true, ".ipp": true,
}

func buildIndex(source Source) *repoIndex {
	idx := &repoIndex{ok: true}
	if mod := readGoModule(source); mod != "" {
		idx.goModule = mod
	}
	idx.files = source.Paths()
	if len(idx.files) == 0 {
		idx.ok = false
	}
	if !idx.ok {
		idx.files = nil
	}
	return idx
}

func readGoModule(source Source) string {
	body, ok := source.Read("go.mod")
	if !ok {
		return ""
	}
	for _, line := range strings.Split(body, "\n") {
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
