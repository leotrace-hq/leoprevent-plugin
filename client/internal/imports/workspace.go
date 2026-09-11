package imports

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Workspace discovery is local metadata only, cached for one Resolve call. Never
// follow node_modules links or enumerate a registry dependency as source context.
type workspaceResolver struct {
	root     string
	loaded   bool
	packages map[string]*workspacePackage
	members  map[string]bool
}
type workspacePackage struct {
	dir                  string
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Main                 string            `json:"main"`
	Exports              json.RawMessage   `json:"exports"`
	Workspaces           json.RawMessage   `json:"workspaces"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}

func readWorkspacePackage(root, dir string) (*workspacePackage, bool) {
	body, ok := safeRead(root, join(dir, "package.json"))
	if !ok || len(body) > 1024*1024 {
		return nil, false
	}
	var p workspacePackage
	if json.Unmarshal([]byte(body), &p) != nil {
		return nil, false
	}
	p.dir = dir
	return &p, true
}
func (w *workspaceResolver) load() {
	if w.loaded {
		return
	}
	w.loaded = true
	w.packages = map[string]*workspacePackage{}
	w.members = map[string]bool{".": true}
	var patterns []string
	if p, ok := readWorkspacePackage(w.root, "."); ok {
		if json.Unmarshal(p.Workspaces, &patterns) != nil {
			var obj struct {
				Packages []string `json:"packages"`
			}
			if json.Unmarshal(p.Workspaces, &obj) == nil {
				patterns = obj.Packages
			}
		}
	}
	if body, ok := safeRead(w.root, "pnpm-workspace.yaml"); ok {
		var cfg struct {
			Packages []string `yaml:"packages"`
		}
		if len(body) > 1024*1024 || yaml.Unmarshal([]byte(body), &cfg) != nil {
			return
		}
		patterns = cfg.Packages
	}
	if len(patterns) == 0 {
		return
	}
	count := 0
	err := filepath.WalkDir(w.root, func(abs string, d fs.DirEntry, err error) error {
		count++
		if count > maxIndexFiles {
			return fs.ErrInvalid
		}
		if err != nil {
			return err
		}
		rel, e := filepath.Rel(w.root, abs)
		if e != nil {
			return e
		}
		rel = filepath.ToSlash(rel)
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		if d.IsDir() {
			if rel != "." && (strings.HasPrefix(d.Name(), ".") || d.Name() == "node_modules" || d.Name() == "vendor") {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() != "package.json" || rel == "package.json" {
			return nil
		}
		dir := path.Dir(rel)
		included := false
		for _, p := range patterns {
			if !strings.HasPrefix(p, "!") && workspaceMatch(p, dir) {
				included = true
			}
		}
		for _, p := range patterns {
			if strings.HasPrefix(p, "!") && workspaceMatch(p[1:], dir) {
				included = false
			}
		}
		if !included {
			return nil
		}
		p, ok := readWorkspacePackage(w.root, dir)
		if !ok || p.Name == "" {
			return nil
		}
		w.members[dir] = true
		if _, duplicate := w.packages[p.Name]; duplicate {
			w.packages[p.Name] = nil
		} else {
			w.packages[p.Name] = p
		}
		return nil
	})
	// A truncated discovery cannot safely distinguish a unique name from duplicates.
	if err != nil {
		w.packages = map[string]*workspacePackage{}
	}
}
func workspaceMatch(pattern, name string) bool {
	pattern = strings.TrimSuffix(strings.TrimPrefix(pattern, "./"), "/")
	if path.IsAbs(pattern) || strings.Contains(pattern, "\\") {
		return false
	}
	a, b := strings.Split(pattern, "/"), strings.Split(name, "/")
	// Repeated ** segments must not make metadata discovery exponential.
	memo := map[[2]int]bool{}
	var match func([]string, []string) bool
	match = func(a, b []string) (result bool) {
		key := [2]int{len(a), len(b)}
		if cached, ok := memo[key]; ok {
			return cached
		}
		defer func() { memo[key] = result }()
		if len(a) == 0 {
			return len(b) == 0
		}
		if a[0] == ".." {
			return false
		}
		if a[0] == "**" {
			return match(a[1:], b) || (len(b) > 0 && match(a, b[1:]))
		}
		if len(b) == 0 {
			return false
		}
		ok, e := path.Match(a[0], b[0])
		return e == nil && ok && match(a[1:], b[1:])
	}
	return match(a, b)
}
func validPackagePath(s string) bool {
	if strings.ContainsAny(s, "\\%?#") {
		return false
	}
	for _, p := range strings.Split(s, "/") {
		if p == "" || p == "." || p == ".." || p == "node_modules" {
			return false
		}
	}
	return true
}
func (w *workspaceResolver) candidates(dir, spec, mode string, symbols ...string) []string {
	if !validPackagePath(spec) {
		return nil
	}
	parts := strings.Split(spec, "/")
	n := 1
	if strings.HasPrefix(spec, "@") {
		n = 2
	}
	if len(parts) < n {
		return nil
	}
	name := strings.Join(parts[:n], "/")
	sub := "."
	if len(parts) > n {
		sub = "./" + strings.Join(parts[n:], "/")
	}
	w.load()
	p := w.packages[name]
	if p == nil {
		return nil
	}
	var importer *workspacePackage
	for inRepoConfigPath(dir) {
		if v, ok := readWorkspacePackage(w.root, dir); ok {
			importer = v
			break
		}
		if dir == "." {
			break
		}
		dir = path.Dir(dir)
	}
	if importer == nil || !w.members[importer.dir] {
		return nil
	}
	if importer.dir != p.dir {
		dep := importer.Dependencies[name]
		if dep == "" {
			dep = importer.DevDependencies[name]
		}
		if v := importer.OptionalDependencies[name]; v != "" {
			dep = v
		}
		// Explicit workspace references, wildcard local links, and exact matching versions.
		// Unsupported ranges/aliases remain unresolved rather than guessing a local version.
		if dep != "workspace:*" && dep != "workspace:^" && dep != "workspace:~" && dep != "*" && !(p.Version != "" && (dep == p.Version || dep == "workspace:"+p.Version)) {
			return nil
		}
	}
	// An installed dependency can override a same-named workspace member. Inspect
	// the link metadata, but never read or follow that dependency's source files.
	for d := importer.dir; inRepoConfigPath(d); d = path.Dir(d) {
		link := filepath.Join(w.root, filepath.FromSlash(join(d, "node_modules", name)))
		if fi, err := os.Lstat(link); err == nil {
			if fi.Mode()&os.ModeSymlink == 0 {
				return nil
			}
			target, err := os.Readlink(link)
			if err != nil {
				return nil
			}
			if !filepath.IsAbs(target) {
				target = filepath.Join(filepath.Dir(link), target)
			}
			expected := filepath.Join(w.root, filepath.FromSlash(p.dir))
			if filepath.Clean(target) != filepath.Clean(expected) {
				return nil
			}
			break
		} else if !os.IsNotExist(err) {
			return nil
		}
		if d == "." {
			break
		}
	}
	target := ""
	if len(p.Exports) > 0 {
		target = workspaceExport(p.Exports, sub, mode)
		if !strings.HasPrefix(target, "./") || !validPackagePath(strings.TrimPrefix(target, "./")) {
			return nil
		}
	} else if sub != "." {
		target = sub
	} else {
		target = p.Main
		if target == "" {
			target = "./index.js"
		}
	}
	target = strings.TrimPrefix(target, "./")
	if !validPackagePath(target) || path.IsAbs(target) {
		return nil
	}
	if f := workspaceSource(w.root, p.dir, target); f != "" {
		out := []string{f}
		for _, symbol := range symbols {
			budget := 32
			for _, forwarded := range workspaceForward(w.root, p.dir, f, symbol, map[string]bool{}, &budget) {
				present := false
				for _, v := range out {
					if v == forwarded {
						present = true
					}
				}
				if !present {
					out = append(out, forwarded)
				}
			}
		}
		return out
	}
	return nil
}

// JSON object order is significant for conditional exports. A Go map would
// select the wrong implementation nondeterministically for import/require.
type exportField struct {
	key   string
	value json.RawMessage
}

func exportFields(raw json.RawMessage) []exportField {
	d := json.NewDecoder(bytes.NewReader(raw))
	t, e := d.Token()
	if e != nil || t != json.Delim('{') {
		return nil
	}
	var out []exportField
	seen := map[string]bool{}
	for d.More() {
		k, e := d.Token()
		if e != nil {
			return nil
		}
		key, ok := k.(string)
		if !ok || seen[key] {
			return nil
		}
		seen[key] = true
		var v json.RawMessage
		if d.Decode(&v) != nil {
			return nil
		}
		out = append(out, exportField{key, v})
	}
	return out
}
func workspaceExport(raw json.RawMessage, sub, mode string) string {
	fields := exportFields(raw)
	mapped := false
	for _, f := range fields {
		if strings.HasPrefix(f.key, ".") {
			mapped = true
		}
	}
	if !mapped {
		if sub != "." {
			return ""
		}
		s, _ := exportCondition(raw, mode, 0)
		return s
	}
	for _, f := range fields {
		if !strings.HasPrefix(f.key, ".") {
			return ""
		}
	}
	for _, f := range fields {
		if f.key == sub {
			s, _ := exportCondition(f.value, mode, 0)
			return s
		}
	}
	best := ""
	capture := ""
	var val json.RawMessage
	for _, f := range fields {
		if strings.Count(f.key, "*") != 1 {
			continue
		}
		pre, post, _ := strings.Cut(f.key, "*")
		if len(sub) < len(pre)+len(post) || !strings.HasPrefix(sub, pre) || !strings.HasSuffix(sub, post) {
			continue
		}
		if len(pre) > strings.Index(best, "*") || (len(pre) == strings.Index(best, "*") && len(f.key) > len(best)) {
			best = f.key
			capture = sub[len(pre) : len(sub)-len(post)]
			val = f.value
		}
	}
	if best == "" {
		return ""
	}
	s, _ := exportCondition(val, mode, 0)
	return strings.ReplaceAll(s, "*", capture)
}
func exportCondition(raw json.RawMessage, mode string, depth int) (string, bool) {
	raw = bytes.TrimSpace(raw)
	if depth > 12 {
		return "", true
	}
	var s string
	if json.Unmarshal(raw, &s) == nil && string(raw) != "null" {
		return s, true
	}
	if string(raw) == "null" {
		return "", true
	}
	// Arrays/custom resolver conditions are intentionally unsupported; no fallback
	// to main or to a different active branch when a target is blocked or missing.
	if len(raw) > 0 && raw[0] == '[' {
		return "", true
	}
	for _, f := range exportFields(raw) {
		if f.key == "node" || f.key == "default" || f.key == mode {
			if s, matched := exportCondition(f.value, mode, depth+1); matched {
				return s, true
			}
		}
	}
	return "", false
}
func workspaceSource(root, dir, target string) string {
	if f := workspaceJSFile(root, dir, target); f != "" {
		return f
	}
	if _, err := os.Lstat(filepath.Join(root, filepath.FromSlash(join(dir, target)))); !os.IsNotExist(err) {
		return ""
	}
	// No guessed dist->src convention: remap only through the package's declared
	// compiler output/source roots, and only when the emitted target is absent.
	budget := 64
	cfg, ok := loadTSConfig(root, join(dir, "tsconfig.json"), map[string]bool{}, &budget)
	if !ok || cfg.rootDir == nil || cfg.outDir == nil {
		return ""
	}
	emitted := join(dir, target)
	if !strings.HasPrefix(emitted, *cfg.outDir+"/") {
		return ""
	}
	source := join(*cfg.rootDir, strings.TrimPrefix(emitted, *cfg.outDir+"/"))
	if !strings.HasPrefix(source, dir+"/") {
		return ""
	}
	return workspaceJSFile(root, ".", source)
}
func workspaceJSFile(root, dir, target string) string {
	rel := join(dir, target)
	if _, err := os.Lstat(filepath.Join(root, filepath.FromSlash(rel))); err == nil {
		if workspaceCodeFile(rel) {
			if _, ok := workspaceRead(root, rel); ok {
				return rel
			}
		}
		return ""
	} else if !os.IsNotExist(err) {
		return ""
	}
	var candidates []string
	if exts, ok := jsSiblingExts[path.Ext(rel)]; ok {
		for _, ext := range exts {
			candidates = append(candidates, strings.TrimSuffix(rel, path.Ext(rel))+ext)
		}
	} else if path.Ext(rel) == "" {
		candidates = jsCandidates(root, dir, target)
	}
	for _, candidate := range candidates {
		if workspaceCodeFile(candidate) {
			if _, ok := workspaceRead(root, candidate); ok {
				return candidate
			}
		}
	}
	return ""
}

// Do not let an in-repo directory symlink redirect package source into another
// package or node_modules. The checkout root itself may be a symlink.
func workspaceRead(root, rel string) (string, bool) {
	for d := path.Dir(rel); d != "." && inRepoConfigPath(d); d = path.Dir(d) {
		info, err := os.Lstat(filepath.Join(root, filepath.FromSlash(d)))
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return "", false
		}
	}
	return safeRead(root, rel)
}

func workspaceCodeFile(rel string) bool {
	ext := path.Ext(rel)
	if ext != ".ts" && ext != ".tsx" && ext != ".js" && ext != ".jsx" && ext != ".mts" && ext != ".mjs" && ext != ".cts" && ext != ".cjs" {
		return false
	}
	return !strings.HasSuffix(rel, ".d.ts") && !strings.HasSuffix(rel, ".d.mts") && !strings.HasSuffix(rel, ".d.cts")
}

var workspaceReexport = regexp.MustCompile(`(?m)\bexport\s+(\*|{[^}]*})\s+from\s*['"]([^'"]+)['"]`)

// Forwarding an exported symbol is resolving its definition, not following
// arbitrary runtime imports. Only proven named re-export chains are emitted.
func workspaceForward(root, pkg, file, symbol string, seen map[string]bool, budget *int) []string {
	key := file + ":" + symbol
	if seen[key] || *budget <= 0 {
		return nil
	}
	seen[key] = true
	defer delete(seen, key)
	*budget--
	body, ok := workspaceRead(root, file)
	if !ok || len(body) > 112*1024 {
		return nil
	}
	direct := regexp.MustCompile(`\bexport\s+(?:async\s+)?(?:const|let|var|function|class)\s+` + regexp.QuoteMeta(symbol) + `\b`)
	if direct.MatchString(body) {
		return []string{file}
	}
	var found []string
	for _, m := range workspaceReexport.FindAllStringSubmatch(body, -1) {
		next := ""
		if m[1] == "*" {
			next = symbol
		} else {
			for _, entry := range strings.Split(strings.Trim(m[1], "{}"), ",") {
				fields := strings.Fields(entry)
				if len(fields) == 1 && fields[0] == symbol {
					next = fields[0]
				}
				if len(fields) == 3 && fields[1] == "as" && fields[2] == symbol {
					next = fields[0]
				}
			}
		}
		if next == "" || !strings.HasPrefix(m[2], ".") {
			continue
		}
		target := join(path.Dir(file), m[2])
		if !strings.HasPrefix(target, pkg+"/") {
			continue
		}
		target = workspaceJSFile(root, ".", target)
		if target == "" {
			continue
		}
		chain := workspaceForward(root, pkg, target, next, seen, budget)
		if len(chain) > 0 {
			if found != nil {
				return nil
			}
			found = append([]string{file}, chain...)
		}
	}
	return found
}
