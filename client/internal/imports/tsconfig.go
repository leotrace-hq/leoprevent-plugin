package imports

import (
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

type tsConfig struct {
	baseURL  *string
	rootDir  *string
	outDir   *string
	paths    map[string][]string
	pathsDir string
}

type tsConfigFile struct {
	Extends         json.RawMessage `json:"extends"`
	CompilerOptions struct {
		RootDir *string             `json:"rootDir"`
		OutDir  *string             `json:"outDir"`
		BaseURL *string             `json:"baseUrl"`
		Paths   map[string][]string `json:"paths"`
	} `json:"compilerOptions"`
}

func nearestTSConfig(
	root, dir string,
) tsConfig {
	for inRepoConfigPath(dir) {
		rel := join(dir, "tsconfig.json")
		if _, err := os.Lstat(filepath.Join(root, filepath.FromSlash(rel))); err == nil {
			budget := 64
			config, _ := loadTSConfig(root, rel, map[string]bool{}, &budget)
			return config
		}
		if dir == "." {
			break
		}
		dir = path.Dir(dir)
	}
	return tsConfig{}
}

func inRepoConfigPath(
	rel string,
) bool {
	return rel != ".." && !strings.HasPrefix(rel, "../") && !path.IsAbs(rel)
}

func loadTSConfig(
	root, rel string,
	visiting map[string]bool,
	budget *int,
) (tsConfig, bool) {
	if !inRepoConfigPath(rel) || visiting[rel] || *budget <= 0 {
		return tsConfig{}, false
	}
	*budget -= 1
	body, ok := safeRead(root, rel)
	if !ok || len(body) > 1024*1024 {
		return tsConfig{}, false
	}
	var file tsConfigFile
	if json.Unmarshal(stripJSONC(body), &file) != nil {
		return tsConfig{}, false
	}
	visiting[rel] = true
	defer delete(visiting, rel)
	var bases []string
	if len(file.Extends) > 0 {
		var single string
		if json.Unmarshal(file.Extends, &single) == nil {
			bases = []string{single}
		} else if json.Unmarshal(file.Extends, &bases) != nil {
			return tsConfig{}, false
		}
	}
	config := tsConfig{}
	for _, base := range bases {
		basePath := tsConfigBase(root, path.Dir(rel), base)
		parent, valid := loadTSConfig(root, basePath, visiting, budget)
		if !valid {
			return tsConfig{}, false
		}
		if parent.rootDir != nil {
			config.rootDir = parent.rootDir
		}
		if parent.outDir != nil {
			config.outDir = parent.outDir
		}
		if parent.baseURL != nil {
			config.baseURL = parent.baseURL
		}
		if parent.paths != nil {
			config.paths, config.pathsDir = parent.paths, parent.pathsDir
		}
	}
	for _, field := range []struct {
		src *string
		dst **string
	}{{file.CompilerOptions.RootDir, &config.rootDir}, {file.CompilerOptions.OutDir, &config.outDir}} {
		if field.src != nil {
			value := *field.src
			if !path.IsAbs(value) {
				value = join(path.Dir(rel), value)
			}
			*field.dst = &value
		}
	}
	if file.CompilerOptions.BaseURL != nil {
		base := *file.CompilerOptions.BaseURL
		if !path.IsAbs(base) {
			base = join(path.Dir(rel), base)
		}
		config.baseURL = &base
	}
	if file.CompilerOptions.Paths != nil {
		config.paths = file.CompilerOptions.Paths
		config.pathsDir = path.Dir(rel)
	}
	return config, true
}

func tsConfigBase(
	root, dir, spec string,
) string {
	if spec == "" {
		return ".."
	}
	if isRelativeSpec(spec) {
		if path.IsAbs(spec) {
			return ".."
		}
		rel := join(dir, spec)
		if _, ok := safeRead(root, rel); ok {
			return rel
		}
		return rel + ".json"
	}
	for inRepoConfigPath(dir) {
		rel := join(dir, "node_modules", spec)
		for _, candidate := range []string{rel, rel + ".json"} {
			if _, ok := safeRead(root, candidate); ok {
				return candidate
			}
		}
		if body, ok := safeRead(root, join(rel, "package.json")); ok {
			var pkg struct {
				TSConfig string `json:"tsconfig"`
			}
			if json.Unmarshal([]byte(body), &pkg) == nil && pkg.TSConfig != "" && !path.IsAbs(pkg.TSConfig) {
				return join(rel, pkg.TSConfig)
			}
		}
		if _, ok := safeRead(root, join(rel, "tsconfig.json")); ok {
			return join(rel, "tsconfig.json")
		}
		if dir == "." {
			break
		}
		dir = path.Dir(dir)
	}
	return ".."
}

func (config tsConfig) candidates(
	root, spec string,
) []string {
	keys := make([]string, 0, len(config.paths))
	for key := range config.paths {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	best, capture, matched := "", "", false
	for _, key := range keys {
		if key == spec {
			best, capture, matched = key, "", true
			break
		}
		if strings.Count(key, "*") != 1 {
			continue
		}
		prefix, suffix, _ := strings.Cut(key, "*")
		if len(spec) < len(prefix)+len(suffix) || !strings.HasPrefix(spec, prefix) || !strings.HasSuffix(spec, suffix) {
			continue
		}
		if !matched || len(prefix) > strings.Index(best, "*") {
			best, capture, matched = key, spec[len(prefix):len(spec)-len(suffix)], true
		}
	}
	if !matched {
		return nil
	}
	base := config.pathsDir
	if config.baseURL != nil {
		base = *config.baseURL
	}
	for _, target := range config.paths[best] {
		if strings.Count(target, "*") > 1 {
			continue
		}
		target = strings.ReplaceAll(target, "*", capture)
		if path.IsAbs(target) || path.IsAbs(base) {
			continue
		}
		for _, rel := range jsCandidates(root, base, target) {
			if !inRepoConfigPath(rel) || strings.Contains("/"+rel+"/", "/node_modules/") {
				continue
			}
			if _, ok := safeRead(root, rel); ok {
				return []string{rel}
			}
		}
	}
	return nil
}

func stripJSONC(
	body string,
) []byte {
	data := []byte(body)
	quoted, escaped := false, false
	for i := 0; i < len(data); i++ {
		ch := data[i]
		if quoted {
			if escaped {
				escaped = false
			} else if ch == '\\' {
				escaped = true
			} else if ch == '"' {
				quoted = false
			}
			continue
		}
		if ch == '"' {
			quoted = true
			continue
		}
		if ch != '/' || i+1 >= len(data) {
			continue
		}
		if data[i+1] == '/' {
			for i < len(data) && data[i] != '\n' {
				data[i] = ' '
				i++
			}
		} else if data[i+1] == '*' {
			data[i], data[i+1] = ' ', ' '
			i += 2
			for i+1 < len(data) && !(data[i] == '*' && data[i+1] == '/') {
				data[i] = ' '
				i++
			}
			if i+1 >= len(data) {
				return nil
			}
			data[i], data[i+1] = ' ', ' '
			i++
		}
	}
	quoted, escaped = false, false
	for i, ch := range data {
		if quoted {
			if escaped {
				escaped = false
			} else if ch == '\\' {
				escaped = true
			} else if ch == '"' {
				quoted = false
			}
			continue
		}
		if ch == '"' {
			quoted = true
			continue
		}
		if ch == ',' {
			j := i + 1
			for j < len(data) && strings.ContainsRune(" \t\r\n", rune(data[j])) {
				j++
			}
			if j < len(data) && (data[j] == '}' || data[j] == ']') {
				data[i] = ' '
			}
		}
	}
	return data
}

// A matching but unresolved explicit alias must not fall through to a different package.
func (config tsConfig) matches(spec string) bool {
	for key := range config.paths {
		if key == spec {
			return true
		}
		if strings.Count(key, "*") == 1 {
			pre, post, _ := strings.Cut(key, "*")
			if len(spec) >= len(pre)+len(post) && strings.HasPrefix(spec, pre) && strings.HasSuffix(spec, post) {
				return true
			}
		}
	}
	return false
}
