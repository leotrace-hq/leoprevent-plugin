// Package imports is the cloud-tier cross-file context resolver. For the code a
// turn changed, it finds the in-repo files that DEFINE the functions/symbols the
// changed code calls into — the helper one import away whose body holds the actual
// sink — and returns them as wire.ContextFile so the server's selector and judge
// can see across the import boundary. This closes the indirect-sink blind spot
// (measured: diff-only catches ~40% of cross-file vulns, ~100% with the helper).
//
// Scope (deliberate):
//   - LOCAL symbols only — never stdlib/third-party (no in-repo file to pull, and
//     we will not egress someone else's library).
//   - ONE hop — the files the change directly imports and references, not their
//     imports' imports.
//   - GATED — a file is pulled only when a symbol it provides is referenced in the
//     ADDED code; self-contained turns resolve nothing and pay nothing.
//   - Read-only, guarded — secret files (gate.IsSecretPath) and symlinks are
//     dropped exactly as in vcs, and reads are confined to the repo root.
//
// Languages: Python, JavaScript/TypeScript, Java, Go, C#. Python and JS/TS resolve
// relative specifiers to a path directly; Java/Go/C# need a one-time repo file
// index (package/namespace → file is not structural from the import alone). A file
// whose language has no parser simply yields no context (graceful).
//
// This runs ONLY on the cloud tier (the local tier sends no code) and only on the
// dev's machine: just the resolved files are egressed, never a repo scan upload.
package imports

import (
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/gate"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
	"github.com/leotrace-hq/leoprevent-plugin/limits"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

// Imported-context egress caps live in the limits package
// (limits.MaxContextFileBytes / MaxContextTotalBytes).
const maxIndexFiles = 20000 // pathological monorepo → skip index-based langs (Java/Go/C#) rather than walk forever

// Resolve returns the imported in-repo files the changed code references. root is
// the absolute repo root; each change's FilePath is repo-root-relative. Returns
// nil when nothing resolves (the common, self-contained case). Never errors — a
// resolution failure just yields less context, never a broken review.
func Resolve(root string, changes []transcript.Change) []wire.ContextFile {
	if root == "" || len(changes) == 0 {
		return nil
	}
	changed := map[string]bool{}
	for _, c := range changes {
		changed[norm(c.FilePath)] = true
	}

	var idx *repoIndex // built lazily, only if an index-based language appears
	getIdx := func() *repoIndex {
		if idx == nil {
			idx = buildIndex(root)
		}
		return idx
	}

	var out []wire.ContextFile
	seen := map[string]bool{}
	total := 0
	for _, c := range changes {
		added := strings.TrimSpace(c.AddedText)
		if added == "" {
			continue // nothing introduced here → nothing to gate on
		}
		src := c.FullContent
		if strings.TrimSpace(src) == "" {
			src = c.AddedText // non-git fallback: imports may still be in the added text
		}
		refs := identifiers(c.AddedText)

		var rels []string
		switch langOf(c.FilePath) {
		case langPython:
			rels = pythonContext(root, c.FilePath, src, refs)
		case langJS:
			rels = jsContext(root, c.FilePath, src, refs)
		case langJava:
			rels = javaContext(getIdx(), src, refs)
		case langGo:
			rels = goContext(getIdx(), src, refs)
		case langCSharp:
			rels = csContext(getIdx(), src, refs)
		default:
			continue
		}

		for _, rel := range rels {
			rel = norm(rel)
			if rel == "" || changed[rel] || seen[rel] {
				continue
			}
			body, ok := safeRead(root, rel)
			if !ok {
				continue
			}
			body = capBytes(body, limits.MaxContextFileBytes)
			if total+len(body) > limits.MaxContextTotalBytes {
				continue // budget spent — stop adding context (the change itself is unaffected)
			}
			seen[rel] = true
			total += len(body)
			out = append(out, wire.ContextFile{Path: rel, Content: body})
		}
	}
	return out
}

// ---- language detection ----

type lang int

const (
	langNone lang = iota
	langPython
	langJS
	langJava
	langGo
	langCSharp
)

func langOf(path string) lang {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".py":
		return langPython
	case ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx":
		return langJS
	case ".java":
		return langJava
	case ".go":
		return langGo
	case ".cs":
		return langCSharp
	}
	return langNone
}

// ---- shared helpers ----

var identRe = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*`)

// identifiers returns the set of identifier tokens in src — the gate: a candidate
// import is only resolved when a name it brings into scope appears here. Token-set
// matching is deliberately recall-generous (a qualified `pkg.Fn()` yields both
// `pkg` and `Fn`); the server judge prunes false context.
func identifiers(src string) map[string]bool {
	out := map[string]bool{}
	for _, m := range identRe.FindAllString(src, -1) {
		out[m] = true
	}
	return out
}

func anyRef(refs map[string]bool, names ...string) bool {
	for _, n := range names {
		if n != "" && refs[n] {
			return true
		}
	}
	return false
}

// norm canonicalises a repo-relative path to forward slashes with no leading "./".
func norm(p string) string {
	p = strings.ReplaceAll(p, `\`, "/")
	p = strings.TrimPrefix(p, "./")
	return path.Clean(p)
}

// safeRead reads root/rel with the same guards vcs applies before egressing a
// file: the path must stay inside root, must not be a symlink (Lstat, so a link
// target is never read+egressed), must be a regular file, and must not be a secret
// (gate.IsSecretPath). ok=false on any failure → the file is simply skipped.
func safeRead(root, rel string) (string, bool) {
	if rel == "" || strings.HasPrefix(rel, "../") || strings.Contains(rel, "/../") {
		return "", false
	}
	if gate.IsSecretPath(rel) {
		return "", false
	}
	abs := filepath.Join(root, filepath.FromSlash(rel))
	// Confirm abs is within root (defence in depth against a crafted rel).
	if r, err := filepath.Rel(root, abs); err != nil || r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) {
		return "", false
	}
	fi, err := os.Lstat(abs)
	if err != nil || fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
		return "", false
	}
	// The leaf Lstat and the lexical Rel check above miss an INTERMEDIATE symlinked
	// directory (a committed helpers -> /etc): the OS follows it on read, which would
	// egress an out-of-repo file as "context". Resolve the full chain on BOTH sides —
	// the root itself is routinely behind a symlink (/tmp -> /private/tmp on macOS,
	// symlinked checkouts), and comparing a resolved path against an unresolved root
	// would silently fail containment for every legitimate file.
	realAbs, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", false
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", false
	}
	if r, err := filepath.Rel(realRoot, realAbs); err != nil || r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) {
		return "", false
	}
	b, err := os.ReadFile(abs)
	if err != nil {
		return "", false
	}
	return string(b), true
}

// capBytes truncates s to at most n bytes on a rune boundary (mirrors vcs.capBytes).
func capBytes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && s[cut]&0xC0 == 0x80 {
		cut--
	}
	return s[:cut] + "\n… [truncated]\n"
}
