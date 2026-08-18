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
//   - SLICED — a resolved helper is sent as the spans the changed code can reach,
//     not the whole file (slice.go). The excerpt carries each retained line's real
//     file line number, so a cited file:line stays true; slicing fails toward the
//     whole file, so a parser gap costs bytes and never context.
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

// sliceBodies and skipTypeOnlyImports are ALWAYS true in the shipped binary. They
// exist so the measurement harness (slice_measure_test.go) can price this change
// against the behaviour it replaced on a real repository, instead of quoting an
// estimate — the two are unexported, have no config or env path to them, and the
// only writer is that test. Do not add one.
var (
	sliceBodies         = true
	skipTypeOnlyImports = true
)

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

	// Slicing is gated on the identifiers of the WHOLE turn, not of the one changed
	// file that happened to resolve a helper first: a helper reached from two changed
	// files must keep the bodies both of them call, and a helper is resolved once.
	// Import GATING stays per-file (an import statement is a property of that file) —
	// only the reachability question is turn-wide, which is the recall-safe direction.
	turnRefs := map[string]bool{}
	for _, c := range changes {
		for id := range identifiers(c.AddedText) {
			turnRefs[id] = true
		}
	}

	// Pass 1: collect the candidate paths and WHY each was pulled, first-seen order.
	// The reason has to be merged across changed files before any file is read: a
	// helper pulled by NAME from one file and by its package from another is a named
	// pull, and reading it at first sight would take whichever reason arrived first.
	var order []string
	named := map[string]bool{}
	for _, c := range changes {
		if strings.TrimSpace(c.AddedText) == "" {
			continue // nothing introduced here → nothing to gate on
		}
		src := c.FullContent
		if strings.TrimSpace(src) == "" {
			src = c.AddedText // non-git fallback: imports may still be in the added text
		}
		refs := identifiers(c.AddedText)

		var cands []candidate
		switch langOf(c.FilePath) {
		case langPython:
			cands = pythonContext(root, c.FilePath, src, refs)
		case langJS:
			cands = jsContext(root, c.FilePath, src, refs)
		case langJava:
			cands = javaContext(getIdx(), src, refs)
		case langGo:
			cands = goContext(getIdx(), src, refs)
		case langCSharp:
			cands = csContext(getIdx(), src, refs)
		default:
			continue
		}
		for _, cd := range cands {
			rel := norm(cd.rel)
			if rel == "" || changed[rel] {
				continue
			}
			if _, seen := named[rel]; !seen {
				order = append(order, rel)
			}
			named[rel] = named[rel] || cd.named
		}
	}

	// Pass 2: read, slice, and spend the egress budget.
	var out []wire.ContextFile
	total := 0
	for _, rel := range order {
		body, ok := safeRead(root, rel)
		if !ok {
			continue
		}
		// Selective function pulling: send the spans the changed code can reach,
		// not the whole helper.
		var nums []int
		if excerpt, ln, sliced := sliceFile(rel, body, turnRefs, limits.MaxContextFileBytes, named[rel]); sliceBodies && sliced {
			body, nums = excerpt, ln
		} else {
			body = capBytes(body, limits.MaxContextFileBytes)
		}
		if total+len(body) > limits.MaxContextTotalBytes {
			continue // budget spent — stop adding context (the change itself is unaffected)
		}
		total += len(body)
		out = append(out, wire.ContextFile{Path: rel, Content: body, Lines: nums})
	}
	return out
}

// candidate is a resolved path plus WHY the resolver pulled it.
//
// named means a symbol DEFINED IN THIS FILE was written in the added code: a
// `from x import fetch`, an `import { fetch } from './x'`, a Java class, a C# type.
// It is FALSE when the file came in on a broader claim — a Go import names a
// PACKAGE and pulls every file in it, a Python `import pkg.mod` names a module, and
// a JS `export * from './x'` re-export has no local binding to gate on at all.
//
// The distinction decides what happens when no span in the file looks reachable.
// For a named pull, something in that file WAS referenced and the slicer just
// cannot see how, so the file travels whole. For the rest, nothing ever claimed a
// symbol here at all, and there is no premise to be conservative about: the file
// travels as its skeleton. Measured on this repo, three quarters of the whole-file
// fallback was the second kind, sent whole on the strength of a claim no import had
// made.
type candidate struct {
	rel   string
	named bool
}

// namedCandidates and moduleCandidates label a batch of resolved paths.
func namedCandidates(rels ...string) []candidate  { return labelled(true, rels) }
func moduleCandidates(rels ...string) []candidate { return labelled(false, rels) }

func labelled(named bool, rels []string) []candidate {
	out := make([]candidate, 0, len(rels))
	for _, r := range rels {
		out = append(out, candidate{rel: r, named: named})
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
