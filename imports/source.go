package imports

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/leotrace-hq/leoprevent-plugin/pathgate"
)

// Source is where the resolver reads the repository from.
//
// ⚠️ IT EXISTS BECAUSE THE PULL-REQUEST LANE HAS NO CHECKOUT. The Stop hook and the Action
// both run on a machine holding the repo, so resolving a helper is a file read. The webhook
// lane holds nothing: it learns the repository from the GitHub API, and without an
// abstraction here it could not resolve cross-file context at all — which meant a pull
// request was reviewed WITHOUT the one-import-away helper that holds the actual sink, while
// the same code reviewed at a Stop hook was not. Same code, two answers, and nothing said so.
//
// The interface is deliberately TWO operations, because those are the only two the resolver
// ever performs: read a repo-relative file, and list the repository. Everything else — the
// import parsers, the candidate ranking, the slicing — is already a pure function of content.
//
// ⚠️ CONTAINMENT IS THE IMPLEMENTATION'S JOB, NOT THE CALLER'S. osSource keeps safeRead's
// symlink and secret-path guards verbatim; a tree-backed source has no symlinks to follow
// and refuses them outright. A Source that reads outside the repository would egress
// somebody else's code as "context", which is the leak this package's own comments forbid.
type Source interface {
	// Read returns a repo-relative file's content, or ok=false when it may not be read.
	Read(rel string) (string, bool)
	// Exists reports whether something is AT rel — regardless of whether Read would
	// return it.
	//
	// ⚠️ IT IS DELIBERATELY NOT "Read succeeded", AND COLLAPSING THE TWO IS A REAL BUG.
	// A tsconfig.json that exists but is unsafe to read (a symlink) must still STOP the
	// upward search for a nearer config: treating it as absent walks on to the PARENT
	// config and resolves the changed file's imports through settings it does not use.
	// TestTypeScriptNearestUnsafeConfigDoesNotUseParent pins exactly that, and it failed
	// when this was one method.
	Exists(rel string) bool
	// Paths lists the repository's source files, repo-relative and slash-form. It backs
	// the package/namespace index Java, Go and C# need. An empty list disables those
	// languages (graceful: no context, never a wrong file).
	Paths() []string
	// Local reports whether this Source is a real checkout. Only a checkout can resolve
	// npm workspace links, which live in node_modules — never committed, so never in a
	// tree-backed source. False simply skips that step.
	Local() bool
}

// osSource is the checkout-backed Source: the behaviour every existing caller had before
// Source existed. Its Read IS safeRead, unchanged, so the guards that matter — symlink
// containment on both sides, secret paths, regular files only — are the same code.
type osSource struct{ root string }

func (s osSource) Read(rel string) (string, bool) { return safeRead(s.root, rel) }
func (s osSource) Local() bool                    { return true }

// Exists is an Lstat, not a read: it must answer for a symlink or a directory too.
func (s osSource) Exists(rel string) bool {
	_, err := os.Lstat(filepath.Join(s.root, filepath.FromSlash(rel)))
	return err == nil
}

func (s osSource) Paths() []string {
	var out []string
	n := 0
	_ = filepath.WalkDir(s.root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if p != s.root && indexSkipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !indexExts[strings.ToLower(filepath.Ext(d.Name()))] {
			return nil
		}
		n++
		if n > maxIndexFiles {
			return filepath.SkipAll
		}
		if rel, err := filepath.Rel(s.root, p); err == nil {
			out = append(out, filepath.ToSlash(rel))
		}
		return nil
	})
	if n > maxIndexFiles {
		return nil // pathological monorepo → no index rather than a partial, wrong one
	}
	return out
}

// MemSource is a Source backed by files already in memory — what a caller with no checkout
// (the pull-request lane) fills from an API. Reads are confined to what it was given, so a
// path it does not hold is simply absent rather than fetched from anywhere else.
type MemSource struct {
	files map[string]string
	paths []string
}

// NewMemSource builds a Source from a repo listing and a reader for file bodies. paths is
// the whole repository's source listing (for the index); load is called at most once per
// path and may return ok=false for anything that must not be read.
func NewMemSource(paths []string, files map[string]string) *MemSource {
	idx := make([]string, 0, len(paths))
	for _, p := range paths {
		if indexExts[strings.ToLower(filepath.Ext(p))] {
			idx = append(idx, p)
		}
	}
	if len(idx) > maxIndexFiles {
		idx = nil // same posture as osSource: no index beats a partial one
	}
	return &MemSource{files: files, paths: idx}
}

func (m *MemSource) Paths() []string { return m.paths }
func (m *MemSource) Local() bool     { return false }

// Exists answers from the listing, so a path held but refused by Read (a secret) still
// counts as present — the same distinction osSource draws.
func (m *MemSource) Exists(rel string) bool {
	_, ok := m.files[rel]
	return ok
}

func (m *MemSource) Read(rel string) (string, bool) {
	// The same two refusals safeRead makes before it touches anything: no escaping path,
	// no secret file. There is no symlink case — a tree-backed caller never supplies one.
	if rel == "" || strings.HasPrefix(rel, "../") || strings.Contains(rel, "/../") {
		return "", false
	}
	if pathgate.IsSecretPath(rel) {
		return "", false
	}
	s, ok := m.files[rel]
	return s, ok
}

// Change is one changed file as the resolver needs it.
//
// ⚠️ IT IS DECLARED HERE RATHER THAN REUSED FROM THE CLIENT, and that is the whole reason
// this package could be promoted out of client/internal. The resolver has to be callable
// from the SERVER's pull-request lane, and a package under client/internal is importable
// only from client/ — so a checkout-free caller could not have reached it, and would have
// had to grow a second copy of the resolver. The fields are the client's transcript.Change
// verbatim, names included, so a caller converts by assignment and a reader comparing the
// two sees no translation to check.
type Change struct {
	FilePath    string
	AddedText   string
	FullContent string
	// AddedLines are the 1-based line numbers the change introduced. Nil is allowed: it
	// only costs slicing precision, never correctness.
	AddedLines []int
}
