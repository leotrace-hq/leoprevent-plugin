package imports

import (
	"os"
	"path/filepath"
	"strings"
)

// osSource is where the resolver reads the repository from: a checkout. Its Read IS
// safeRead, so the guards that matter — symlink containment on both sides, secret paths,
// regular files only — are the same code. A read outside the repository would egress
// somebody else's code as "context", which is the leak this package's own comments forbid.
type osSource struct{ root string }

func (s osSource) Read(rel string) (string, bool) { return safeRead(s.root, rel) }

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

// Change is one changed file as the resolver needs it. The fields are the client's
// transcript.Change verbatim, names included, so a caller converts by assignment and a
// reader comparing the two sees no translation to check.
type Change struct {
	FilePath    string
	AddedText   string
	FullContent string
	// AddedLines are the 1-based line numbers the change introduced. Nil is allowed: it
	// only costs slicing precision, never correctness.
	AddedLines []int
}
