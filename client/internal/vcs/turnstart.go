package vcs

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
)

// ErrNoTurnStartCopy is returned for a file that existed at the start of the turn but whose
// copy wasn't kept: an untracked file too large for the turn-start snapshot, or a repository
// with no turn-start capture of its own (HEAD-anchored). The caller treats the change as
// unknown, never as "new this turn".
var ErrNoTurnStartCopy = errors.New("no start-of-turn copy kept")

// maxTurnStartFileBytes bounds one turn-start read. It matches the dependency readers' own
// limit (64 MiB): the copy is read into memory.
const maxTurnStartFileBytes = 64 << 20

// TurnStart is the turn-start state of the repositories this session's baseline covers, for
// reading a file as it was when the turn began. It is read-only: it never changes the baseline
// or what is reviewed.
type TurnStart struct {
	sections map[string]repoBaseline // by repository root
}

// LoadTurnStart reads the session's turn-start baseline. ok is false when nothing was
// captured (no git, or the prompt hook never ran).
func LoadTurnStart(cwd, sessionID string) (TurnStart, bool) {
	if cwd == "" || sessionID == "" {
		return TurnStart{}, false
	}
	sections, _, _ := readSections(cwd, sessionID)
	ts := TurnStart{sections: map[string]repoBaseline{}}
	for _, s := range sections {
		root, err := git(s.dir(cwd), "rev-parse", "--show-toplevel")
		if err != nil {
			continue
		}
		ts.sections[filepath.Clean(strings.TrimSpace(root))] = s
	}
	return ts, len(ts.sections) > 0
}

// Opener returns a reader of files under the repository at root, as they were at the start
// of the turn. path is absolute. It returns:
//   - an error satisfying errors.Is(err, fs.ErrNotExist) for a file that wasn't there (new
//     this turn);
//   - ErrNoTurnStartCopy for one that was there but whose copy wasn't kept;
//   - an error for anything that isn't an ordinary file (a symlink is stored as a mode
//     120000 blob holding the link's target, which must never be read as the file), and for
//     a copy over 64 MiB.
func (ts TurnStart) Opener(root string) func(path string) ([]byte, error) {
	s, ok := ts.sections[filepath.Clean(root)]
	return func(path string) ([]byte, error) {
		if !ok || s.headOnly {
			return nil, ErrNoTurnStartCopy
		}
		rel, err := filepath.Rel(root, path)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return nil, fmt.Errorf("%s: outside the repository", path)
		}
		rel = filepath.ToSlash(rel)
		if sha, ok := s.blobs[rel]; ok {
			return readBlob(root, sha, path)
		}
		if _, ok := s.untracked[rel]; ok {
			return nil, ErrNoTurnStartCopy // untracked at turn start, but not kept (too large)
		}
		// A literal pathspec, so a file name with glob characters names only itself.
		out, err := git(root, "ls-tree", "-l", "-z", s.ref, "--", ":(literal)"+rel)
		if err != nil {
			return nil, fmt.Errorf("%s: reading the turn-start tree: %w", path, err)
		}
		entry := strings.TrimSuffix(out, "\x00")
		if entry == "" {
			return nil, &fs.PathError{Op: "open", Path: path, Err: fs.ErrNotExist}
		}
		// "<mode> <type> <oid> <size>\t<path>"
		meta, _, _ := strings.Cut(entry, "\t")
		f := strings.Fields(meta)
		if len(f) != 4 || f[1] != "blob" || (f[0] != "100644" && f[0] != "100755") {
			return nil, fmt.Errorf("%s: not a regular file at the start of the turn (%q), not read", path, meta)
		}
		if n, err := strconv.ParseInt(f[3], 10, 64); err != nil || n > maxTurnStartFileBytes {
			return nil, fmt.Errorf("%s: over the %d-byte limit at the start of the turn", path, maxTurnStartFileBytes)
		}
		return readBlob(root, f[2], path)
	}
}

func readBlob(root, oid, path string) ([]byte, error) {
	out, err := git(root, "cat-file", "blob", oid)
	if err != nil {
		return nil, fmt.Errorf("%s: reading the turn-start copy: %w", path, err)
	}
	if len(out) > maxTurnStartFileBytes {
		return nil, fmt.Errorf("%s: over the %d-byte limit at the start of the turn", path, maxTurnStartFileBytes)
	}
	return []byte(out), nil
}
