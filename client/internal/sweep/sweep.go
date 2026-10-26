package sweep

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/leotrace-hq/leoprevent-plugin/limits"
	"github.com/leotrace-hq/leoprevent-plugin/pathgate"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

const (
	SkipUnsafePath = "path outside the repository"
	SkipSecret     = "secret file, never sent"
	SkipSymlink    = "symlink, never followed"
	SkipMissing    = "not in this checkout"
	SkipTooLarge   = "larger than a review can carry"
	SkipBinary     = "not text"
	SkipTooMany    = "more Aikido issues than one request can judge"
)

type Skipped struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

type File struct {
	Path    string
	Issues  int
	Content string
}

func Read(root string,
	path string) (string, string) {
	rel := strings.TrimPrefix(filepath.ToSlash(path), "/")
	clean := filepath.Clean(filepath.FromSlash(rel))
	if rel == "" || !filepath.IsLocal(clean) {
		return "", SkipUnsafePath
	}
	if pathgate.IsSecretPath(rel) {
		return "", SkipSecret
	}
	r, err := os.OpenRoot(root)
	if err != nil {
		return "", SkipMissing
	}
	defer r.Close()
	if linked(r, clean) {
		return "", SkipSymlink
	}
	f, err := r.Open(clean)
	if err != nil {
		return "", SkipMissing
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return "", SkipMissing
	}
	onDisk, err := r.Lstat(clean)
	if err != nil {
		return "", SkipMissing
	}
	if onDisk.Mode()&os.ModeSymlink != 0 || !os.SameFile(opened, onDisk) {
		return "", SkipSymlink
	}
	if !opened.Mode().IsRegular() {
		return "", SkipMissing
	}
	if opened.Size() > limits.MaxChangedFileBytes {
		return "", SkipTooLarge
	}
	b, err := io.ReadAll(io.LimitReader(f, limits.MaxChangedFileBytes+1))
	if err != nil {
		return "", SkipMissing
	}
	if len(b) > limits.MaxChangedFileBytes {
		return "", SkipTooLarge
	}
	if !utf8.Valid(b) || strings.ContainsRune(string(b), '\x00') {
		return "", SkipBinary
	}
	if strings.TrimSpace(string(b)) == "" {
		return "", SkipMissing
	}
	return string(b), ""
}

func linked(r *os.Root,
	clean string) bool {
	cur := ""
	for _, seg := range strings.Split(clean, string(filepath.Separator)) {
		cur = filepath.Join(cur, seg)
		info, err := r.Lstat(cur)
		if err != nil {
			return false
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return true
		}
	}
	return false
}

func Batches(files []File,
	maxBytes int,
	maxFiles int,
	maxIssues int) [][]File {
	var out [][]File
	var cur []File
	bytes, issues := 0, 0
	for _, f := range files {
		if len(cur) > 0 && (bytes+len(f.Content) > maxBytes || len(cur)+1 > maxFiles || issues+f.Issues > maxIssues) {
			out = append(out, cur)
			cur, bytes, issues = nil, 0, 0
		}
		cur = append(cur, f)
		bytes += len(f.Content)
		issues += f.Issues
	}
	if len(cur) > 0 {
		out = append(out, cur)
	}
	return out
}

type Pending struct {
	ReviewID string         `json:"review_id"`
	Findings []wire.Finding `json:"findings"`
}

type Open struct {
	ReviewID string         `json:"review_id"`
	Commit   string         `json:"commit"`
	Findings []wire.Finding `json:"findings"`
	At       time.Time      `json:"at"`
}

type State struct {
	Repo    string    `json:"repo"`
	Pending []Pending `json:"pending"`
	Open    []Open    `json:"open,omitempty"`
}

const OpenTTL = 14 * 24 * time.Hour

func (st *State) DropExpired(now time.Time) {
	kept := st.Open[:0]
	for _, o := range st.Open {
		if now.Sub(o.At) < OpenTTL && len(o.Findings) > 0 {
			kept = append(kept, o)
		}
	}
	st.Open = kept
}

var userConfigDir = os.UserConfigDir

func SetUserConfigDirForTest(dir string) func() {
	prev := userConfigDir
	userConfigDir = func() (string, error) { return dir, nil }
	return func() { userConfigDir = prev }
}

func stateDir() (string, error) {
	dir, err := userConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "leoprevent", "aikido-sweep"), nil
}

func stateName(repo string) string {
	sum := sha256.Sum256([]byte(repo))
	return hex.EncodeToString(sum[:8]) + ".json"
}

func Load(repo string) (State, error) {
	st := State{Repo: repo}
	dir, err := stateDir()
	if err != nil {
		return st, err
	}
	r, err := os.OpenRoot(dir)
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	defer r.Close()
	b, err := r.ReadFile(stateName(repo))
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return st, err
	}
	st.Repo = repo
	return st, nil
}

func Save(st State) error {
	dir, err := stateDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	r, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer r.Close()
	return r.WriteFile(stateName(st.Repo), b, 0o600)
}

func (st *State) Take(reviewID string) (Pending, bool) {
	for i, p := range st.Pending {
		if p.ReviewID == reviewID {
			st.Pending = append(st.Pending[:i], st.Pending[i+1:]...)
			return p, true
		}
	}
	return Pending{}, false
}

func Changed(root string,
	o Open,
	before func(root, rev, path string) (string, bool),
	read func(root, path string) (string, string)) (touched, untouched []wire.Finding, b, a []wire.ChangedFile) {
	type pair struct {
		ok bool
	}
	files := map[string]pair{}
	for _, f := range o.Findings {
		path := wire.ParseLocation(f.Location).Path
		p, seen := files[path]
		if !seen {
			old, okOld := before(root, o.Commit, path)
			now, skip := read(root, path)
			p = pair{ok: okOld && skip == "" && old != now}
			files[path] = p
			if p.ok {
				b = append(b, wire.ChangedFile{Path: path, FullContent: old})
				a = append(a, wire.ChangedFile{Path: path, FullContent: now})
			}
		}
		if p.ok {
			touched = append(touched, f)
		} else {
			untouched = append(untouched, f)
		}
	}
	return touched, untouched, b, a
}
