package deps

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// A reader is picked by file name alone, from wherever the file sits.
func TestReadersPickByFileName(t *testing.T) {
	for path, eco := range map[string]string{
		"package-lock.json": "npm", "web/npm-shrinkwrap.json": "npm", "services/api/go.mod": "Go",
	} {
		r, ok := All.For(path)
		if !ok || r.Ecosystem() != eco {
			t.Errorf("%s: got %v, %v", path, r, ok)
		}
	}
	for _, path := range []string{"package.json", "go.sum", "yarn.lock", "requirements.txt"} {
		if _, ok := All.For(path); ok {
			t.Errorf("%s has no reader", path)
		}
	}
	if got := strings.Join(All.Files(), ","); got != "go.mod,npm-shrinkwrap.json,package-lock.json" {
		t.Errorf("Files = %s", got)
	}
}

// ReadFile reads the companions beside the file: go.sum fills in an old go.mod.
func TestReadFileReadsCompanions(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "go.mod", "module m\n\ngo 1.16\n\nrequire a.com/x v1.0.0\n")
	write(t, dir, "go.sum", "b.com/y v1.0.0 h1:x=\n")
	r, reader, err := All.ReadFile(filepath.Join(dir, "go.mod"))
	if err != nil || reader.Ecosystem() != "Go" {
		t.Fatal(reader, err)
	}
	if _, ok := byName(r.Dependencies)["b.com/y"]; !ok {
		t.Errorf("go.sum wasn't read beside go.mod: %+v", r)
	}
	if _, _, err := All.ReadFile(filepath.Join(dir, "go.sum")); err == nil || !strings.Contains(err.Error(), "not a supported file") {
		t.Errorf("go.sum alone: %v", err)
	}
}

// The plugin never follows a symlink: it could point anywhere on the machine.
func TestReadFileRefusesASymlink(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "elsewhere.json", `{"lockfileVersion": 3, "packages": {}}`)
	if err := os.Symlink(filepath.Join(dir, "elsewhere.json"), filepath.Join(dir, "package-lock.json")); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	if _, _, err := All.ReadFile(filepath.Join(dir, "package-lock.json")); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("a symlinked lockfile was read: %v", err)
	}
}

func write(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// A file over the limit is refused, and so is a directory where a lockfile was expected.
func TestReadBoundedRefusesWhatIsntAnOrdinaryFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "go.mod"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := readBounded(filepath.Join(dir, "go.mod")); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("a directory: %v", err)
	}
	big := filepath.Join(dir, "big")
	f, err := os.Create(big)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxFileBytes + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := readBounded(big); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Errorf("an oversized file: %v", err)
	}
}

// files is an Opener over copies held in memory: a stand-in for the start-of-turn baseline. It
// records every path asked for.
type files struct {
	copies map[string]string
	asked  []string
}

func (f *files) open(path string) ([]byte, error) {
	f.asked = append(f.asked, path)
	if strings.HasPrefix(f.copies[path], "!") {
		return nil, errors.New(f.copies[path][1:])
	}
	if b, ok := f.copies[path]; ok {
		return []byte(b), nil
	}
	return nil, &fs.PathError{Op: "open", Path: path, Err: fs.ErrNotExist}
}

// The file and its companions come from the same opener, never from disk, and only the files the
// reader names are opened.
func TestReadWithReadsOnlyWhatTheReaderNamesFromOneSource(t *testing.T) {
	mod := filepath.Join("svc", "api", "go.mod")
	f := &files{copies: map[string]string{
		mod:                                      "module m\n\ngo 1.16\n\nrequire a.com/x v1.0.0\n",
		filepath.Join("svc", "api", "go.sum"):    "b.com/y v1.0.0 h1:x=\n",
		filepath.Join("svc", "api", "README.md"): "not a dependency file",
	}}
	r, reader, err := All.ReadWith(mod, f.open)
	if err != nil || reader.Ecosystem() != "Go" {
		t.Fatal(reader, err)
	}
	if _, ok := byName(r.Dependencies)["b.com/y"]; !ok {
		t.Errorf("go.sum is read from the same source as go.mod: %+v", r)
	}
	want := []string{mod, filepath.Join("svc", "api", "go.sum")}
	if !reflect.DeepEqual(f.asked, want) {
		t.Errorf("opened %v, want exactly %v", f.asked, want)
	}
	f.asked = nil
	if _, _, err := All.ReadWith(filepath.Join("svc", "api", "README.md"), f.open); err == nil || len(f.asked) != 0 {
		t.Errorf("a file no reader reads is never opened: %v, %v", err, f.asked)
	}
}

// A file missing from the source (created this turn, so absent from the baseline) is
// fs.ErrNotExist, for the caller to read as "nothing before". A missing companion is left out
// quietly; one that couldn't be read is left out with a note.
func TestReadWithMissingFilesAndRefusedCompanions(t *testing.T) {
	f := &files{copies: map[string]string{}}
	if _, _, err := All.ReadWith("go.mod", f.open); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing go.mod: %v", err)
	}
	// Go 1.17 and later don't need go.sum: refused or missing, it says nothing.
	f.copies = map[string]string{"go.mod": "module m\n\ngo 1.21\n\nrequire a.com/x v1.0.0\n", "go.sum": "!a symlink, not read"}
	if r, _, err := All.ReadWith("go.mod", f.open); err != nil || len(r.Notes) != 0 {
		t.Errorf("a refused go.sum on go 1.21 isn't worth a note: %+v, %v", r.Notes, err)
	}
	delete(f.copies, "go.sum")
	if r, _, _ := All.ReadWith("go.mod", f.open); len(r.Notes) != 0 {
		t.Errorf("a missing companion on go 1.21 needs no note: %+v", r.Notes)
	}
	// Before 1.17 it matters, and refused is told apart from missing: one note, not two
	// contradicting each other.
	f.copies = map[string]string{"go.mod": "module m\n\ngo 1.16\n\nrequire a.com/x v1.0.0\n", "go.sum": "!a symlink, not read"}
	r, _, _ := All.ReadWith("go.mod", f.open)
	if len(r.Notes) != 1 || r.Notes[0].Code != NoteGoPre117SumUnreadable || !strings.Contains(r.Notes[0].Reason, "a symlink") {
		t.Errorf("go 1.16 with an unreadable go.sum: %+v", r.Notes)
	}
}

// The size limit holds whatever the opener does.
func TestReadWithEnforcesTheSizeLimit(t *testing.T) {
	big := func(string) ([]byte, error) { return make([]byte, maxFileBytes+1), nil }
	if _, _, err := All.ReadWith("package-lock.json", big); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Errorf("an oversized copy: %v", err)
	}
}
