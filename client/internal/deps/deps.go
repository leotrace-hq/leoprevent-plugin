// Package deps reads the files that record a project's dependencies, on the developer's machine,
// into one format: each package's name, version and where it was read from (LEO-511, LEO-517).
// It reads only the standard library and the file it is given; it never runs a package manager,
// never resolves a version and sends nothing. What is sent, and when, is the caller's decision
// (the dependency check, POST /dependencies, decision D57 in the server's design record).
//
// Compare marks each dependency against the start of the turn (added, changed, unchanged, and
// what was removed), so the caller can send the turn's diff, or the whole file with the diff
// marked (decision D58).
//
// One reader per file type, picked by file name from All: adding an ecosystem is a new Reader and
// one entry in All, with no change anywhere else.
package deps

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Dependency is one package at one version, as a project file records it.
type Dependency struct {
	// Ecosystem in OSV's spelling: "npm", "Go".
	Ecosystem string
	Name      string
	// Version as recorded, e.g. "4.17.15" or "v0.31.0".
	Version string
	// Location is where it was read from: "node_modules/axios", "go.mod:12".
	Location string
	// Key identifies this copy of the package between two readings of the file, so Compare can
	// match them: npm's install folder (one package can be installed in several), Go's module path
	// (its line moves when lines above it change).
	Key string
	// Line is the line it is declared on, when the file has one that means something (go.mod);
	// 0 otherwise. A lockfile's line is in a file nobody edits by hand, so it's left out.
	Line int
	// Indirect: pulled in by another package, rather than asked for by the project.
	Indirect bool
	// Dev: only needed for development (npm's "dev": true), never installed for production.
	Dev bool
	// DevOptional: reached only through development or optional dependencies (npm's
	// "devOptional": true). Nothing requires it at runtime, but an install that leaves out
	// development dependencies still installs it, so it isn't Dev. At most one of the two is set.
	DevOptional bool
	// Private: it may not be a public package (it came from another registry, a company mirror,
	// or nowhere recorded).
	Private bool
}

// Reading is what a reader got from a file and its companions: the dependencies, and notes on
// how complete that is (a go.mod written before Go 1.17 doesn't list every module the build
// uses).
type Reading struct {
	Dependencies []Dependency
	Notes        []Note
}

// Note says how a reading falls short of the whole picture, as a code rather than wording: what
// the developer is told is written on the server, like every other notice, so it can change
// without a plugin release, and a dashboard can count notes by code.
type Note struct {
	// Code is one of the Note* constants.
	Code string
	// File is the file the note is about, when it isn't the one read ("go.sum").
	File string
	// Go is the go line as written ("1.16"); "" when go.mod has none.
	Go string
	// Reason is why a file couldn't be read, for NoteGoPre117SumUnreadable and NoteFileUnreadable.
	Reason string
	// Count is how many dependencies the note is about (NoteGoPre117FromSum).
	Count int
}

// What a Note can say.
const (
	// NoteGoPre117FromSum: go.mod is older than Go 1.17 (or has no go line), so it doesn't list
	// every module the build uses; Count more were read from go.sum as a best effort, at the
	// highest version it has code for, which may not be the one built.
	NoteGoPre117FromSum = "go_pre_117_from_sum"
	// NoteGoPre117NoSum: as above, with no go.sum beside it, so those modules aren't checked.
	NoteGoPre117NoSum = "go_pre_117_no_sum"
	// NoteGoPre117SumUnreadable: as above, and a go.sum is there but couldn't be read (a symlink,
	// too large), so those modules aren't checked.
	NoteGoPre117SumUnreadable = "go_pre_117_sum_unreadable"
	// NoteFileUnreadable: the dependency file itself couldn't be read, so none of it was checked.
	NoteFileUnreadable = "file_unreadable"
)

func (n Note) String() string {
	parts := []string{n.Code}
	if n.File != "" {
		parts = append(parts, "file="+n.File)
	}
	if n.Code != NoteFileUnreadable {
		parts = append(parts, "go="+n.Go)
	}
	if n.Count > 0 {
		parts = append(parts, fmt.Sprintf("count=%d", n.Count))
	}
	if n.Reason != "" {
		parts = append(parts, "reason="+n.Reason)
	}
	return strings.Join(parts, " ")
}

// Companion is a file read from beside the main one. Err is set when it's there but couldn't be
// read; a companion that isn't there at all is simply absent from Companions, so a reader can
// tell "none" from "refused".
type Companion struct {
	Data []byte
	Err  error
}

// Companions are a reader's companion files, by name.
type Companions map[string]Companion

// Reader turns one kind of file into dependencies.
type Reader interface {
	// Ecosystem is the ecosystem its packages belong to: "npm", "Go".
	Ecosystem() string
	// Files lists the file names it reads, e.g. "package-lock.json".
	Files() []string
	// Companions lists files read from beside the main one when present (go.sum beside go.mod).
	Companions() []string
	// Read reads the file, with each companion that is there (read, or refused).
	Read(data []byte, companions Companions) (Reading, error)
}

// Readers is a set of readers, picked between by file name.
type Readers []Reader

// All is every reader there is.
var All = Readers{NPM{}, GoMod{}}

// For returns the reader for the file at path, by its name, or false when no reader reads it.
func (rs Readers) For(path string) (Reader, bool) {
	base := filepath.Base(path)
	for _, r := range rs {
		for _, f := range r.Files() {
			if f == base {
				return r, true
			}
		}
	}
	return nil, false
}

// Files lists every file name some reader reads, sorted.
func (rs Readers) Files() []string {
	var out []string
	for _, r := range rs {
		out = append(out, r.Files()...)
	}
	sort.Strings(out)
	return out
}

// maxFileBytes bounds one file. No real go.mod comes near it; a very large npm lockfile is a few
// megabytes.
const maxFileBytes = 64 << 20

// Opener returns the bytes of the file at path, wherever the copy comes from: Disk for the file as
// it is now, or the copy at the start of the turn (the git baseline). A file that isn't there is
// an error satisfying errors.Is(err, fs.ErrNotExist). Paths are the OS's (path/filepath); an
// opener reading from git converts them with filepath.ToSlash.
//
// ⚠️ AN OPENER MUST REFUSE WHAT readBounded REFUSES: a symlink (git stores one as a small blob
// holding the link's target, mode 120000, so reading it gives a path, not a lockfile), anything
// that isn't an ordinary file, and anything over maxFileBytes. ReadWith re-checks the size; it
// can't tell a symlink's blob from a file's.
type Opener func(path string) ([]byte, error)

// Disk reads the file as it is now, refusing a symlink and anything over maxFileBytes.
var Disk Opener = readBounded

// ReadFile reads the file at path from disk, with its companions from the same folder.
func (rs Readers) ReadFile(path string) (Reading, Reader, error) {
	return rs.ReadWith(path, Disk)
}

// ReadWith reads the file at path with the reader that reads it, and that reader's companions
// from the same folder, every one through open: the start-of-turn copy of a go.mod is read with
// the start-of-turn go.sum, never today's. The reader decides which files: nothing else is opened.
//
// A companion that isn't there is left out; one that is there but couldn't be read (a symlink,
// too large) is passed on as refused, and the reader decides whether that matters (it only does
// when the reader needed the file).
func (rs Readers) ReadWith(path string, open Opener) (Reading, Reader, error) {
	r, ok := rs.For(path)
	if !ok {
		return Reading{}, nil, fmt.Errorf("%s: not a supported file (supported: %s)", filepath.Base(path), strings.Join(rs.Files(), ", "))
	}
	data, err := openBounded(open, path)
	if err != nil {
		return Reading{}, r, err
	}
	companions := Companions{}
	for _, name := range r.Companions() {
		b, err := openBounded(open, filepath.Join(filepath.Dir(path), name))
		switch {
		case err == nil:
			companions[name] = Companion{Data: b}
		case !errors.Is(err, fs.ErrNotExist):
			companions[name] = Companion{Err: err}
		}
	}
	reading, err := r.Read(data, companions)
	if err != nil {
		return Reading{}, r, fmt.Errorf("%s: %w", path, err)
	}
	return reading, r, nil
}

// openBounded opens through open and enforces maxFileBytes whatever the opener did.
func openBounded(open Opener, path string) ([]byte, error) {
	data, err := open(path)
	if err != nil {
		return nil, err
	}
	if len(data) > maxFileBytes {
		return nil, fmt.Errorf("%s: over the %d-byte limit", path, maxFileBytes)
	}
	return data, nil
}

// readBounded reads a regular file, refusing a symlink (the plugin never follows one: it could
// point anywhere on the machine) and anything over maxFileBytes.
//
// ⚠️ OPEN FIRST, THEN PROVE WHAT WAS OPENED, the same order as vcs's changed-file read and for
// the same reason. Checking the path and then reading it is check-then-use: the file can be
// swapped for a symlink or a larger file in between. So the bytes come from the descriptor
// already open, and os.SameFile proves that descriptor wasn't reached through a link: Lstat
// describes the link itself and Stat its target, so a symlink gives two different files. A
// mode check on the descriptor alone can't tell, because opening has already followed the link.
// The size is enforced while reading too, so a file that grows after the check is still cut off.
func readBounded(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, statErr := f.Stat()
	onDisk, lstatErr := os.Lstat(path)
	if statErr != nil || lstatErr != nil || !opened.Mode().IsRegular() || !os.SameFile(opened, onDisk) {
		return nil, fmt.Errorf("%s: not a regular file (a symlink or a directory), not read", path)
	}
	if opened.Size() > maxFileBytes {
		return nil, fmt.Errorf("%s: %d bytes, over the %d-byte limit", path, opened.Size(), maxFileBytes)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxFileBytes {
		return nil, fmt.Errorf("%s: over the %d-byte limit", path, maxFileBytes)
	}
	return data, nil
}
