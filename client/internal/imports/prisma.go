package imports

import (
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/leotrace-hq/leoprevent-plugin/limits"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

// Prisma schema context (LEO-925).
//
// A Prisma query names its model through the client, not through an import:
// `db.order.findMany()` reaches the Order model defined in a .prisma schema that no
// code imports, and the TypeScript types for it are generated into node_modules. So
// the import resolver never sends the schema, and a reviewer asked "does this
// response leak driver pay?" cannot see that the row HAS a driverPayCents column.
// Measured: a whole-row return reviewed 0/5 with the real `@prisma/client` import and
// 5/5 once the schema is visible.
//
// Deliberately blunt:
//
//   - No query detection. Any turn that changes a JS/TS file sends the schemas of its
//     PACKAGE (the nearest package.json or git root, else the repository root).
//   - No schema selection. Every .prisma file in the package is sent.
//   - The file travels whole, read by the same safeRead as an imported helper, with the
//     same secret-path and symlink guards and nothing masked: like any file sent for
//     review, a literal secret in it is what the secret rules exist to catch.
//
// It runs as its own step (PrismaContext), after the import resolver, so imported
// helpers keep their budget across every repository of the turn, and the caller can
// place each schema in the request that carries its package's changes.

const (
	prismaMaxFiles = 50    // .prisma files read in one turn
	prismaMaxWalk  = 20000 // directory entries visited in one turn
)

// PrismaPackage is one package's schema files and the changed files that brought them
// in.
type PrismaPackage struct {
	Schemas  []wire.ContextFile
	Triggers []string // every changed JS/TS file in that package, as the caller named it
}

// PrismaBudget is one turn's allowance, shared by every repository the turn touches:
// the bytes that may be sent, and the walk and file limits.
type PrismaBudget struct {
	Send  int // context bytes left to send
	walk  int
	files int
}

// NewPrismaBudget starts a turn's allowance with send bytes to spend.
func NewPrismaBudget(send int) *PrismaBudget {
	return &PrismaBudget{Send: send, walk: prismaMaxWalk, files: prismaMaxFiles}
}

// PrismaContext returns the .prisma files in the packages of the turn's changed JS/TS
// files under root, whole, spending from b. A file the turn itself changes is not
// sent again, nor one excluded reports true for, nor one larger than an imported
// helper may be; every file considered gets a disposition through report. Checkout
// only: it reads disk.
func PrismaContext(root string, changes []Change, b *PrismaBudget, excluded func(string) bool, report func(string, string)) []PrismaPackage {
	if report == nil {
		report = func(string, string) {}
	}
	changed := map[string]bool{}
	var pkgs []string
	triggers := map[string][]string{}
	for _, c := range changes {
		changed[norm(c.FilePath)] = true
		// A literal backslash would be read as a separator by norm, naming a different
		// file than the one on disk.
		if !prismaTrigger(c.FilePath) || strings.ContainsRune(c.FilePath, '\\') || prismaInSkippedDir(c.FilePath) {
			continue
		}
		pkg := prismaPackageRoot(root, c.FilePath)
		if _, seen := triggers[pkg]; !seen {
			pkgs = append(pkgs, pkg)
		}
		triggers[pkg] = append(triggers[pkg], c.FilePath)
	}
	w := &prismaWalker{root: root, b: b}
	var out []PrismaPackage
	for _, pkg := range pkgs {
		var schemas []wire.ContextFile
		for _, rel := range w.files(pkg) {
			switch {
			case changed[rel]:
				continue // travels as the change itself
			case excluded != nil && excluded(rel):
				report(rel, "excluded_path")
				continue
			case b.Send <= 0 || b.files <= 0:
				report(rel, "context_budget")
				continue
			}
			// Sized before reading: a file too big to send is never read.
			if fi, err := os.Lstat(filepath.Join(root, filepath.FromSlash(rel))); err != nil || fi.Size() > int64(min(limits.MaxContextFileBytes, b.Send)) {
				report(rel, "context_budget")
				continue
			}
			b.files--
			body, ok := safeRead(root, rel)
			if !ok {
				report(rel, "context_unavailable")
				continue
			}
			if len(body) > limits.MaxContextFileBytes || len(body) > b.Send {
				report(rel, "context_budget") // grew after it was sized
				continue
			}
			b.Send -= len(body)
			report(rel, "sent")
			schemas = append(schemas, wire.ContextFile{Path: rel, Content: body})
		}
		if len(schemas) > 0 {
			out = append(out, PrismaPackage{Schemas: schemas, Triggers: triggers[pkg]})
		}
	}
	return out
}

// prismaTrigger reports whether a changed file is one whose package's schemas are
// sent: any JS or TS source.
func prismaTrigger(rel string) bool {
	switch strings.ToLower(path.Ext(rel)) {
	case ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts":
		return true
	}
	return false
}

// prismaIsSchema is the one extension check: any case of .prisma.
func prismaIsSchema(rel string) bool { return strings.EqualFold(path.Ext(rel), ".prisma") }

// ---- discovery ----

// prismaBoundary reports whether dir starts a package or repository of its own: it
// holds a package.json or a .git entry. Metadata only, whatever kind of entry it is
// (a symlinked manifest still marks a package), and the same test in both directions.
func prismaBoundary(root, dir string) bool {
	for _, marker := range []string{"package.json", ".git"} {
		if _, err := os.Lstat(filepath.Join(root, filepath.FromSlash(atDir(dir, marker)))); err == nil {
			return true
		}
	}
	return false
}

// prismaPackageRoot is the nearest directory at or above the changed file that is a
// package or repository boundary, else the repository root.
func prismaPackageRoot(root, changedRel string) string {
	dir := path.Dir(norm(changedRel))
	for dir != "." && dir != "/" && dir != "" {
		if prismaBoundary(root, dir) {
			return dir
		}
		dir = path.Dir(dir)
	}
	return "."
}

// prismaInSkippedDir reports whether a changed file sits below a directory the walker
// skips (node_modules, a dot-directory): such a file brings in no schema, not even
// the root package's. ".." starts with a dot too, so a path that climbs out of root
// never picks a folder to walk: every folder the walk opens is root or below it.
func prismaInSkippedDir(rel string) bool {
	for _, part := range strings.Split(path.Dir(norm(rel)), "/") {
		if part != "." && prismaSkipDir(part) {
			return true
		}
	}
	return false
}

// prismaSkipDir is the walker's one skip policy for a directory name.
func prismaSkipDir(name string) bool {
	return name == "node_modules" || strings.HasPrefix(name, ".")
}

// prismaWalker lists .prisma files package by package under one turn-wide budget of
// directory entries, reading each directory in batches so one huge directory cannot
// be loaded whole.
type prismaWalker struct {
	root string
	b    *PrismaBudget
}

// files lists the .prisma files in one package, sorted: never entering a skipped
// directory, a nested package or repository, or a symlink, and never returning a
// path the decision log would refuse (control characters, secret names).
func (w *prismaWalker) files(pkg string) []string {
	// pkg itself never sits below a skipped directory: such a trigger is dropped first.
	var out []string
	stack := []string{pkg}
	for len(stack) > 0 && w.b.walk > 0 {
		dir := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		// Non-blocking, and checked to be a directory: a FIFO swapped in for a
		// queued folder is refused rather than waited on.
		f, err := os.OpenFile(filepath.Join(w.root, filepath.FromSlash(dir)), os.O_RDONLY|prismaOpenFlags, 0)
		if err != nil {
			continue
		}
		if fi, err := f.Stat(); err != nil || !fi.IsDir() {
			f.Close()
			continue
		}
		for w.b.walk > 0 {
			ents, err := f.ReadDir(256)
			for _, e := range ents {
				if w.b.walk <= 0 {
					break // the turn's entry budget is spent mid-batch
				}
				w.b.walk--
				rel := atDir(dir, e.Name())
				if wire.SafeDecisionPath(rel) == "" || strings.ContainsAny(e.Name(), "/\\") {
					continue
				}
				switch t := e.Type(); {
				case t&fs.ModeSymlink != 0:
				case t.IsDir():
					if !prismaSkipDir(e.Name()) && !prismaBoundary(w.root, rel) {
						stack = append(stack, rel)
					}
				case t.IsRegular() && prismaIsSchema(rel):
					out = append(out, rel)
				}
			}
			if err != nil {
				break // io.EOF or a read error: done with this directory
			}
		}
		f.Close()
	}
	sort.Strings(out)
	return out
}

func atDir(dir, rel string) string {
	if dir == "." {
		return norm(rel)
	}
	return join(dir, rel)
}
