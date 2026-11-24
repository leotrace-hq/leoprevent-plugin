package imports

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/limits"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

// A literal password in the datasource travels like any other line: a file sent for
// review is never masked, so a hardcoded secret is there for the secret rules to catch.
const testPrismaSchema = `generator client {
  provider = "prisma-client-js"
}

datasource db {
  provider = "postgresql"
  url      = "postgresql://app:hunter2@db.internal:5432/prod"
}

enum OrderStatus {
  draft
  booked
}

model Order {
  id             String      @id @default(uuid())
  merchantId     String
  driverId       String?
  status         OrderStatus
  priceCents     Int
  marginCents    Int
  driverPayCents Int
  internalNotes  String?
  driver         Driver?     @relation(fields: [driverId], references: [id])
}

model Driver {
  id           String  @id @default(uuid())
  name         String
  payRateCents Int
  orders       Order[]
}
`

const testPrismaRoute = `import { Router } from "express";
import { prisma } from "../db";

export const router = Router();

router.get("/orders", async (req, res) => {
  const orders = await prisma.order.findMany({
    where: { merchantId: req.user.merchantId },
    include: { driver: true },
  });
  res.json(orders);
});
`

// prismaRepo writes files into a fresh checkout and returns its root. The Prisma
// step runs only on a real checkout, so every test here uses one.
func prismaRepo(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, body := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// prismaOut runs the Prisma step alone with a generous budget, the way delivery
// does after the import resolver.
func prismaOut(root string, changes []Change, reports ...func(string, string)) []wire.ContextFile {
	var report func(string, string)
	if len(reports) > 0 {
		report = reports[0]
	}
	var out []wire.ContextFile
	for _, pf := range PrismaContext(root, changes, NewPrismaBudget(128*1024), nil, report) {
		out = append(out, pf.Schemas...)
	}
	return out
}

func prismaChange(rel, src string) Change {
	return Change{FilePath: rel, AddedText: src, FullContent: src}
}

func contextByPath(out []wire.ContextFile, rel string) (wire.ContextFile, bool) {
	for _, c := range out {
		if c.Path == rel {
			return c, true
		}
	}
	return wire.ContextFile{}, false
}

// Two changed files querying the same schema send it once.
func TestPrismaSchemaSentOncePerTurn(t *testing.T) {
	src := prismaRepo(t, map[string]string{"prisma/schema.prisma": testPrismaSchema})
	out := prismaOut(src, []Change{prismaChange("src/a.ts", testPrismaRoute), prismaChange("src/b.ts", testPrismaRoute)})
	if len(out) != 1 {
		t.Fatalf("want the schema once, got %d files", len(out))
	}
}

// On a real checkout the conventional path is found by probing, and a symlinked
// schema is refused by the same guard as any other file.
func TestPrismaCheckoutProbeAndSymlinkGuard(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("prisma/schema.prisma", testPrismaSchema)
	write("src/routes/orders.ts", testPrismaRoute)
	out := prismaOut(root, []Change{prismaChange("src/routes/orders.ts", testPrismaRoute)})
	if _, ok := contextByPath(out, "prisma/schema.prisma"); !ok {
		t.Fatalf("probe did not find prisma/schema.prisma: %+v", out)
	}

	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "schema.prisma"), []byte(testPrismaSchema), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "prisma", "schema.prisma")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "schema.prisma"), filepath.Join(root, "prisma", "schema.prisma")); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	if out := prismaOut(root, []Change{prismaChange("src/routes/orders.ts", testPrismaRoute)}); len(out) != 0 {
		t.Fatalf("symlinked schema must not be read: %+v", out)
	}
}

// Fix 3: the search stops at the changed file's own package. apps/api has a
// package.json and no schema, so the root app's schema is never used for it.
func TestPrismaStopsAtPackageBoundary(t *testing.T) {
	root := prismaRepo(t, map[string]string{
		"package.json":          `{"name":"root"}`,
		"prisma/schema.prisma":  testPrismaSchema,
		"apps/api/package.json": `{"name":"api","dependencies":{"@acme/db":"*"}}`,
	})
	if out := prismaOut(root, []Change{prismaChange("apps/api/src/orders.ts", testPrismaRoute)}); len(out) != 0 {
		t.Fatalf("a schema above the package must not be used: %+v", out)
	}
	if _, ok := contextByPath(prismaOut(root, []Change{prismaChange("src/orders.ts", testPrismaRoute)}), "prisma/schema.prisma"); !ok {
		t.Fatal("the root package's own schema should still be found")
	}
}

// A change that only deletes lines (removing a `select`) still brings the schema.
func TestPrismaRemovalOnlyChange(t *testing.T) {
	root := prismaRepo(t, map[string]string{"prisma/schema.prisma": testPrismaSchema})
	c := Change{FilePath: "src/routes/orders.ts", AddedText: "", FullContent: testPrismaRoute}
	if _, ok := contextByPath(prismaOut(root, []Change{c}), "prisma/schema.prisma"); !ok {
		t.Fatal("a removal-only change should still bring the schema")
	}
}

// A schema file the turn edits is not sent again (it travels as the change); its
// sibling in the same folder still is.
func TestPrismaChangedSchemaNotResent(t *testing.T) {
	root := prismaRepo(t, map[string]string{
		"prisma/schema/orders.prisma":  "model Order {\n  id String @id\n}\n",
		"prisma/schema/drivers.prisma": "model Driver {\n  id String @id\n  payRateCents Int\n}\n",
	})
	out := prismaOut(root, []Change{
		prismaChange("src/routes/orders.ts", testPrismaRoute),
		prismaChange("prisma/schema/orders.prisma", "model Order {\n  id String @id\n}\n"),
	})
	if len(out) != 1 || out[0].Path != "prisma/schema/drivers.prisma" {
		t.Fatalf("want drivers.prisma only (orders.prisma travels as the change), got %+v", out)
	}
}

// The trigger: any JS/TS change in a package with a Prisma schema sends the schema, whether or not the file queries anything; a non-JS change, or a package with
// no schema, sends nothing.
func TestPrismaTrigger(t *testing.T) {
	root := prismaRepo(t, map[string]string{
		"apps/api/package.json":         `{"name":"api"}`,
		"apps/api/prisma/schema.prisma": testPrismaSchema,
		"apps/web/package.json":         `{"name":"web"}`,
	})
	for _, tc := range []struct {
		file string
		want int
	}{
		{"apps/api/src/util.ts", 1},
		{"apps/api/README.md", 0},
		{"apps/web/src/page.tsx", 0},
	} {
		out := prismaOut(root, []Change{prismaChange(tc.file, "export const n = 1;\n")})
		if len(out) != tc.want {
			t.Errorf("%s: %d context files, want %d: %+v", tc.file, len(out), tc.want, out)
		}
	}
}

// A multi-file schema in prisma/schema/ sends every file of it, the
// generator-and-datasource one included.
func TestPrismaMultiFileSchemaFolder(t *testing.T) {
	root := prismaRepo(t, map[string]string{
		"prisma/schema/orders.prisma":  "model Order {\n  id String @id\n  driverPayCents Int\n}\n",
		"prisma/schema/drivers.prisma": "model Driver {\n  id String @id\n  payRateCents Int\n}\n",
		"prisma/schema/schema.prisma":  "generator client {\n  provider = \"prisma-client-js\"\n}\ndatasource db {\n  url = env(\"DATABASE_URL\")\n}\n",
	})
	out := prismaOut(root, []Change{prismaChange("src/routes/orders.ts", testPrismaRoute)})
	got := map[string]bool{}
	for _, c := range out {
		got[c.Path] = true
	}
	if len(out) != 3 || !got["prisma/schema/orders.prisma"] || !got["prisma/schema/drivers.prisma"] || !got["prisma/schema/schema.prisma"] {
		t.Fatalf("want all three files, got %+v", out)
	}
}

// Every .prisma file in the changed file's package is used, from any folder in it,
// and nothing else: not a nested package's, not node_modules', not another app's.
func TestPrismaPackageWalk(t *testing.T) {
	root := prismaRepo(t, map[string]string{
		"apps/api/package.json":                 `{"name":"api"}`,
		"apps/api/prisma/schema.prisma":         testPrismaSchema,
		"apps/api/prisma/models/extra.prisma":   "model Extra {\n  id Int\n}\n",
		"apps/api/db/legacy/old.prisma":         "model Old {\n  id Int\n}\n",
		"apps/api/tools/gen/package.json":       `{"name":"gen"}`,
		"apps/api/tools/gen/gen.prisma":         "model Gen {\n  id Int\n}\n",
		"apps/api/node_modules/x/schema.prisma": "model Dep {\n  id Int\n}\n",
		"apps/admin/package.json":               `{"name":"admin"}`,
		"apps/admin/prisma/schema.prisma":       testPrismaSchema,
	})
	out := prismaOut(root, []Change{prismaChange("apps/api/src/routes/orders.ts", testPrismaRoute)})
	got := map[string]bool{}
	for _, c := range out {
		got[c.Path] = true
	}
	want := map[string]bool{"apps/api/prisma/schema.prisma": true, "apps/api/prisma/models/extra.prisma": true, "apps/api/db/legacy/old.prisma": true}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// A schema folder reached through a directory symlink is never read.
func TestPrismaDirectorySymlinkSkipped(t *testing.T) {
	root := prismaRepo(t, map[string]string{"apps/reporting/prisma/schema.prisma": testPrismaSchema, "apps/api/package.json": `{}`})
	if err := os.Symlink(filepath.Join(root, "apps", "reporting", "prisma"), filepath.Join(root, "apps", "api", "prisma")); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	if out := prismaOut(root, []Change{prismaChange("apps/api/src/orders.ts", testPrismaRoute)}); len(out) != 0 {
		t.Fatalf("a schema through a directory symlink must not be read: %+v", out)
	}
}

// .mts and .cts changes trigger the schema too.
func TestPrismaModuleExtensions(t *testing.T) {
	root := prismaRepo(t, map[string]string{"prisma/schema.prisma": testPrismaSchema})
	for _, f := range []string{"src/orders.mts", "src/orders.cts"} {
		if _, ok := contextByPath(prismaOut(root, []Change{prismaChange(f, testPrismaRoute)}), "prisma/schema.prisma"); !ok {
			t.Errorf("%s did not trigger the schema", f)
		}
	}
}

// A symlinked package.json still marks the package, in both directions, and a nested
// git checkout is a boundary too.
func TestPrismaBoundariesAreConsistent(t *testing.T) {
	root := prismaRepo(t, map[string]string{
		"shared/package.json":           `{"name":"shared"}`,
		"prisma/schema.prisma":          "model RootOnly {\n  id Int\n}\n",
		"apps/api/prisma/schema.prisma": "model Api {\n  id Int\n}\n",
		"vendor-repo/.git/HEAD":         "ref: refs/heads/main\n",
		"vendor-repo/schema.prisma":     "model Vendored {\n  id Int\n}\n",
	})
	if err := os.Symlink(filepath.Join(root, "shared", "package.json"), filepath.Join(root, "apps", "api", "package.json")); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	out := prismaOut(root, []Change{prismaChange("apps/api/src/a.ts", "export const n = 1;\n")})
	if len(out) != 1 || out[0].Path != "apps/api/prisma/schema.prisma" {
		t.Fatalf("a symlinked manifest must still make apps/api the package: %+v", out)
	}
	for _, c := range prismaOut(root, []Change{prismaChange("src/a.ts", "export const n = 1;\n")}) {
		if strings.HasPrefix(c.Path, "vendor-repo/") || strings.HasPrefix(c.Path, "apps/") {
			t.Fatalf("the root package must not reach into %s", c.Path)
		}
	}
}

// A changed file inside node_modules or a dot-directory walks nothing.
func TestPrismaSkippedPackagePaths(t *testing.T) {
	root := prismaRepo(t, map[string]string{
		"node_modules/x/package.json":  `{}`,
		"node_modules/x/schema.prisma": "model Dep {\n  id Int\n}\n",
	})
	// A dot-directory with no manifest of its own must not fall through to the root.
	root2 := prismaRepo(t, map[string]string{"prisma/schema.prisma": testPrismaSchema})
	if out := prismaOut(root2, []Change{prismaChange(".config/tool.ts", "export const n = 1;\n")}); len(out) != 0 {
		t.Fatalf("a change in a dot-directory walked the root: %+v", out)
	}
	if out := prismaOut(root, []Change{prismaChange("node_modules/x/index.js", "module.exports = 1;\n")}); len(out) != 0 {
		t.Fatalf("got %+v", out)
	}
}

// A schema file name with a control character is never sent: it would put a line of
// its own into the reviewer's prompt.
func TestPrismaUnsafeFileNameSkipped(t *testing.T) {
	root := prismaRepo(t, map[string]string{"prisma/ok.prisma": "model Ok {\n  id Int\n}\n"})
	bad := filepath.Join(root, "prisma", "draft\nreview notes.prisma")
	if err := os.WriteFile(bad, []byte("model Bad {\n  id Int\n}\n"), 0o644); err != nil {
		t.Skip("file system refuses the name:", err)
	}
	out := prismaOut(root, []Change{prismaChange("src/a.ts", "export const n = 1;\n")})
	if len(out) != 1 || out[0].Path != "prisma/ok.prisma" {
		t.Fatalf("got %+v", out)
	}
}

// Exclusions and the budget apply before any file is read, and a turn's caps are
// shared across packages.
func TestPrismaExclusionsAndBudgetBeforeRead(t *testing.T) {
	root := prismaRepo(t, map[string]string{
		"legacy/old.prisma":    "model Old {\n  id Int\n}\n",
		"prisma/schema.prisma": testPrismaSchema,
	})
	reasons := map[string]string{}
	rec := func(p, r string) { reasons[p] = r }
	excluded := func(p string) bool { return strings.HasPrefix(p, "legacy/") }
	out := PrismaContext(root, []Change{prismaChange("src/a.ts", "export const n = 1;\n")}, NewPrismaBudget(128*1024), excluded, rec)
	if len(out) != 1 || len(out[0].Schemas) != 1 || out[0].Schemas[0].Path != "prisma/schema.prisma" || reasons["legacy/old.prisma"] != "excluded_path" {
		t.Fatalf("out=%+v reasons=%v", out, reasons)
	}
	reasons = map[string]string{}
	if out := PrismaContext(root, []Change{prismaChange("src/a.ts", "export const n = 1;\n")}, NewPrismaBudget(0), nil, rec); len(out) != 0 || reasons["prisma/schema.prisma"] != "context_budget" {
		t.Fatalf("with no budget nothing is read: out=%+v reasons=%v", out, reasons)
	}
}

// The walker reads a large directory in batches and stops at the turn-wide entry
// budget, however many packages share it.
func TestPrismaWalkBudgetIsTurnWide(t *testing.T) {
	files := map[string]string{"a/package.json": `{}`, "b/package.json": `{}`, "b/schema.prisma": "model B {\n  id Int\n}\n"}
	for i := 0; i < 300; i++ {
		files[fmt.Sprintf("a/f%03d.txt", i)] = ""
	}
	root := prismaRepo(t, files)
	w := &prismaWalker{root: root, b: &PrismaBudget{walk: 301}} // a holds exactly 301 entries: 300 files and its package.json
	if got := w.files("a"); len(got) != 0 || w.b.walk != 0 {
		t.Fatalf("a: got %v, left %d", got, w.b.walk)
	}
	if got := w.files("b"); len(got) != 0 {
		t.Fatalf("b must get nothing once the budget is spent: %v", got)
	}
}

// A file whose name holds a literal backslash is skipped: normalising it would name a
// different file, one inside a nested package the walk had skipped.
func TestPrismaBackslashNameSkipped(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a backslash is a separator on Windows")
	}
	root := prismaRepo(t, map[string]string{
		"fixtures/package.json":   `{}`,
		"fixtures/archive.prisma": "model Archived {\n  id Int\n}\n",
	})
	if err := os.WriteFile(filepath.Join(root, `fixtures\archive.prisma`), []byte("model Decoy {\n  id Int\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if out := prismaOut(root, []Change{prismaChange("src/a.ts", "export const n = 1;\n")}); len(out) != 0 {
		t.Fatalf("got %+v", out)
	}
}

// The turn's caps are shared: a budget spent on one repository leaves nothing for the
// next, and a file larger than the send budget left is not read.
func TestPrismaBudgetSharedAcrossCalls(t *testing.T) {
	one := prismaRepo(t, map[string]string{"prisma/schema.prisma": testPrismaSchema})
	two := prismaRepo(t, map[string]string{"prisma/schema.prisma": testPrismaSchema})
	b := NewPrismaBudget(128 * 1024)
	b.files = 1
	if out := PrismaContext(one, []Change{prismaChange("src/a.ts", "x\n")}, b, nil, nil); len(out) != 1 {
		t.Fatalf("first repository: %+v", out)
	}
	reasons := map[string]string{}
	if out := PrismaContext(two, []Change{prismaChange("src/a.ts", "x\n")}, b, nil, func(p, r string) { reasons[p] = r }); len(out) != 0 || reasons["prisma/schema.prisma"] != "context_budget" {
		t.Fatalf("second repository must find the file budget spent: out=%+v reasons=%v", out, reasons)
	}
	if out := PrismaContext(one, []Change{prismaChange("src/a.ts", "x\n")}, NewPrismaBudget(10), nil, nil); len(out) != 0 {
		t.Fatalf("a schema larger than the send budget left must not be read: %+v", out)
	}
}

// Every changed JS/TS file of the package is a trigger, and the schema travels whole.
func TestPrismaTriggersAndWholeFile(t *testing.T) {
	root := prismaRepo(t, map[string]string{"prisma/schema.prisma": testPrismaSchema})
	out := PrismaContext(root, []Change{prismaChange("src/a.ts", "x\n"), prismaChange("src/b.ts", "y\n"), prismaChange("README.md", "z\n")}, NewPrismaBudget(128*1024), nil, nil)
	if len(out) != 1 || len(out[0].Schemas) != 1 || out[0].Schemas[0].Content != testPrismaSchema || out[0].Schemas[0].Lines != nil || !reflect.DeepEqual(out[0].Triggers, []string{"src/a.ts", "src/b.ts"}) {
		t.Fatalf("got %+v", out)
	}
}

// A package's schemas share one trigger list: two schemas, one package entry.
func TestPrismaOneTriggerListPerPackage(t *testing.T) {
	root := prismaRepo(t, map[string]string{"prisma/a.prisma": testPrismaSchema, "prisma/b.prisma": "model B {\n  id Int\n}\n"})
	out := PrismaContext(root, []Change{prismaChange("src/a.ts", "x\n")}, NewPrismaBudget(128*1024), nil, nil)
	if len(out) != 1 || len(out[0].Schemas) != 2 || !reflect.DeepEqual(out[0].Triggers, []string{"src/a.ts"}) {
		t.Fatalf("got %+v", out)
	}
}

// An import that resolves to a .prisma file (an asset loader) is left to the Prisma
// step, so the schema is sent once, not by both.
func TestPrismaImportedSchemaSentOnce(t *testing.T) {
	root := prismaRepo(t, map[string]string{"prisma/schema.prisma": testPrismaSchema})
	route := "import schemaText from \"../prisma/schema.prisma\";\nexport const x = schemaText;\n"
	for _, c := range Resolve(root, []Change{prismaChange("src/a.ts", route)}) {
		if prismaIsSchema(c.Path) {
			t.Fatalf("the import resolver sent a schema: %+v", c)
		}
	}
	if _, ok := contextByPath(prismaOut(root, []Change{prismaChange("src/a.ts", route)}), "prisma/schema.prisma"); !ok {
		t.Fatal("the Prisma step must send it")
	}
}

// A schema larger than an imported helper may be is not read, and is reported.
func TestPrismaOversizedSchemaSkipped(t *testing.T) {
	big := "model Big {\n" + strings.Repeat("  f Int\n", limits.MaxContextFileBytes/8+1) + "}\n"
	root := prismaRepo(t, map[string]string{"prisma/schema.prisma": big})
	reasons := map[string]string{}
	if out := prismaOut(root, []Change{prismaChange("src/a.ts", "x\n")}, func(p, r string) { reasons[p] = r }); len(out) != 0 || reasons["prisma/schema.prisma"] != "context_budget" {
		t.Fatalf("out=%+v reasons=%v", out, reasons)
	}
}

// A changed path that climbs out of the repository or is absolute picks no folder to
// walk: the walk never opens anything above root.
func TestPrismaTriggerOutsideRootWalksNothing(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "repo")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(parent, "package.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(parent, "outside.prisma"), []byte("model Outside {\n  id Int\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	b := NewPrismaBudget(128 * 1024)
	walk := b.walk
	for _, p := range []string{"../x.ts", "../../x.ts", filepath.ToSlash(filepath.Join(parent, "x.ts"))} {
		if out := PrismaContext(root, []Change{prismaChange(p, "x\n")}, b, nil, nil); len(out) != 0 {
			t.Fatalf("%s: got %+v", p, out)
		}
	}
	if b.walk != walk {
		t.Fatalf("the walk opened folders for an outside path: %d entries spent", walk-b.walk)
	}
}
