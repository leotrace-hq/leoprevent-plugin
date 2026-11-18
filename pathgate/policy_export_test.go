package pathgate

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/go-enry/go-enry/v2/data"
)

var updatePolicy = flag.Bool("update-policy",
	false,
	"rewrite testdata/policy.json from the current tables")

type policyCase struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

type exportedPolicy struct {
	LockfileBasenames        []string     `json:"lockfileBasenames"`
	GeneratedSuffixes        []string     `json:"generatedSuffixes"`
	VendoredSegments         []string     `json:"vendoredSegments"`
	VendoredPathFragments    []string     `json:"vendoredPathFragments"`
	AmbiguousBuildSegments   []string     `json:"ambiguousBuildSegments"`
	TestSegments             []string     `json:"testSegments"`
	AmbiguousTestSegments    []string     `json:"ambiguousTestSegments"`
	TestBasenames            []string     `json:"testBasenames"`
	InertBackupExts          []string     `json:"inertBackupExts"`
	DatabaseBasenames        []string     `json:"databaseBasenames"`
	DatabaseNumberedPrefixes []string     `json:"databaseNumberedPrefixes"`
	DatabaseExts             []string     `json:"databaseExts"`
	DatabaseSegments         []string     `json:"databaseSegments"`
	MigrationSegments        []string     `json:"migrationSegments"`
	MigrationName            string       `json:"migrationName"`
	PrismaFolder             string       `json:"prismaFolder"`
	InertExtensions          []string     `json:"inertExtensions"`
	ChecksumBasenames        []string     `json:"checksumBasenames"`
	EnryVendor               string       `json:"enryVendor"`
	EnryTest                 []string     `json:"enryTest"`
	Cases                    []policyCase `json:"cases"`
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sorted(s []string) []string {
	out := append([]string(nil), s...)
	sort.Strings(out)
	return out
}

func pattern(r interface{}) string {
	return r.(fmt.Stringer).String()
}

func policyPaths() []string {
	paths := []string{
		"package-lock.json", "apps/web/package-lock.json", "package.json", "go.mod", "go.sum",
		"yarn.lock", "Cargo.lock", "poetry.lock", "pnpm-lock.yaml",
		"src/app.ts", "src/app.tsx", "server/main.go", "lib/handler.py", "Dockerfile", "Makefile",
		"config.yaml", "config.json", ".env.example", "logo.svg", "unknown.xyz",
		"README.md", "docs/guide.MD", "web/app.css", "web\\styles\\theme.SCSS", "logo.png",
		"README.md/handler.ts", "notes.txt", "CHANGELOG", "LICENSE",
		"src/app.test.ts", "src/app.spec.tsx", "src/app.test.js", "pkg/x_test.go", "test_api.py",
		"spec/models/user_spec.rb", "src/FooTest.java", "test/FooTest.java", "tests/FooTest.php",
		"app/UserTest.php", "app/UserTestCase.php", "app/user_test.php", "Test.php", "Tests/FooTests.cs",
		"src/test/scala/FooSpec.scala", "test/helper.ts", "tests/helper.ts", "test", "tests",
		"src/tests/helper.ts", "/abs/tests/helper.ts", "/abs/test/helper.ts",
		"e2e/login.ts", "apps/web/e2e/login.ts", "cypress/support/commands.ts", "playwright/fixtures.ts",
		"src/__tests__/a.ts", "src/__snapshots__/a.snap", "cypress.cy.js", "src/app.cy.ts",
		"vitest.config.ts", "jest.config.js", "apps/web/playwright.config.ts", "conftest.py",
		"tsconfig.spec.json", "tsconfig.json",
		"node_modules/react/index.js", "web/node_modules/x/y.js", "vendor/github.com/x/y.go",
		"dist/bundle.js", "build/out.js", "/abs/build/out.js", "src/build.ts", "out/index.js", "target/x.class",
		"cmake-build-debug/main.o", "cmake-builder/main.c", ".next/server/page.js", ".venv/lib/x.py",
		"third_party/lib.go", "third-party/lib.go", "Godeps/_workspace/x.go", ".github/workflows/ci.yml",
		"ci/.github/workflows/deploy.yaml", ".github/CODEOWNERS", ".github/dependabot.yml", "Jenkinsfile",
		"ci/Jenkinsfile", ".vscode/settings.json", ".gitignore", ".gitattributes", "types/index.d.ts",
		"src/global.d.ts", "jquery.min.js", "static/jquery-3.6.0.js", "cache/x.ts", "env/x.py",
		"django/core/cache/backends/filebased.py", "src/cache/foo.py", `src\cache\foo.py`,
		"src/cmd/go/internal/cache/cache.go", "tools/cache/reflector.go",
		"activesupport/lib/active_support/cache/redis_cache_store.rb",
		"cache/node_modules/pkg/index.js", "node_modules/pkg/cache/index.js",
		"cache/vendor/pkg/lib.go", "cache/react.js", "cache/.cache/data.py", "cache/__pycache__/data.py",
		".pnp/cache/pkg/index.js", "web/.pnp/cache/pkg/index.js", `web\.pnp\cache\pkg\index.js`,
		".pnp/src/helper.js", "cache/.pnp/cache/pkg/index.js",
		"docs/_build/index.html", "testdata/sample.json", "deps/x.c", "Dependencies/x.c", "debian/rules",
		"gradlew", "mvnw", "Vagrantfile", "fabfile.py", "src/react.js", "src/react-dom.js", "src/Chart.js",
		"packages/foo.1.2/lib.cs",
		"src/api.pb.go", "src/api_pb2.py", "src/schema.gen.ts", "src/types.generated.ts",
		"zz_generated.deepcopy.go", "app.min.css", "app.bundle.js", "model.freezed.dart",
		"db/migrations/20240101120000_create_users.sql", "db/migrations/0001_init.sql",
		"db/migrations/001_init.sql", "db/migrations/V1__init.sql", "db/migrations/V1.2__x.sql",
		"migrations/version20240101120000.php", "prisma/migrations/20240101_init/migration.sql",
		"prisma/migrations/init/migration.sql", "db/migrations/README.md", "db/migrations/helpers.ts",
		"src/migrate/20240101_x.ts", "migrations.sql", "20240101_x.sql",
		"data/db/WiredTiger", "data/db/collection-0.wt", "pgdata/base/16384/1259", "pgdata/base/16384/1259_fsm",
		"pgdata/base/16384/1259.1", "pgdata/global/1262", "pgdata/pg_wal/000000010000000000000001",
		"mysql/ibdata1", "mysql/ib_logfile0", "mysql/mysql-bin.000001", "redis/appendonly.aof",
		"data/x.sqlite-wal", "dump.bson", "backup.pgdump", "base/a/1259", "global/x1",
		"src/app.ts~", "src/.#app.ts", "src/#app.ts#", "src/app.ts.bak", "src/app.ts.bak.1",
		"src/app.orig.2", "src/app.ts.old", "src/app.ts.1",
		"SHA256SUMS", "dist/sha512sums", "checksums.txt",
		"src/STYLE.CSS", "a.b.c.md", ".md", "noext", "dir.md/file", "dir/.hidden",
	}
	for _, k := range keys(lockfileBasenames) {
		paths = append(paths, "pkg/"+k)
	}
	for _, s := range generatedSuffixes {
		paths = append(paths, "src/file"+s)
	}
	for _, k := range keys(vendoredSegments) {
		paths = append(paths, "a/"+k+"/x.ts", k)
	}
	for _, fragment := range vendoredPathFragments {
		rooted := fragment[1:]
		paths = append(paths, rooted+"x.ts", "app/"+rooted+"x.ts", strings.ReplaceAll(rooted+"x.ts", "/", `\`))
		paths = append(paths, strings.TrimSuffix(rooted, "/")+"able/x.ts")
	}
	for _, k := range keys(ambiguousBuildSegments) {
		paths = append(paths, "a/"+k+"/x.ts", "/abs/"+k+"/x.ts")
	}
	for _, k := range keys(testSegments) {
		paths = append(paths, "a/"+k+"/x.ts")
	}
	for _, k := range keys(testBasenames) {
		paths = append(paths, "a/"+k)
	}
	for _, k := range keys(inertBackupExts) {
		paths = append(paths, "a/x"+k+".3")
	}
	for _, k := range keys(databaseBasenames) {
		paths = append(paths, "data/"+k)
	}
	for _, k := range databaseNumberedPrefixes {
		paths = append(paths, "data/"+k+"42", "data/"+k+"x")
	}
	for _, k := range keys(databaseExts) {
		paths = append(paths, "data/x"+k)
	}
	for _, k := range keys(databaseSegments) {
		paths = append(paths, "data/"+k+"/x")
	}
	for _, k := range keys(inertExtensions) {
		paths = append(paths, "a/x"+k)
	}
	for _, k := range keys(checksumBasenames) {
		paths = append(paths, "a/"+k)
	}
	return paths
}

func currentPolicy() exportedPolicy {
	enryTest := make([]string, 0, len(data.TestMatchers))
	for _, m := range data.TestMatchers {
		enryTest = append(enryTest, pattern(m))
	}
	p := exportedPolicy{
		LockfileBasenames:        keys(lockfileBasenames),
		GeneratedSuffixes:        sorted(generatedSuffixes),
		VendoredSegments:         keys(vendoredSegments),
		VendoredPathFragments:    sorted(vendoredPathFragments),
		AmbiguousBuildSegments:   keys(ambiguousBuildSegments),
		TestSegments:             keys(testSegments),
		AmbiguousTestSegments:    keys(ambiguousTestSegments),
		TestBasenames:            keys(testBasenames),
		InertBackupExts:          keys(inertBackupExts),
		DatabaseBasenames:        keys(databaseBasenames),
		DatabaseNumberedPrefixes: sorted(databaseNumberedPrefixes),
		DatabaseExts:             keys(databaseExts),
		DatabaseSegments:         keys(databaseSegments),
		MigrationSegments:        keys(migrationSegments),
		MigrationName:            migrationName.String(),
		PrismaFolder:             prismaFolder.String(),
		InertExtensions:          keys(inertExtensions),
		ChecksumBasenames:        keys(checksumBasenames),
		EnryVendor:               pattern(enryVendorWithoutCache),
		EnryTest:                 enryTest,
	}
	for _, path := range policyPaths() {
		p.Cases = append(p.Cases, policyCase{Path: path, Reason: InertReason(path)})
	}
	return p
}

func TestPolicyExport_MatchesTables(t *testing.T) {
	// Arrange
	file := filepath.Join("testdata", "policy.json")
	want, err := json.MarshalIndent(currentPolicy(), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	want = append(want, '\n')

	// Act
	if *updatePolicy {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, want, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(file)

	// Assert
	if err != nil {
		t.Fatalf("read %s: %v (run go test ./pathgate -run TestPolicyExport -update-policy)", file, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s is stale; run: go test ./pathgate -run TestPolicyExport -update-policy, then copy the tables into packages/metrics/src/pathgate-policy.json", file)
	}
}
