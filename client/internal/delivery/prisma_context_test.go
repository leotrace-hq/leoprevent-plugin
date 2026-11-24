package delivery

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/apiclient"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
	"github.com/leotrace-hq/leoprevent-plugin/limits"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

const deliverySchema = "datasource db {\n  url = \"postgresql://app:hunter2@db/prod\"\n}\nmodel Order {\n  id String @id\n  driverPayCents Int\n}\n"

// Schemas are labelled by repository, carry their trigger, travel whole, and an
// organisation-excluded schema is not sent.
func TestResolvePrismaContextAcrossRepos(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	ws := t.TempDir()
	gitRepo(t, filepath.Join(ws, "api"), map[string]string{"prisma/schema.prisma": deliverySchema, "src/a.ts": "export const n = 1;\n"})
	gitRepo(t, filepath.Join(ws, "web"), map[string]string{"legacy/old.prisma": deliverySchema, "src/b.ts": "export const n = 1;\n"})
	changes := []transcript.Change{
		{FilePath: "api/src/a.ts", RepoDir: "api", RepoRoot: filepath.Join(ws, "api"), AddedText: "export const n = 1;\n"},
		{FilePath: "web/src/b.ts", RepoDir: "web", RepoRoot: filepath.Join(ws, "web"), AddedText: "export const n = 1;\n", ExcludedPaths: []string{"legacy/**"}},
	}
	decisions := wire.NewFileDecisions()
	got := resolvePrismaContext(ws, changes, 128*1024, decisions)
	if len(got) != 1 || len(got[0].files) != 1 || got[0].files[0].Path != "api/prisma/schema.prisma" || !reflect.DeepEqual(got[0].triggers, []repoPath{{"api", "api/src/a.ts"}}) {
		t.Fatalf("got %+v", got)
	}
	if c := got[0].files[0].Content; c != deliverySchema {
		t.Fatalf("content: %q", c)
	}
}

// The helpers come first: the Prisma step only spends what they left.
func TestResolvePrismaContextSpendsOnlyTheRemainingBudget(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	ws := t.TempDir()
	gitRepo(t, filepath.Join(ws, "api"), map[string]string{"prisma/schema.prisma": deliverySchema})
	changes := []transcript.Change{{FilePath: "api/src/a.ts", RepoDir: "api", RepoRoot: filepath.Join(ws, "api"), AddedText: "x\n"}}
	if got := resolvePrismaContext(ws, changes, 10); len(got) != 0 {
		t.Fatalf("a schema larger than the remaining budget must not be sent: %+v", got)
	}
}

// Each package's schemas ride every batch holding one of its package's changes, once per
// batch, and no other: not one whose change merely has the same wire path in another
// repository, and not a fallback batch when none holds a trigger.
func TestPrismaByBatch(t *testing.T) {
	batches := [][]wire.ChangedFile{
		{{Path: "py/big.py"}, {Path: "api/src/orders.ts"}}, // the working directory's own api/ folder
		{{Path: "api/src/orders.ts", RepoLabel: "api"}, {Path: "api/src/more.ts", RepoLabel: "api"}},
		{{Path: "api/src/report.ts", RepoLabel: "api"}},
	}
	prisma := []prismaList{
		{files: []wire.ContextFile{{Path: "api/prisma/schema.prisma"}}, triggers: []repoPath{{"api", "api/src/orders.ts"}, {"api", "api/src/more.ts"}, {"api", "api/src/report.ts"}}},
		{files: []wire.ContextFile{{Path: "x/schema.prisma"}}, triggers: []repoPath{{"", "nowhere.ts"}}},
	}
	got := prismaByBatch(batches, prisma)
	if len(got[0]) != 0 ||
		len(got[1]) != 1 || got[1][0].Path != "api/prisma/schema.prisma" ||
		len(got[2]) != 1 || got[2][0].Path != "api/prisma/schema.prisma" {
		t.Fatalf("got %+v", got)
	}
}

// End to end through Cloud.Review: two schemas of a labelled repository ride the
// request holding that repository's change, never the unrelated first one.
func TestCloudSendsPrismaListsWithTheirChange(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	ws := t.TempDir()
	gitRepo(t, filepath.Join(ws, "py"), map[string]string{"big.py": "x = 1\n"})
	gitRepo(t, filepath.Join(ws, "api"), map[string]string{
		"prisma/a.prisma": deliverySchema, "prisma/b.prisma": "model Driver {\n  id String @id\n  payRateCents Int\n}\n",
		"src/a.ts": "export const n = 1;\n",
	})
	var reqs []wire.ReviewRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req wire.ReviewRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		reqs = append(reqs, req)
		_, _ = w.Write([]byte(`{"verdict":"clean","review_id":"rv"}`))
	}))
	t.Cleanup(srv.Close)

	// Each change just over half a request, so each is a batch of its own.
	big := strings.Repeat("x", limits.MaxReviewBytes/2+1024)
	changes := []transcript.Change{
		{FilePath: "py/big.py", RepoDir: "py", RepoRoot: filepath.Join(ws, "py"), AddedText: big},
		{FilePath: "api/src/a.ts", RepoDir: "api", RepoRoot: filepath.Join(ws, "api"), AddedText: big},
	}
	h := Cloud{client: apiclient.New(srv.URL, ""), resolveImports: true}
	if _, err := h.Review(ws, changes, wire.TurnMeta{}, ""); err != nil {
		t.Fatalf("Review: %v", err)
	}
	if len(reqs) != 2 {
		t.Fatalf("want two requests, got %d", len(reqs))
	}
	derived := func(req wire.ReviewRequest) (paths []string) {
		for _, cf := range req.Context {
			if strings.HasSuffix(cf.Path, ".prisma") {
				paths = append(paths, cf.Path)
			}
		}
		return paths
	}
	if got := derived(reqs[0]); len(got) != 0 {
		t.Fatalf("the unrelated request carried schemas: %q", got)
	}
	if got := derived(reqs[1]); !reflect.DeepEqual(got, []string{"api/prisma/a.prisma", "api/prisma/b.prisma"}) {
		t.Fatalf("the api request's schemas: %q", got)
	}
}
