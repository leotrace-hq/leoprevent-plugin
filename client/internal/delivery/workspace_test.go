package delivery

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/apiclient"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

// The optional export writes exactly the request received over HTTP, permitting
// an engine A/B of the resolver without manually supplying a validator's body.
// The endpoint is a local stub: this test itself makes no paid model calls.
func TestCloudSendsWorkspaceValidation(t *testing.T) {
	read := func(name string) string {
		t.Helper()
		b, e := os.ReadFile(filepath.Join("testdata/workspace-package", name))
		if e != nil {
			t.Fatal(e)
		}
		return string(b)
	}
	original := read("catalog.ts")
	strict := read("strict.ts")
	loose := read("permissive.ts")
	for _, kind := range []string{"strict", "permissive", "ignored-failure", "barrel", "dist"} {
		t.Run(kind, func(t *testing.T) {
			source, schema := original, strict
			if kind == "permissive" {
				schema = loose
			}
			if kind == "ignored-failure" {
				source = strings.ReplaceAll(source, "  if (!parsed.success) return c.json({ error: 'invalid language' }, 400);\n", "")
				source = strings.ReplaceAll(source, "parsed.data, 'catalog.json'", "raw, 'catalog.json'")
			}
			files := map[string]string{
				"package.json": "{}", "pnpm-workspace.yaml": "packages:\n - 'apps/*'\n - 'packages/*'\n",
				"apps/api/package.json":          `{"name":"api","dependencies":{"@leotrace/shared":"workspace:*"}}`,
				"apps/api/src/routes/catalog.ts": source,
				"packages/shared/package.json":   `{"name":"@leotrace/shared","exports":{"types":"./src/index.d.ts","import":"./src/index.js","default":"./src/index.js"}}`,
				"packages/shared/src/index.d.ts": "export declare const languageSchema: any;",
				"packages/shared/src/index.ts":   schema,
			}
			if kind == "barrel" {
				files["packages/shared/src/index.ts"] = "export { languageSchema } from './language.js';\n"
				files["packages/shared/src/language.ts"] = schema
			}
			if kind == "dist" {
				files["packages/shared/package.json"] = `{"name":"@leotrace/shared","exports":"./dist/index.js"}`
				files["packages/shared/tsconfig.json"] = `{"compilerOptions":{"rootDir":"src","outDir":"dist"}}`
			}
			root := filepath.Join(t.TempDir(), "repo")
			gitRepo(t, root, files)
			var got wire.ReviewRequest
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if e := json.NewDecoder(r.Body).Decode(&got); e != nil {
					t.Error(e)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"verdict":"clean"}`))
			}))
			defer srv.Close()
			nums := []int{}
			for i := range strings.Split(strings.TrimSuffix(source, "\n"), "\n") {
				nums = append(nums, i+1)
			}
			changes := []transcript.Change{{FilePath: "apps/api/src/routes/catalog.ts", FullContent: source, AddedText: source, AddedLines: nums}}
			h := Cloud{client: apiclient.New(srv.URL, ""), resolveImports: true}
			if _, e := h.Review(root, changes, wire.TurnMeta{}); e != nil {
				t.Fatal(e)
			}
			if dest := os.Getenv("LEOPREVENT_WORKSPACE_CAPTURE"); dest != "" {
				if e := os.MkdirAll(dest, 0700); e != nil {
					t.Fatal(e)
				}
				b, e := json.MarshalIndent(got, "", "  ")
				if e != nil {
					t.Fatal(e)
				}
				if e = os.WriteFile(filepath.Join(dest, kind+".json"), b, 0600); e != nil {
					t.Fatal(e)
				}
			}
			found := false
			for _, c := range got.Context {
				if strings.Contains(c.Content, schema) {
					found = true
				}
				if strings.Contains(c.Path, ".d.ts") {
					t.Fatal("declarations are not a validator implementation")
				}
			}
			if !found {
				t.Fatalf("schema absent from actual /review request: %+v", got.Context)
			}
		})
	}
}
