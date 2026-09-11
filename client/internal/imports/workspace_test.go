package imports

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
)

func workspaceFixture() map[string]string {
	return map[string]string{
		"package.json":                 `{"private":true,"workspaces":["apps/*","packages/*"]}`,
		"apps/api/package.json":        `{"name":"api","dependencies":{"@leotrace/shared":"workspace:*"}}`,
		"packages/shared/package.json": `{"name":"@leotrace/shared","exports":"./src/index.ts"}`,
		"packages/shared/src/index.ts": "import { z } from 'zod';\nexport const languageSchema = z.enum(['java','python']);\n",
	}
}
func workspaceChange(spec, mode string) transcript.Change {
	src := "import { languageSchema } from '" + spec + "';\nconst parsed = languageSchema.safeParse(input);\n"
	if mode == "require" {
		src = "const { languageSchema } = require('" + spec + "');\nconst parsed = languageSchema.safeParse(input);\n"
	}
	return transcript.Change{FilePath: "apps/api/src/catalog.ts", FullContent: src, AddedText: src}
}
func TestWorkspacePackageResolution(t *testing.T) {
	const manifest = "packages/shared/package.json"
	const schema = "packages/shared/src/index.ts"
	cases := []struct {
		name, spec, mode, want string
		files                  map[string]string
	}{
		{name: "npm", want: schema},
		{name: "pnpm", want: schema, files: map[string]string{"package.json": "{}", "pnpm-workspace.yaml": "packages:\n - 'apps/*'\n - 'packages/*'\n"}},
		{name: "yarn-object", want: schema, files: map[string]string{"package.json": `{"workspaces":{"packages":["apps/*","packages/*"]}}`}},
		{name: "subpath", spec: "@leotrace/shared/language", want: schema, files: map[string]string{manifest: `{"name":"@leotrace/shared","exports":{"./language":"./src/index.ts"}}`}},
		{name: "wildcard", spec: "@leotrace/shared/index", want: schema, files: map[string]string{manifest: `{"name":"@leotrace/shared","exports":{"./*":"./src/*.ts"}}`}},
		{name: "unexported", spec: "@leotrace/shared/src/index.ts"},
		{name: "blocked", files: map[string]string{manifest: `{"name":"@leotrace/shared","main":"./src/index.ts","exports":null}`}},
		{name: "missing-export", files: map[string]string{manifest: `{"name":"@leotrace/shared","main":"./src/index.ts","exports":"./missing.ts"}`}},
		{name: "main", want: schema, files: map[string]string{manifest: `{"name":"@leotrace/shared","main":"./src/index.ts"}`}},
		{name: "emitted-js", want: schema, files: map[string]string{manifest: `{"name":"@leotrace/shared","exports":"./src/index.js"}`}},
		{name: "real-js-first", want: "packages/shared/src/index.js", files: map[string]string{manifest: `{"name":"@leotrace/shared","exports":"./src/index.js"}`, "packages/shared/src/index.js": "export const languageSchema = PERMISSIVE;"}},
		{name: "nested-import", want: schema, files: map[string]string{manifest: `{"name":"@leotrace/shared","exports":{"types":"./types.d.ts","node":{"import":"./src/index.ts","require":"./cjs.cjs"}}}`, "packages/shared/cjs.cjs": "exports.languageSchema = PERMISSIVE;"}},
		{name: "require", mode: "require", want: "packages/shared/cjs.cjs", files: map[string]string{manifest: `{"name":"@leotrace/shared","exports":{"import":"./src/index.ts","require":"./cjs.cjs"}}`, "packages/shared/cjs.cjs": "exports.languageSchema = PERMISSIVE;"}},
		{name: "ordered-conditions", want: schema, files: map[string]string{manifest: `{"name":"@leotrace/shared","exports":{"default":"./src/index.ts","import":"./missing.ts"}}`}},
		{name: "missing-active-condition", files: map[string]string{manifest: `{"name":"@leotrace/shared","exports":{"import":"./missing.ts","default":"./src/index.ts"}}`}},
		{name: "types-only", files: map[string]string{manifest: `{"name":"@leotrace/shared","exports":{"types":"./src/index.ts"}}`}},
		{name: "exclusion", files: map[string]string{"pnpm-workspace.yaml": "packages:\n - 'apps/*'\n - 'packages/*'\n - '!packages/shared'\n"}},
		{name: "duplicate-name", files: map[string]string{"packages/decoy/package.json": `{"name":"@leotrace/shared","exports":"./secret.ts"}`, "packages/decoy/secret.ts": "NEVER_SEND"}},
		{name: "undeclared", files: map[string]string{"apps/api/package.json": `{"name":"api"}`}},
		{name: "registry-alias", files: map[string]string{"apps/api/package.json": `{"name":"api","dependencies":{"@leotrace/shared":"npm:other@1"}}`}},
		{name: "explicit-alias", want: "local.ts", files: map[string]string{"tsconfig.json": `{"compilerOptions":{"paths":{"@leotrace/shared":["./local.ts"]}}}`, "local.ts": "export const languageSchema = LOCAL;"}},
		{name: "missing-alias-no-fallback", files: map[string]string{"tsconfig.json": `{"compilerOptions":{"paths":{"@leotrace/shared":["./missing.ts"]}}}`}},
		{name: "escape", files: map[string]string{manifest: `{"name":"@leotrace/shared","exports":"./../other/secret.ts"}`, "packages/other/secret.ts": "NEVER_SEND"}},
		{name: "encoded-target", files: map[string]string{manifest: `{"name":"@leotrace/shared","exports":"./src/%2e%2e/secret.ts"}`}},
		{name: "invalid-specifier", spec: "@leotrace/shared/../other"},
		{name: "secret", files: map[string]string{manifest: `{"name":"@leotrace/shared","exports":"./.env"}`, "packages/shared/.env": "NEVER_SEND"}},
		{name: "vendor-target", files: map[string]string{manifest: `{"name":"@leotrace/shared","exports":"./node_modules/vendor/index.ts"}`, "packages/shared/node_modules/vendor/index.ts": "NEVER_SEND"}},
		{name: "installed-registry-copy", files: map[string]string{"apps/api/node_modules/@leotrace/shared/package.json": `{"name":"@leotrace/shared"}`}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			files := workspaceFixture()
			for k, v := range tc.files {
				files[k] = v
			}
			root := writeRepo(t, files)
			spec := tc.spec
			if spec == "" {
				spec = "@leotrace/shared"
			}
			got := Resolve(root, []transcript.Change{workspaceChange(spec, tc.mode)})
			if tc.want == "" {
				if len(got) != 0 {
					t.Fatalf("must not resolve %+v", got)
				}
				return
			}
			if len(got) != 1 || got[0].Path != tc.want || got[0].Content != files[tc.want] {
				t.Fatalf("want %s with its source, got %+v", tc.want, got)
			}
		})
	}
}
func TestWorkspaceReferenceAndSymlinkGuards(t *testing.T) {
	for _, mode := range []string{"unreferenced", "type-only", "outside-symlink", "manifest-change"} {
		t.Run(mode, func(t *testing.T) {
			root := writeRepo(t, workspaceFixture())
			ch := workspaceChange("@leotrace/shared", "")
			switch mode {
			case "unreferenced":
				ch.AddedText = "const other = 1;"
			case "type-only":
				ch.FullContent = strings.Replace(ch.FullContent, "import {", "import type {", 1)
				ch.AddedText = ch.FullContent
			case "outside-symlink":
				outside := filepath.Join(t.TempDir(), "outside.ts")
				if err := os.WriteFile(outside, []byte("NEVER_SEND"), 0600); err != nil {
					t.Fatal(err)
				}
				leaf := filepath.Join(root, "packages/shared/src/index.ts")
				if err := os.Remove(leaf); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, leaf); err != nil {
					t.Fatal(err)
				}
			case "manifest-change":
				if got := Resolve(root, []transcript.Change{ch}); len(got) != 1 {
					t.Fatal(got)
				}
				if err := os.WriteFile(filepath.Join(root, "packages/shared/package.json"), []byte(`{"name":"@leotrace/shared","exports":null}`), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if got := Resolve(root, []transcript.Change{ch}); len(got) != 0 {
				t.Fatal(got)
			}
		})
	}
}

func TestWorkspaceBarrelsAndBuildRoots(t *testing.T) {
	for _, kind := range []string{"named", "star", "renamed", "cycle", "dist", "dist-without-config", "dist-real-js"} {
		t.Run(kind, func(t *testing.T) {
			files := workspaceFixture()
			schema := "packages/shared/src/language.ts"
			files[schema] = "export const languageSchema = REAL_SCHEMA;\n"
			want := []string{"packages/shared/src/index.ts", schema}
			switch kind {
			case "named":
				files[want[0]] = "export { languageSchema } from './language.js';\n"
			case "star":
				files[want[0]] = "export * from './language.js';\nexport * from './unrelated.js';\n"
				files["packages/shared/src/unrelated.ts"] = "export const irrelevant = NEVER_SEND;"
			case "renamed":
				files[want[0]] = "export { internalSchema as languageSchema } from './language.js';\n"
				files[schema] = "export const internalSchema = REAL_SCHEMA;"
			case "cycle":
				files[want[0]] = "export * from './language.js';"
				files[schema] = "export * from './index.js';"
				want = want[:1]
			default:
				files["packages/shared/package.json"] = `{"name":"@leotrace/shared","exports":"./dist/index.js"}`
				files["packages/shared/tsconfig.json"] = `{"extends":"../../tsconfig.json"}`
				files["tsconfig.json"] = `{"compilerOptions":{"rootDir":"./packages/shared/src","outDir":"./packages/shared/dist"}}`
				want = want[:1]
				if kind == "dist-without-config" {
					delete(files, "packages/shared/tsconfig.json")
					want = nil
				}
				if kind == "dist-real-js" {
					files["packages/shared/dist/index.js"] = "export const languageSchema = BUILT_SCHEMA;"
					want = []string{"packages/shared/dist/index.js"}
				}
			}
			root := writeRepo(t, files)
			got := Resolve(root, []transcript.Change{workspaceChange("@leotrace/shared", "")})
			if len(got) != len(want) {
				t.Fatalf("want %v, got %+v", want, got)
			}
			for i, p := range want {
				if got[i].Path != p || got[i].Content != files[p] {
					t.Fatalf("want %s body, got %+v", p, got)
				}
			}
		})
	}
}

func TestWorkspaceGlobBoundedMatching(t *testing.T) {
	if workspaceMatch(strings.Repeat("**/", 30)+"missing", strings.Repeat("dir/", 100)+"package") {
		t.Fatal("nonmatching terminal segment accepted")
	}
	for _, pattern := range []string{"packages/*", "**/shared", "**/**/shared"} {
		if !workspaceMatch(pattern, "packages/shared") {
			t.Fatalf("did not match %s", pattern)
		}
	}
}

func TestWorkspaceInstalledLink(t *testing.T) {
	root := writeRepo(t, workspaceFixture())
	link := filepath.Join(root, "apps/api/node_modules/@leotrace/shared")
	if err := os.MkdirAll(filepath.Dir(link), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../../../packages/shared", link); err != nil {
		t.Fatal(err)
	}
	got := Resolve(root, []transcript.Change{workspaceChange("@leotrace/shared", "")})
	if len(got) != 1 || got[0].Path != "packages/shared/src/index.ts" {
		t.Fatalf("local installed link did not resolve: %+v", got)
	}
}

func TestWorkspaceDoesNotFollowDirectoryLinkIntoVendor(t *testing.T) {
	files := workspaceFixture()
	delete(files, "packages/shared/src/index.ts")
	files["node_modules/vendor/index.ts"] = "export const languageSchema = NEVER_SEND;"
	root := writeRepo(t, files)
	if err := os.Symlink("../../node_modules/vendor", filepath.Join(root, "packages/shared/src")); err != nil {
		t.Fatal(err)
	}
	if got := Resolve(root, []transcript.Change{workspaceChange("@leotrace/shared", "")}); len(got) != 0 {
		t.Fatalf("followed dependency source: %+v", got)
	}
}
