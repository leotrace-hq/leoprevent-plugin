package imports

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
)

func TestTypeScriptPathAliases(
	t *testing.T,
) {
	tests := []struct {
		name    string
		configs map[string]string
		file    string
		spec    string
		want    []string
	}{
		{"next alias", map[string]string{"tsconfig.json": `{"compilerOptions":{"baseUrl":".","paths":{"@/*":["src/*"]}}}`}, "src/app/page.ts", "@/lib/auth", []string{"src/lib/auth.ts"}},
		{"without baseUrl", map[string]string{"tsconfig.json": `{"compilerOptions":{"paths":{"~/*":["src/*"]}}}`}, "src/app/page.ts", "~/lib/auth", []string{"src/lib/auth.ts"}},
		{"exact and fallback", map[string]string{"tsconfig.json": `{"compilerOptions":{"paths":{"auth":["missing","src/lib/auth"],"*":["wrong"]}}}`}, "app.ts", "auth", []string{"src/lib/auth.ts"}},
		{"longest prefix", map[string]string{"tsconfig.json": `{"compilerOptions":{"paths":{"@/*":["wrong/*"],"@/lib/*":["src/lib/*"]}}}`}, "app.ts", "@/lib/auth", []string{"src/lib/auth.ts"}},
		{"nearest", map[string]string{"tsconfig.json": `{"compilerOptions":{"paths":{"@/*":["wrong/*"]}}}`, "src/tsconfig.json": `{"compilerOptions":{"paths":{"@/*":["*"]}}}`}, "src/app/page.ts", "@/lib/auth", []string{"src/lib/auth.ts"}},
		{"inherited origin", map[string]string{"config/base.json": `{"compilerOptions":{"paths":{"@/*":["../src/*"]}}}`, "src/tsconfig.json": `{"extends":"../config/base"}`}, "src/app/page.ts", "@/lib/auth", []string{"src/lib/auth.ts"}},
		{"inherited baseUrl", map[string]string{"config/base.json": `{"compilerOptions":{"baseUrl":"../src"}}`, "tsconfig.json": `{"extends":"./config/base.json","compilerOptions":{"paths":{"@/*":["*"]}}}`}, "app.ts", "@/lib/auth", []string{"src/lib/auth.ts"}},
		{"baseUrl alone skips bare", map[string]string{"tsconfig.json": `{"compilerOptions":{"baseUrl":"src"}}`}, "app.ts", "lib/auth", []string{}},
		{"unmatched bare", map[string]string{"tsconfig.json": `{"compilerOptions":{"paths":{"@/*":["src/*"]}}}`}, "app.ts", "lib/auth", []string{}},
		{"jsonc", map[string]string{"tsconfig.json": "{/* comment */\n\"compilerOptions\": {\"paths\": {\"@/*\": [\"src/*\",],},}, // tail\n}"}, "app.ts", "@/lib/auth", []string{"src/lib/auth.ts"}},
		{"malformed", map[string]string{"tsconfig.json": `{broken`}, "app.ts", "@/lib/auth", []string{}},
		{"cycle", map[string]string{"tsconfig.json": `{"extends":"./base"}`, "base.json": `{"extends":"./tsconfig"}`}, "app.ts", "@/lib/auth", []string{}},
		{"override paths", map[string]string{"base.json": `{"compilerOptions":{"paths":{"@/*":["src/*"]}}}`, "tsconfig.json": `{"extends":"./base","compilerOptions":{"paths":{}}}`}, "app.ts", "@/lib/auth", []string{}},
		{"relative unchanged", map[string]string{"tsconfig.json": `{broken`}, "src/app.ts", "./lib/auth", []string{"src/lib/auth.ts"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.configs["src/lib/auth.ts"] = "export function verifyAdminToken() { return true; }"
			root := writeRepo(t, tt.configs)
			got := paths(resolve(t, root, transcript.Change{FilePath: tt.file, AddedText: "verifyAdminToken()", FullContent: "import { verifyAdminToken } from '" + tt.spec + "';"}))
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTypeScriptAliasTargetsAndGates(
	t *testing.T,
) {
	root := writeRepo(t, map[string]string{
		"tsconfig.json":             `{"compilerOptions":{"paths":{"@/*":["src/*"],"secret":[".env"],"external":["../outside"],"dependency":["node_modules/pkg/index"],"fallback":["src/lib/auth","src/lib/other"]}}}`,
		"src/lib/auth.ts":           "export function verifyAdminToken() { return true; }",
		"src/lib/other.ts":          "export function verifyAdminToken() { return false; }",
		"src/lib/folder/index.ts":   "export function verifyAdminToken() { return true; }",
		"node_modules/pkg/index.ts": "export function verifyAdminToken() { return false; }",
		".env":                      "SECRET=value",
	})
	tests := []struct {
		name, source, added string
		want                []string
	}{
		{"require", "const { verifyAdminToken } = require('@/lib/auth');", "verifyAdminToken()", []string{"src/lib/auth.ts"}},
		{"reexport", "export * from '@/lib/auth';", "export * from '@/lib/auth';", []string{"src/lib/auth.ts"}},
		{"index", "import { verifyAdminToken } from '@/lib/folder';", "verifyAdminToken()", []string{"src/lib/folder/index.ts"}},
		{"first target only", "import { verifyAdminToken } from 'fallback';", "verifyAdminToken()", []string{"src/lib/auth.ts"}},
		{"unused", "import { verifyAdminToken } from '@/lib/auth';", "other()", []string{}},
		{"type only", "import type { verifyAdminToken } from '@/lib/auth';", "verifyAdminToken", []string{}},
		{"inline type", "import { type verifyAdminToken } from '@/lib/auth';", "verifyAdminToken", []string{}},
		{"secret", "import { verifyAdminToken } from 'secret';", "verifyAdminToken()", []string{}},
		{"escape", "import { verifyAdminToken } from 'external';", "verifyAdminToken()", []string{}},
		{"dependency", "import { verifyAdminToken } from 'dependency';", "verifyAdminToken()", []string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := paths(resolve(t, root, transcript.Change{FilePath: "app.ts", FullContent: tt.source, AddedText: tt.added}))
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTypeScriptConfigInheritance(
	t *testing.T,
) {
	for _, configs := range []map[string]string{
		{"tsconfig.json": `{"extends":["./first","./second"]}`, "first.json": `{"compilerOptions":{"paths":{"@/*":["wrong/*"]}}}`, "second.json": `{"compilerOptions":{"paths":{"@/*":["src/*"]}}}`},
		{"tsconfig.json": `{"extends":"@config/base"}`, "node_modules/@config/base/tsconfig.json": `{"compilerOptions":{"paths":{"@/*":["../../../src/*"]}}}`},
		{"tsconfig.json": `{"extends":"config"}`, "node_modules/config/package.json": `{"tsconfig":"base.json"}`, "node_modules/config/base.json": `{"compilerOptions":{"paths":{"@/*":["../../src/*"]}}}`},
	} {
		configs["src/auth.ts"] = "export function verifyAdminToken() { return true; }"
		root := writeRepo(t, configs)
		got := paths(resolve(t, root, transcript.Change{FilePath: "app.ts", FullContent: "import { verifyAdminToken } from '@/auth';", AddedText: "verifyAdminToken()"}))
		if !reflect.DeepEqual(got, []string{"src/auth.ts"}) {
			t.Fatalf("got %v", got)
		}
	}
}

func TestTypeScriptAliasSymlinkEscape(
	t *testing.T,
) {
	outside := writeRepo(t, map[string]string{"auth.ts": "export function verifyAdminToken() { return true; }", "tsconfig.json": `{"compilerOptions":{"paths":{"@/*":["src/*"]}}}`})
	for _, configLink := range []bool{false, true} {
		root := writeRepo(t, map[string]string{"tsconfig.json": `{"compilerOptions":{"paths":{"@/*":["src/*"]}}}`, "src/local.ts": "export const x = 1;"})
		if configLink {
			if err := os.MkdirAll(filepath.Join(root, "src", "linked"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "src", "linked", "auth.ts"), []byte("export function verifyAdminToken() { return true; }"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(filepath.Join(root, "tsconfig.json")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(outside, "tsconfig.json"), filepath.Join(root, "tsconfig.json")); err != nil {
				t.Fatal(err)
			}
		} else {
			if err := os.Symlink(outside, filepath.Join(root, "src", "linked")); err != nil {
				t.Fatal(err)
			}
		}
		got := resolve(t, root, transcript.Change{FilePath: "app.ts", FullContent: "import { verifyAdminToken } from '@/linked/auth';", AddedText: "verifyAdminToken()"})
		if len(got) != 0 {
			t.Fatalf("unsafe context: %v", got)
		}
	}
}

func TestTypeScriptNearestUnsafeConfigDoesNotUseParent(
	t *testing.T,
) {
	root := writeRepo(t, map[string]string{"tsconfig.json": `{"compilerOptions":{"paths":{"@/*":["src/*"]}}}`, "src/auth.ts": "export function verifyAdminToken() { return true; }"})
	outside := writeRepo(t, map[string]string{"tsconfig.json": `{}`})
	if err := os.Symlink(filepath.Join(outside, "tsconfig.json"), filepath.Join(root, "src", "tsconfig.json")); err != nil {
		t.Fatal(err)
	}
	got := resolve(t, root, transcript.Change{FilePath: "src/app.ts", FullContent: "import { verifyAdminToken } from '@/auth';", AddedText: "verifyAdminToken()"})
	if len(got) != 0 {
		t.Fatalf("used parent config despite nearer unsafe config: %v", got)
	}
}
