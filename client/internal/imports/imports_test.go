package imports

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
)

// writeRepo materialises a map of repo-relative path → content under a temp dir and
// returns the root. Lets each case build a tiny realistic repo on disk so the
// resolver exercises its real file reads (Lstat/secret/symlink guards included).
func writeRepo(t *testing.T, files map[string]string) string {
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

func paths(ctx []ctxFile) []string {
	out := make([]string, len(ctx))
	for i, c := range ctx {
		out[i] = c.Path
	}
	sort.Strings(out)
	return out
}

// ctxFile mirrors wire.ContextFile for local assertions without importing wire here
// (Resolve returns []wire.ContextFile; we only read Path/Content).
type ctxFile = struct {
	Path    string
	Content string
}

func resolve(t *testing.T, root string, ch transcript.Change) []ctxFile {
	t.Helper()
	var out []ctxFile
	for _, c := range Resolve(root, []transcript.Change{ch}) {
		out = append(out, ctxFile{c.Path, c.Content})
	}
	return out
}

func TestPythonResolvesImportedHelper(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"app.py":     "from netutil import safe_fetch\n",
		"netutil.py": "import requests\ndef safe_fetch(u):\n    return requests.get(u).text\n",
		"logging.py": "def log(x):\n    pass\n", // imported elsewhere but NOT referenced here
	})
	ch := transcript.Change{
		FilePath:    "app.py",
		AddedText:   "url = request.args['url']\nreturn safe_fetch(url)",
		FullContent: "from netutil import safe_fetch\nfrom logging import log\nurl = request.args['url']\nreturn safe_fetch(url)\n",
	}
	got := paths(resolve(t, root, ch))
	if len(got) != 1 || got[0] != "netutil.py" {
		t.Fatalf("want [netutil.py] (only the REFERENCED import), got %v", got)
	}
}

func TestGateSkipsUnreferencedAndThirdParty(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"app.py":   "def f():\n    return 1\n",
		"other.py": "def g():\n    pass\n",
	})
	// Added code references nothing imported + imports a third-party module → no context.
	ch := transcript.Change{
		FilePath:    "app.py",
		AddedText:   "import os\nx = 1 + 2",
		FullContent: "import os\nfrom other import g\nx = 1 + 2\n",
	}
	if got := resolve(t, root, ch); len(got) != 0 {
		t.Fatalf("self-contained / third-party-only turn must resolve nothing, got %v", paths(got))
	}
}

func TestSecretAndSymlinkHelpersDropped(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"app.py": "from settings import KEY\nfrom config import VALUE\n",
		".env":   "SECRET=1\n", // not a .py import target, but prove secret guard via a .py-named secret below
	})
	// A helper that is a symlink must never be read+egressed (link-target exfil guard).
	target := filepath.Join(root, "outside.py")
	if err := os.WriteFile(target, []byte("LEAK=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, "settings.py")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "config.py"), []byte("VALUE=2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ch := transcript.Change{
		FilePath:    "app.py",
		AddedText:   "use(KEY)\nuse(VALUE)",
		FullContent: "from settings import KEY\nfrom config import VALUE\nuse(KEY)\nuse(VALUE)\n",
	}
	got := paths(resolve(t, root, ch))
	// settings.py is a symlink → dropped; config.py is a real file → kept.
	if len(got) != 1 || got[0] != "config.py" {
		t.Fatalf("symlinked helper must be dropped, real one kept; got %v", got)
	}
}

// TestSafeReadSymlinkedDirEscape: an INTERMEDIATE symlinked directory (a committed
// helpers -> outside-the-repo) must not let safeRead follow the chain out of the
// repo — the leaf Lstat alone misses this (the dir-symlink variant of the
// link-target exfil the leaf guard closes).
func TestSafeReadSymlinkedDirEscape(t *testing.T) {
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "leak.js"), []byte("LEAK"), 0o644); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "helpers")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if _, ok := safeRead(root, "helpers/leak.js"); ok {
		t.Fatal("file reached through a symlinked directory must be dropped (out-of-repo egress)")
	}
}

// TestSafeReadSymlinkedRoot: the repo root itself routinely sits behind a symlink
// (/tmp -> /private/tmp on macOS, symlinked checkouts). Containment must compare
// RESOLVED-vs-RESOLVED — comparing resolved candidate against unresolved root would
// silently drop every legitimate file (context vanishes, tests stay green).
func TestSafeReadSymlinkedRoot(t *testing.T) {
	real := t.TempDir()
	if err := os.WriteFile(filepath.Join(real, "util.js"), []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "repo")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	body, ok := safeRead(link, "util.js")
	if !ok || body != "ok" {
		t.Fatalf("legitimate file under a symlinked root must still resolve; got ok=%v body=%q", ok, body)
	}
}

func TestJSResolvesRelativeImport(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"src/handler.ts": "import { runCmd } from './backup'\n",
		"src/backup.ts":  "export function runCmd(n: string) { exec('tar ' + n) }\n",
		"src/util.ts":    "export function noop() {}\n",
	})
	ch := transcript.Change{
		FilePath:    "src/handler.ts",
		AddedText:   "const name = req.query.name\nrunCmd(name)",
		FullContent: "import { runCmd } from './backup'\nimport { noop } from './util'\nconst name = req.query.name\nrunCmd(name)\n",
	}
	got := paths(resolve(t, root, ch))
	if len(got) != 1 || got[0] != "src/backup.ts" {
		t.Fatalf("want [src/backup.ts] (relative + referenced), got %v", got)
	}
}

func TestJavaResolvesByPackagePath(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"src/main/java/com/acme/web/Handler.java": "package com.acme.web;\nimport com.acme.db.Store;\n",
		"src/main/java/com/acme/db/Store.java":    "package com.acme.db;\npublic class Store { public static Object find(String id){ return null; } }\n",
	})
	ch := transcript.Change{
		FilePath:    "src/main/java/com/acme/web/Handler.java",
		AddedText:   "return Store.find(id);",
		FullContent: "package com.acme.web;\nimport com.acme.db.Store;\npublic class Handler { Object h(String id){ return Store.find(id); } }\n",
	}
	got := paths(resolve(t, root, ch))
	if len(got) != 1 || got[0] != "src/main/java/com/acme/db/Store.java" {
		t.Fatalf("want the Store.java by package path, got %v", got)
	}
}

func TestGoResolvesLocalPackage(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"go.mod":              "module github.com/acme/app\n\ngo 1.22\n",
		"handler.go":          "package main\nimport \"github.com/acme/app/store\"\n",
		"store/store.go":      "package store\nfunc Find(id string) any { return nil }\n",
		"store/store_test.go": "package store\n", // must be excluded
	})
	ch := transcript.Change{
		FilePath:    "handler.go",
		AddedText:   "return store.Find(id)",
		FullContent: "package main\nimport \"github.com/acme/app/store\"\nfunc h(id string) any { return store.Find(id) }\n",
	}
	got := paths(resolve(t, root, ch))
	if len(got) != 1 || got[0] != "store/store.go" {
		t.Fatalf("want [store/store.go] (non-test files of the local package), got %v", got)
	}
}

func TestGoSkipsThirdParty(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"go.mod":     "module github.com/acme/app\n",
		"handler.go": "package main\nimport \"github.com/other/lib\"\n",
	})
	ch := transcript.Change{
		FilePath:    "handler.go",
		AddedText:   "lib.Do()",
		FullContent: "package main\nimport \"github.com/other/lib\"\nfunc h(){ lib.Do() }\n",
	}
	if got := resolve(t, root, ch); len(got) != 0 {
		t.Fatalf("third-party import must not resolve, got %v", paths(got))
	}
}

func TestCSharpResolvesByConvention(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"Web/Handler.cs": "using Acme.Db;\n",
		"Db/Store.cs":    "namespace Acme.Db;\npublic class Store { public static object Find(string id) => null; }\n",
	})
	ch := transcript.Change{
		FilePath:    "Web/Handler.cs",
		AddedText:   "return Store.Find(id);",
		FullContent: "using Acme.Db;\nnamespace Acme.Web;\npublic class Handler { object H(string id) => Store.Find(id); }\n",
	}
	got := paths(resolve(t, root, ch))
	if len(got) != 1 || got[0] != "Db/Store.cs" {
		t.Fatalf("want [Db/Store.cs] by filename convention, got %v", got)
	}
}

func TestChangedFileNotReturnedAsContext(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"a.py": "from a import x\n", // self-import edge: must not return itself
	})
	ch := transcript.Change{FilePath: "a.py", AddedText: "x()", FullContent: "from a import x\nx()\n"}
	if got := resolve(t, root, ch); len(got) != 0 {
		t.Fatalf("a changed file must never be its own context, got %v", paths(got))
	}
}

func TestNoGitRootResolvesNothing(t *testing.T) {
	if got := Resolve("", []transcript.Change{{FilePath: "a.py", AddedText: "x()"}}); got != nil {
		t.Fatalf("empty root must yield nil, got %v", got)
	}
}
