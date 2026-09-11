// Package gate is the always-on, tier-agnostic relevance gate that runs before
// any review. It is a DENYLIST, not an allowlist: it suppresses only changes it
// can prove are inert (pure prose, or diffs whose every non-blank added line is
// a comment) and lets EVERYTHING else through to the reviewer.
//
// This is a deliberate inversion of the old keyword pre-check. A keyword
// allowlist fails toward "skip" — a vocabulary miss silently drops a real diff,
// the vuln ships, and the developer sees a clean "done" with false assurance.
// That false negative is the dangerous failure for a security tool. The inert
// gate fails toward "review": the worst case is sending a harmless diff to the
// reviewer, which costs a little latency/egress and then comes back silent
// (selection ≠ detection — the judge only speaks on a real finding). We bias
// toward over-sending on purpose.
//
// Safety property: comment detection is START-ANCHORED (a line must START with
// the language's comment marker to count as inert), so a trailing comment on a
// real code line (`x = get(url)  # fetch`) is NOT inert and reaches the reviewer.
package gate

import (
	"log/slog"
	"path/filepath"
	"strings"

	"github.com/go-enry/go-enry/v2"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
)

// nonExecutable are file types we never review: pure prose, lockfiles, and
// COMPILED / BINARY build artifacts (.pyc, .class, .so, …). The latter aren't
// human-authored source — they're generated, often huge/binary, and reviewing
// them is pure noise/cost. Kept deliberately unambiguous; we do NOT list config
// formats (.yaml/.json/.xml/.toml) here because config can be security-relevant
// (CORS, TLS, debug flags, actuator exposure).
var nonExecutable = map[string]bool{
	// prose / docs
	".md":       true,
	".markdown": true,
	".txt":      true,
	".rst":      true,
	".adoc":     true,
	// lockfiles
	".lock": true,
	// compiled / bytecode artifacts
	".pyc":   true,
	".pyo":   true,
	".pyd":   true,
	".class": true,
	".o":     true,
	".obj":   true,
	".a":     true,
	".so":    true,
	".dylib": true,
	".dll":   true,
	".exe":   true,
	".bin":   true,
	".wasm":  true,
	".jar":   true,
	".war":   true,
	// minified / source-map build output (not hand-authored)
	".map": true,
	// locale / translation data — strings, not logic
	".po":    true,
	".pot":   true,
	".mo":    true,
	".arb":   true,
	".xliff": true,
	".xlf":   true,
	// stylesheets — presentation, not logic. CSS is not a nil security surface (an
	// `@import` or a `url()` can reach out, and a selector can exfiltrate an attribute
	// value), but the corpus carries no rule that targets a stylesheet, so today the
	// only outcome of sending one is cost: measured at 13.5% of one customer's egressed
	// bytes, a single 808 KB home.css among them, against zero rules that could fire.
	// REVISIT WHEN the corpus gains a stylesheet pattern — at that point these
	// extensions come back out, and .css/.scss want an entry in rulespec.extLanguage
	// too (absent today, so a stylesheet is offered the whole catalogue).
	".css":     true,
	".scss":    true,
	".sass":    true,
	".less":    true,
	".styl":    true,
	".stylus":  true,
	".pcss":    true,
	".postcss": true,
	// tabular / geographic data — coordinate and record dumps, not logic. A single
	// committed .geojson boundary file measured 129 KB, half the whole payload budget.
	".csv":     true,
	".tsv":     true,
	".geojson": true,
	// logs / run output — generated, often huge, never hand-authored source
	".log": true,
	".err": true,
	".out": true,
	// diffs / patches — a generated representation of a change, not source itself
	".diff":  true,
	".patch": true,
	// line-delimited data / event streams. NB plain .json/.yaml/.xml stay ABSENT
	// (reviewable) because config can be security-relevant; .jsonl/.ndjson are
	// append-only data/logs, not config.
	".jsonl":  true,
	".ndjson": true,
	// binary assets: fonts, raster images, media — never hand-authored source.
	// NB .svg is deliberately ABSENT: it is text and can carry active content
	// (<script>, onload= → stored XSS), so it stays reviewable. The noise is removed
	// instead by svgWithoutActiveContent below — a content check, not a size one.
	".woff":   true,
	".woff2":  true,
	".ttf":    true,
	".eot":    true,
	".otf":    true,
	".png":    true,
	".jpg":    true,
	".jpeg":   true,
	".gif":    true,
	".bmp":    true,
	".ico":    true,
	".webp":   true,
	".avif":   true,
	".pdf":    true,
	".mp4":    true,
	".mp3":    true,
	".wav":    true,
	".mov":    true,
	".avi":    true,
	".mkv":    true,
	".webm":   true,
	".flac":   true,
	".ogg":    true,
	".opus":   true,
	".aac":    true,
	".m4a":    true,
	".heic":   true,
	".heif":   true,
	".psd":    true,
	".ai":     true,
	".sketch": true,
	".fig":    true,
	".icns":   true,

	// archives — containers, never hand-authored source.
	".zip": true,
	".tar": true,
	".gz":  true,
	".tgz": true,
	".bz2": true,
	".xz":  true,
	".zst": true,
	".7z":  true,
	".rar": true,

	// binary data / model / db dumps — opaque blobs, not source.
	".parquet": true,
	".avro":    true,
	".orc":     true,
	".pkl":     true,
	".pickle":  true,
	".npy":     true,
	".npz":     true,
	".h5":      true,
	".hdf5":    true,
	".sqlite":  true,
	".sqlite3": true,
	".db":      true,
	".rdb":     true,
	".dat":     true,

	// compiled / packaged artifacts (ext fast-path; IsBinary also catches these
	// when content is present, but this covers empty/streamed payloads too).
	".node":  true,
	".rlib":  true,
	".rmeta": true,
	".pdb":   true,
	".lib":   true,
	".whl":   true,
	".gem":   true,
	".nupkg": true,
	".beam":  true,
	".ear":   true,
	".nar":   true,

	// backup / temp / patch-reject artifacts — the real file is reviewed instead,
	// so these copies are redundant noise. (.rej/.orig come from failed patch/merge.)
	".bak":  true,
	".orig": true,
	".rej":  true,
	".tmp":  true,
	".temp": true,

	// IDE / editor project metadata.
	".iml": true,
}

// lockfileBasenames are machine-generated dependency locks whose names do NOT end in
// `.lock`, so the nonExecutable `.lock` rule misses them. (The `.lock`-named locks —
// yarn.lock, composer.lock, Cargo.lock, poetry.lock, Pipfile.lock, pdm.lock, uv.lock —
// are already caught by extension.) These are never hand-authored; the matching
// hand-authored MANIFEST (package.json, go.mod, *.csproj, build.gradle, …) is NOT
// listed — it stays reviewable, since deps/scripts are a supply-chain surface.
var lockfileBasenames = map[string]bool{
	"package-lock.json":   true, // npm
	"npm-shrinkwrap.json": true, // npm
	"pnpm-lock.yaml":      true, // pnpm
	"go.sum":              true, // Go (go.mod kept)
	"packages.lock.json":  true, // .NET / NuGet
	"gradle.lockfile":     true, // Gradle
	"conda-lock.yml":      true, // conda
}

// generatedSuffixes mark machine-generated source whose extension alone looks
// hand-authored (.js/.css/.go/.py/.cs/.dart). Matched as a suffix of the lowercased
// base name. Minified/bundled web output and codegen (protobuf, C#/Dart designers)
// are noise to review and often huge.
var generatedSuffixes = []string{
	".min.js", ".min.mjs", ".min.css", ".bundle.js", // minified / bundled web output
	".pb.go", "_pb2.py", "_pb2_grpc.py", ".pb.cc", ".pb.h", // protobuf codegen
	".g.cs", ".designer.cs", ".g.dart", // C# / Dart codegen
	// `.gen.<ext>` ANCHORED AT THE END of the base name — the convention emitted by
	// hey-api/openapi-ts, oapi-codegen, sqlc, mockgen and friends. Measured in a
	// customer corpus: one types.gen.ts accounted for 8.4% of all bytes egressed and
	// ~40% of the payload budget on the reviews that carried it. The judge cannot act
	// on it either: a corpus exemption already tells it not to conclude from "a
	// generated API client". NB this is a SUFFIX, not the `.gen.` infix — see
	// generated() for why the infix stays unmatched.
	".gen.ts", ".gen.tsx", ".gen.go", ".gen.py", ".gen.js", ".gen.mjs",
	".gen.dart", ".gen.rs", ".gen.kt", ".gen.cs", ".gen.rb", ".gen.php",
}

// maxHandAuthoredLineLen bounds the longest line we expect in human-written source.
// Minified bundles and committed generated/library blobs (e.g. a MathJax font-data
// file, whose payload sits on a single ~5.5k-char defineImageData(...) line) pack data
// onto pathologically long lines, where hand-authored code almost never exceeds a few
// hundred. One line at/over this length marks the file generated → dropped. The high
// threshold keeps it high-precision (fail toward review): real source never trips it.
const maxHandAuthoredLineLen = 2000

// vendoredSegments are path SEGMENTS that mark a third-party / tool-cache tree
// which go-enry's IsVendor MISSES (measured): Python venvs & caches, several JS
// framework caches, VCS internals, and the IaC provider cache. enry.IsVendor is
// broad but not a superset — it lacks these — so the two are UNIONED in vendored()
// below (enry adds dist/, third_party/, Godeps/, minified libs, hundreds more that
// this list lacks; this list adds what enry misses + separator normalization for
// Windows paths, which enry does not handle). Whole-segment match, so a file named
// e.g. `vendor.go` is unaffected. Deliberately omits ambiguous build dirs
// (build/, out/, bin/, target/) — those stay reviewable (may hold hand-authored code).
var vendoredSegments = map[string]bool{
	// JS framework caches enry.IsVendor misses
	"jspm_packages": true, ".next": true, ".nuxt": true, ".svelte-kit": true,
	".angular": true, ".parcel-cache": true, ".turbo": true,
	// Python venvs / tool caches
	"__pycache__": true, ".venv": true, "venv": true, "site-packages": true,
	".eggs": true, ".tox": true, ".nox": true, ".mypy_cache": true,
	".pytest_cache": true, ".ruff_cache": true, ".hypothesis": true,
	// JVM / iOS / IaC
	".gradle": true, "Pods": true, ".terraform": true,
	// VCS internals
	".git": true, ".svn": true, ".hg": true,
	".nyc_output": true, ".cache": true,
	"__snapshots__": true,
	// NB `coverage/` deliberately NOT here: it is a common first-party DOMAIN word
	// (insurance/health/fintech modules named coverage/) and enry.IsVendor does not
	// cover it, so skipping it would silently drop a real module — the exact
	// false-negative this gate exists to avoid. Coverage *reports* are mild noise we
	// accept. (.nyc_output stays: unambiguously a tool cache.)
	// NB build/out/target/obj/Debug/Release live in ambiguousBuildSegments below, not
	// here — they are only trusted on a RELATIVE path (see vendored()).
}

// ambiguousBuildSegments are build/compiler-output dir names we SKIP — generated FROM
// first-party source, not authored directly (accepted risk: a hand-authored build
// script under build/ out/ target/ goes unscanned). enry.IsVendor does NOT cover these
// (dist/ is its only build-output dir). `bin/` is intentionally ABSENT — it commonly
// holds real deploy/utility scripts; cmake-build-* is matched by prefix in vendored().
//
// These names double as common first-party PARENT-dir names, so they are trusted ONLY
// on a RELATIVE path. In the git path FilePath is repo-root-relative, so a match is
// genuinely inside the repo's build output; in the gitless transcript fallback FilePath
// is ABSOLUTE (the agent's tool-input path), where an ancestor dir like
// /home/me/out/proj/ would otherwise spuriously drop EVERY change (a review bypass).
var ambiguousBuildSegments = map[string]bool{
	"build": true, "out": true, "target": true, "obj": true,
	"Debug": true, "Release": true,
}

// vendored reports whether a path is third-party / build output we skip. It UNIONS
// two sources: the hand list above (covers common trees enry.IsVendor misses, and
// normalizes Windows separators), and go-enry's IsVendor (Linguist's community-
// maintained vendor patterns: dist/, third_party/, Godeps/, minified libs, …).
// Content-based binary/generated detection is separate (inert() → IsGenerated/IsBinary).
//
// CARVE-OUT: CI pipeline definitions (.github/workflows/*, Jenkinsfile) are a real
// security surface — secrets, ${{ }} expression injection, supply-chain — and
// Linguist vendors them; leoprevent keeps them REVIEWABLE. (Other CI/IaC — GitLab/
// CircleCI/Azure, Terraform, k8s, Helm, Dockerfile — enry leaves un-vendored, no
// carve-out needed.) Separator-agnostic.
func vendored(p string) bool {
	v, _ := vendoredReason(p)
	return v
}

// vendoredReason reports whether p is vendored AND whether the decision came from the
// go-enry heuristic (byEnry) rather than the explicit hand-list. The caller logs the
// byEnry drops: enry's Linguist patterns match on ambiguous dir words (cache/, env/)
// and library-name basenames (controls.js), so a heuristic match on a first-party
// SOURCE file would drop it unreviewed — the exact silent false negative this gate
// exists to avoid. The hand-list matches (byEnry=false) are deterministic and quiet.
func vendoredReason(p string) (isVendored, byEnry bool) {
	q := strings.ReplaceAll(p, `\`, "/")
	// Ambiguous build-output segments are trusted only on a relative path — an absolute
	// path means the gitless fallback, where an ancestor dir would spuriously match.
	rel := !absAnyPlatform(q)
	for _, seg := range strings.Split(q, "/") {
		if vendoredSegments[seg] || strings.HasPrefix(seg, "cmake-build") {
			return true, false
		}
		if rel && ambiguousBuildSegments[seg] {
			return true, false
		}
	}
	// Pass the separator-normalized path: enry.IsVendor does not handle backslashes,
	// so a Windows-style node_modules\pkg\x.js would otherwise slip through.
	if !enry.IsVendor(q) {
		return false, false
	}
	base := q
	if i := strings.LastIndex(q, "/"); i >= 0 {
		base = q[i+1:]
	}
	if strings.Contains(q, ".github/workflows/") || base == "Jenkinsfile" {
		return false, false // CI config: review it despite Linguist vendoring it
	}
	return true, true
}

// absAnyPlatform reports whether a separator-normalized path is absolute on ANY
// platform, not merely on the one this binary was built for. filepath.IsAbs answers
// the host's question: on Windows it calls /home/me/out/proj/app.py RELATIVE (no drive
// letter), so the ambiguous `out` ancestor matched and the whole project was dropped
// UNREVIEWED — the exact review bypass the relative-only rule exists to prevent, just
// on the other OS. A path shape this cannot recognise falls through to filepath.IsAbs,
// and an unrecognised shape reads as relative, so the residual risk is unchanged.
// Erring toward absolute errs toward reviewing.
func absAnyPlatform(q string) bool {
	if strings.HasPrefix(q, "/") { // POSIX, and a normalized UNC //server/share
		return true
	}
	if len(q) >= 2 && q[1] == ':' && isDriveLetter(q[0]) { // C:/… and drive-relative C:…
		return true
	}
	return filepath.IsAbs(q)
}

func isDriveLetter(b byte) bool {
	return ('a' <= b && b <= 'z') || ('A' <= b && b <= 'Z')
}

// secretBasenames are credential/secret files whose CONTENT is secrets, not code —
// never egressed for review. Matched on the file's base name.
var secretBasenames = map[string]bool{
	"id_rsa": true, "id_dsa": true, "id_ecdsa": true, "id_ed25519": true,
	".netrc": true, ".pgpass": true, ".htpasswd": true, ".npmrc": true,
}

// secretExts are file types that hold key / credential material.
var secretExts = map[string]bool{
	".pem": true, ".key": true, ".pfx": true, ".p12": true, ".keystore": true, ".jks": true,
	// Credential-bearing artifacts — treated as NEVER-EGRESS (dropped before the file
	// is read or sent), not merely inert: leaking a token off the machine is worse than
	// skipping a review. .tfvars/.tfstate carry plaintext Terraform secrets; .har is an
	// HTTP capture that routinely contains auth headers, cookies, and bearer tokens.
	".tfvars": true, ".tfstate": true, ".har": true,
}

// IsSecretPath reports whether a path holds secret/credential material that must NOT
// be egressed for review: private keys, .env files (and .env.<x>), and credential
// stores. The client drops these from the change set BEFORE the inert gate, so a
// secret is never sent to the cloud /review nor read for local selection. The trade
// is deliberate: a secret file is consequently NOT reviewed (we can't review what we
// refuse to read), but leaking a key off the machine is worse than missing a lint on
// a key file. Matched on base name / extension, separator-agnostic.
func IsSecretPath(p string) bool {
	p = strings.ReplaceAll(p, `\`, "/")
	base := p
	if i := strings.LastIndex(p, "/"); i >= 0 {
		base = p[i+1:]
	}
	if secretBasenames[base] {
		return true
	}
	// Three env-file shapes, all secret-bearing: the dotfile (.env), its suffixed
	// variants (.env.production), and the PREFIXED form (prod.env, staging.env,
	// 2.4.8.env) — a common convention that the first two rules miss. Measured in a
	// customer corpus: nine `<name>.env` files egressed for review because only the
	// dotfile shapes were matched. Their content there was benign version pinning, but
	// the name says "environment file", and that is what this function refuses to read.
	if base == ".env" || strings.HasPrefix(base, ".env.") || strings.HasSuffix(base, ".env") {
		return true
	}
	return secretExts[strings.ToLower(filepath.Ext(base))]
}

// commentMarkers maps a source extension to the line-comment prefixes for that
// language. A diff is inert only if EVERY non-blank added line starts with one
// of these. Extensions absent from this map (and from nonExecutable) are always
// reviewed — including HTML/XML, where block comments (<!-- -->) make
// line-anchored detection unsafe, so we never treat them as inert.
var commentMarkers = map[string][]string{
	// '#' line comments
	".py":   {"#"},
	".rb":   {"#"},
	".sh":   {"#"},
	".bash": {"#"},
	".zsh":  {"#"},
	".yaml": {"#"},
	".yml":  {"#"},
	".tf":   {"#"},
	".toml": {"#"},
	".ini":  {"#"},
	// NOTE: .env is deliberately NOT here — it holds secrets/config (keys, debug and
	// auth flags), never "just comments", and is dropped from egress entirely upstream
	// (gate.IsSecretPath); listing it as comment-inert would be wrong on both counts.
	".pl":  {"#"},
	".ex":  {"#"},
	".exs": {"#"},
	".ps1": {"#"},
	// '//' line comments
	".js":     {"//"},
	".mjs":    {"//"},
	".cjs":    {"//"},
	".ts":     {"//"},
	".jsx":    {"//"},
	".tsx":    {"//"},
	".go":     {"//"},
	".java":   {"//"},
	".kt":     {"//"},
	".scala":  {"//"},
	".groovy": {"//"},
	".c":      {"//"},
	".cc":     {"//"},
	".cpp":    {"//"},
	".h":      {"//"},
	".hpp":    {"//"},
	".cs":     {"//"},
	".fs":     {"//"},
	".rs":     {"//"},
	".swift":  {"//"},
	".m":      {"//"},
	".mm":     {"//"},
	".dart":   {"//"},
	".vue":    {"//"},
	".svelte": {"//"},
	// '--' line comments
	".sql": {"--"},
	".lua": {"--"},
	// PHP accepts both '//' and '#'
	".php": {"//", "#"},
}

// baseLower returns the lowercased base name of a path, separator-agnostic.
func baseLower(p string) string {
	p = strings.ReplaceAll(p, `\`, "/")
	if i := strings.LastIndex(p, "/"); i >= 0 {
		p = p[i+1:]
	}
	return strings.ToLower(p)
}

// generated reports whether a lowercased base name ends in a known codegen/minified
// suffix (see generatedSuffixes).
func generated(base string) bool {
	for _, s := range generatedSuffixes {
		if strings.HasSuffix(base, s) {
			return true
		}
	}
	// `.generated.` codegen infix (e.g. types.generated.ts, api.generated.go) — an
	// unambiguous convention enry's suffix rules miss. NB the terser `.gen.` marker is
	// still deliberately NOT matched as an INFIX: `.gen.` mid-name is too easy to
	// false-hit a real source name (gen.service.ts, token.gen.helper.ts) → we would
	// blind the judge to actual code. Only the anchored `<name>.gen.<ext>` tail is
	// treated as generated, via generatedSuffixes above.
	return strings.Contains(base, ".generated.")
}

// looksGenerated reports whether the change's CONTENT is machine-generated/minified
// independent of name or extension: a single pathologically long line (see
// maxHandAuthoredLineLen). It scans the full file when present — that is what the
// cloud judge + selector see and what bloats the prompt (a giant committed asset like
// a MathJax font blob) — else the added text. Allocation-free, early-returns on the
// first long line.
func looksGenerated(c transcript.Change) bool {
	body := c.FullContent
	if body == "" {
		body = c.AddedText
	}
	for len(body) > 0 {
		i := strings.IndexByte(body, '\n')
		if i < 0 {
			return len(body) >= maxHandAuthoredLineLen
		}
		if i >= maxHandAuthoredLineLen {
			return true
		}
		body = body[i+1:]
	}
	return false
}

// testSegments are path SEGMENTS that mark a browser/integration test tree whose
// SUPPORT files enry.IsTest misses. enry matches on the FILE name (login.spec.ts,
// UserTest.java), so a Playwright/Cypress suite's page objects, helpers, fixtures and
// setup files — login.page.ts, auth.helper.ts, base-test.ts, auth.setup.ts — sail
// through even though they are test-only by construction. Measured in a customer
// corpus: 41 such files, 636 KB egressed, including a totp.helper.ts and an
// auth.constants.ts whose whole content is throwaway test credentials — the
// false-positive bait the test rule exists to keep out.
//
// Whole-segment match, and unlike ambiguousBuildSegments these are trusted on an
// ABSOLUTE path too: `e2e` and `cypress` are not plausible ancestor-directory names on
// a developer's machine, so the gitless-fallback hazard (an ancestor dir silently
// dropping a whole project) does not arise. Deliberately omits the bare `test`/`tests`
// segment: that is a common first-party domain word (a `tests` table module, dbt data
// tests), and blanket-dropping it would take real source with it.
var testSegments = map[string]bool{
	"e2e": true, "cypress": true, "playwright": true, "__tests__": true,
}

// testBasenames are test-harness config/bootstrap files that carry no shipped logic.
var testBasenames = map[string]bool{
	"tsconfig.spec.json": true, "phpunit.xml": true, "phpunit.xml.dist": true,
	"jest.config.js": true, "jest.config.ts": true, "jest.setup.js": true, "jest.setup.ts": true,
	"vitest.config.js": true, "vitest.config.ts": true, "playwright.config.ts": true,
	"conftest.py": true, "karma.conf.js": true,
}

// testSupport reports whether a path is test-only by convention in a way enry.IsTest
// does not detect: a test-tree segment, a harness config file, or PHPUnit's
// `<Name>Test.php` / `<Name>TestCase.php` naming (enry covers *Test.java but not the
// PHP convention). Separator-agnostic, mirroring vendored().
func testSupport(p string) bool {
	q := strings.ReplaceAll(p, `\`, "/")
	for _, seg := range strings.Split(q, "/") {
		if testSegments[seg] {
			return true
		}
	}
	if testBasenames[baseLower(q)] {
		return true
	}
	// PHPUnit's `<Name>Test.php` / `<Name>TestCase.php`. Matched CASE-SENSITIVELY on the
	// raw base name, because PHPUnit's convention is PascalCase and a lowercased suffix
	// check drops real source: latest.php and Attest.php both end in "test.php".
	// (`_test.php` is accepted too — the snake_case variant some suites use.)
	raw := q
	if i := strings.LastIndex(q, "/"); i >= 0 {
		raw = q[i+1:]
	}
	for _, suf := range []string{"Test.php", "TestCase.php", "_test.php"} {
		if len(raw) > len(suf) && strings.HasSuffix(raw, suf) {
			return true
		}
	}
	return false
}

// svgActiveMarkers are the substrings that make an SVG executable rather than
// decorative: an embedded script, an inline event handler, a javascript: or data:
// URL, an HTML island via <foreignObject>, or an external reference pulled in by
// <use>/<image>. Lowercased comparison; `on` handlers are matched as `on…=` below.
var svgActiveMarkers = []string{
	"<script", "<foreignobject", "<handler", "<set", "<animate",
	"javascript:", "data:text/html", "<!entity", "<use", "xlink:href", "href=",
}

// svgWithoutActiveContent reports whether an SVG provably carries no executable
// content and is therefore decoration, not a security surface.
//
// This REPLACES an assumption the gate used to make: that a giant generated SVG is
// caught by the long-line heuristic because its path data sits on one line. Measured
// against customer corpora, that holds for 2 of 10 large SVGs. Design tools pretty-
// print — a 196 KB leo-globe.svg has a longest line of 107 characters, and 48-85 KB
// icon exports run 900-1800 — so the size sailed through while the premise looked
// sound in the comment.
//
// Fails toward review in every direction: any marker, any doubt, and the file is sent.
// Only the added text is available on a diff, which mirrors how the comment-inert path
// already reasons — a change that introduces no active content is not a new surface.
func svgWithoutActiveContent(c transcript.Change) bool {
	body := c.FullContent
	if body == "" {
		body = c.AddedText
	}
	if body == "" {
		return false // nothing to prove inertness with
	}
	lower := strings.ToLower(body)
	for _, m := range svgActiveMarkers {
		if strings.Contains(lower, m) {
			return false
		}
	}
	// Inline event handlers: `on<name>=`, allowing whitespace before the `=`.
	for i := 0; i+2 < len(lower); i++ {
		if lower[i] != 'o' || lower[i+1] != 'n' {
			continue
		}
		if i > 0 && isASCIILetter(lower[i-1]) {
			continue // inside a longer word (version=, button=)
		}
		j := i + 2
		for j < len(lower) && isASCIILetter(lower[j]) {
			j++
		}
		if j == i+2 {
			continue // bare "on", no handler name
		}
		for j < len(lower) && (lower[j] == ' ' || lower[j] == '\t' || lower[j] == '\n' || lower[j] == '\r') {
			j++
		}
		if j < len(lower) && lower[j] == '=' {
			return false
		}
	}
	return true
}

func isASCIILetter(b byte) bool { return ('a' <= b && b <= 'z') || ('A' <= b && b <= 'Z') }

// inert reports whether a single change is provably harmless and can skip review.
// It returns true ONLY for pure-prose files and for source diffs whose every
// non-blank added line is a comment. When in doubt it returns false (review).
func inert(c transcript.Change) bool {
	// Dependency installs / build output are never the dev's own change — drop
	// regardless of extension or content (covers a tracked node_modules and the
	// gitignore-blind transcript fallback).
	if v, byEnry := vendoredReason(c.FilePath); v {
		if byEnry {
			// A go-enry heuristic drop (not the explicit hand-list). Usually correct
			// (real vendored tree), but it can misfire on a first-party source file in
			// a cache/env-named dir or with a library-name basename — which would then
			// go UNREVIEWED. Leave a breadcrumb in the client log so such a false
			// negative is discoverable (behavior is unchanged: the file is still dropped).
			slog.Warn("gate: file dropped as vendored by go-enry heuristic (not the explicit hand-list) — if this is first-party source it goes UNREVIEWED", "path", c.FilePath)
		}
		return true
	}

	base := baseLower(c.FilePath)
	// Editor backup copies (emacs/gedit `file~`, and `.#file` / `#file#` locks) — the
	// live file is reviewed instead, so these are redundant. Checked on the raw base
	// (a trailing `~` survives lowercasing).
	if strings.HasSuffix(base, "~") || strings.HasPrefix(base, ".#") ||
		(strings.HasPrefix(base, "#") && strings.HasSuffix(base, "#")) {
		return true
	}
	// Machine-generated dependency locks not caught by the .lock extension below.
	if lockfileBasenames[base] {
		return true
	}

	// Test files (unit / integration / e2e) — the dev's own code, but NOT a shipped
	// security surface, and dense with hardcoded test creds + localhost URLs that read
	// as false-positive bait. Path-based, via go-enry's Linguist test matchers (same
	// source as IsVendor/IsGenerated below): *_test.go, *.test.tsx, *.e2e.test.ts,
	// test_*.py, *_spec.rb, *Test.java, … all match. NB this is coarse (all tests, no
	// e2e-vs-unit split) and misses a few conventions enry doesn't track (e.g. Cypress
	// .cy.js) — those still get reviewed, which is the safe direction.
	if enry.IsTest(c.FilePath) || testSupport(c.FilePath) {
		return true
	}

	ext := strings.ToLower(filepath.Ext(c.FilePath))

	if nonExecutable[ext] {
		return true
	}

	// Codegen / minified output (suffix), then a content signal for generated/minified
	// blobs whose name looks hand-authored (e.g. a committed library .js with a single
	// multi-kilobyte data line). Both run BEFORE the comment-marker logic so a minified
	// .js is dropped on content, not mis-scanned line-by-line.
	if generated(base) || looksGenerated(c) {
		return true
	}

	// An SVG with no active content. SVG stays reviewable because it can carry a
	// script; when it demonstrably carries none, there is nothing for the judge to
	// find and the file is a large asset like any other .png.
	if ext == ".svg" && svgWithoutActiveContent(c) {
		return true
	}

	// Content-based backstop via go-enry (GitHub Linguist's Go port): generated-code
	// and binary detection, so the hand suffix lists don't grow per codegen tool or
	// binary format. (Path-based third-party detection is handled by vendored() above
	// via enry.IsVendor.) Deliberately EXCLUDED here:
	//   - enry.IsImage: would skip .svg, kept reviewable for SVG-XSS.
	//   - enry.IsConfiguration: config is security-relevant (CORS/TLS/debug flags).
	content := []byte(c.FullContent)
	if len(content) == 0 {
		content = []byte(c.AddedText)
	}
	if enry.IsGenerated(c.FilePath, content) || enry.IsBinary(content) {
		return true
	}

	markers, known := commentMarkers[ext]
	if !known {
		// Unknown extension (or no extension, or HTML/XML) → never assume inert.
		return false
	}

	// Inert iff there is at least one non-blank added line AND every one of them
	// starts with a comment marker. The "at least one" guard matters: an EMPTY
	// AddedText must NOT be deemed inert by vacuous truth — that would be a silent
	// skip of a file we couldn't read added lines for (e.g. a diff that resolved to
	// nothing because of a path/cwd mismatch upstream), which is exactly the
	// false-negative this denylist exists to avoid. No added lines → fail toward
	// review.
	sawLine := false
	for _, line := range strings.Split(c.AddedText, "\n") {
		t := strings.TrimSpace(line)
		if t == "" {
			continue
		}
		sawLine = true
		if !hasAnyPrefix(t, markers) {
			return false
		}
	}
	return sawLine
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// Run returns the subset of changed files that warrant review — i.e. everything
// not provably inert. The gate is a denylist: it fails toward review.
func Run(changes []transcript.Change) []transcript.Change {
	var reviewable []transcript.Change
	for _, c := range changes {
		if !inert(c) {
			reviewable = append(reviewable, c)
		}
	}
	return reviewable
}
