// Inert paths: the half of the review gate that needs only a file's NAME.
//
// ⚠️ IT LIVES HERE FOR THE REASON IsSecretPath DOES, AND ITS ABSENCE COST A REAL REVIEW.
// The full gate (client/internal/gate) also reads a file's CONTENT, which is exactly what
// the pull-request lane is deciding whether to spend its budget fetching — so the lane
// could not use it, and being client-internal it could not import it either. The result
// was that a pull request's whole budget could go on test files and generated output,
// which the Stop hook drops before it reads a byte: on PR #589, 205 KiB of a 512 KiB
// budget went on two test files and the tree the change was actually about was never
// reached.
//
// So the PATH-ONLY predicates live here and both callers share them. Content heuristics
// (a comment-only diff, a minified blob detected by line length, an SVG with no active
// content) stay in the client's gate, because they need the body and the lane's whole
// question is whether to fetch one.

package pathgate

import (
	"path/filepath"
	"strings"

	"github.com/go-enry/go-enry/v2"
)

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
func IsVendored(p string) bool {
	v, _ := VendoredReason(p)
	return v
}

// vendoredReason reports whether p is vendored AND whether the decision came from the
// go-enry heuristic (byEnry) rather than the explicit hand-list. The caller logs the
// byEnry drops: enry's Linguist patterns match on ambiguous dir words (cache/, env/)
// and library-name basenames (controls.js), so a heuristic match on a first-party
// SOURCE file would drop it unreviewed — the exact silent false negative this gate
// exists to avoid. The hand-list matches (byEnry=false) are deterministic and quiet.
func VendoredReason(p string) (isVendored, byEnry bool) {
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

// baseLower returns the lowercased base name of a path, separator-agnostic.
func BaseLower(p string) string {
	p = strings.ReplaceAll(p, `\`, "/")
	if i := strings.LastIndex(p, "/"); i >= 0 {
		p = p[i+1:]
	}
	return strings.ToLower(p)
}

// generated reports whether a lowercased base name ends in a known codegen/minified
// suffix (see generatedSuffixes).
func IsGeneratedName(base string) bool {
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
	if testBasenames[BaseLower(q)] {
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

// IsEditorBackup reports an editor's backup or lock copy (emacs/gedit `file~`, `.#file`,
// `#file#`). The live file is reviewed instead, so these are redundant. Checked on the
// RAW base name, since a trailing `~` survives lowercasing.
func IsEditorBackup(p string) bool {
	base := BaseLower(p)
	return strings.HasSuffix(base, "~") || strings.HasPrefix(base, ".#") ||
		(strings.HasPrefix(base, "#") && strings.HasSuffix(base, "#"))
}

// IsLockfile reports a machine-generated dependency lock, by extension or by one of the
// names the extension misses. The hand-authored MANIFEST beside it (package.json, go.mod,
// *.csproj) is deliberately NOT matched: a new dependency or a postinstall script is real
// supply-chain surface.
func IsLockfile(p string) bool {
	if strings.EqualFold(filepath.Ext(p), ".lock") {
		return true
	}
	return lockfileBasenames[BaseLower(p)]
}

// IsTestPath reports a test file, by enry's Linguist matchers or by the conventions they
// miss. Test code is the developer's own but is not a shipped security surface, and it is
// dense with hardcoded credentials and localhost URLs that read as false-positive bait.
func IsTestPath(p string) bool {
	return enry.IsTest(p) || testSupport(p)
}

// InertReason names why a path needs no review, or returns "" when it does.
//
// ⚠️ IT ANSWERS FROM THE NAME ALONE, WHICH IS WHAT MAKES IT USABLE BEFORE A FETCH — and
// it is therefore a STRICT SUBSET of the client gate's answer, never a replacement for it.
// A caller that has the body still has content checks to run; a caller that does not can
// at least decline to pay for one.
//
// ⚠️ AND IT NAMES THE REASON RATHER THAN RETURNING A BOOLEAN, because both callers have to
// say what they skipped: a silently absent file reads as a file with nothing wrong in it.
func InertReason(p string) string {
	switch {
	case IsVendored(p):
		return "vendored or build output"
	case IsEditorBackup(p):
		return "editor backup"
	case IsLockfile(p):
		return "lockfile"
	case IsTestPath(p):
		return "test"
	case IsGeneratedName(BaseLower(p)):
		return "generated"
	}
	return ""
}
