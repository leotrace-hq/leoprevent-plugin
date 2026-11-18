package pathgate

import (
	"strings"
	"testing"

	"github.com/go-enry/go-enry/v2/data"
)

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
		if !IsVendored(p) {
			t.Errorf("%s should be vendored (skipped)", p)
		}
	}
	// CI pipelines: Linguist vendors these, but they're a security surface — keep reviewable.
	for _, p := range []string{".github/workflows/ci.yml", "Jenkinsfile", "ci/.github/workflows/deploy.yaml"} {
		if IsVendored(p) {
			t.Errorf("%s must stay REVIEWABLE (CI security surface), got vendored", p)
		}
	}
}

func TestVendoredMatchReportsFirstEnryRuleWithoutChangingDecisions(t *testing.T) {
	for _, tc := range []struct {
		path string
		skip bool
		rule string
	}{
		{"django/core/cache/backends/filebased.py", false, ""},
		{`django\core\cache\backends\filebased.py`, false, ""},
		{"node_modules/lib/index.js", true, `(^|/)node_modules/`},
		{"cache/node_modules/lib/index.js", true, `(^|/)node_modules/`},
		{"node_modules/lib/cache/index.js", true, `(^|/)node_modules/`},
		{"cache/vendor/lib/index.js", true, `(^|/)vendors?/`},
		{"cache/react.js", true, `(^|/)react(-[^.]*)?\.js$`},
		{"cache/env/lib.py", true, `(^|/)env/`},
		{"fixtures/testdata/sample.go", true, `(^|/)testdata/`},
		{".cache/data.py", true, ""},
		{".venv/cache/lib.py", true, ""},
		{"build/cache/lib.py", true, ""},
		{".github/workflows/ci.yml", false, ""},
		{"ci/Jenkinsfile", false, ""},
		{"src/cacheable.py", false, ""},
	} {
		t.Run(tc.path, func(t *testing.T) {
			got, byEnry, rule := VendoredMatch(tc.path)
			if got != tc.skip || rule != tc.rule {
				t.Fatalf("VendoredMatch = (%v, %q), want (%v, %q)", got, rule, tc.skip, tc.rule)
			}
			v, oldByEnry := VendoredReason(tc.path)
			if v != got || oldByEnry != byEnry || byEnry != (rule != "") || (rule != "" && !IsEnryVendorRule(rule)) {
				t.Fatal("rule attribution disagrees with existing vendor decision")
			}
		})
	}
	if !IsEnryVendorRule(enryCacheRule) {
		t.Fatal("older plugins' cache rule totals must remain valid")
	}
	for _, rule := range []string{"", "cache/", "/private/customer/path", "(?s).*"} {
		if IsEnryVendorRule(rule) {
			t.Errorf("accepted text that is not an upstream vendor pattern: %q", rule)
		}
	}
}

func TestCacheSourcePathsRemainReviewable(t *testing.T) {
	for _, p := range []string{
		"cache/store.py", "src/cache/foo.py", "repo/src/cache/foo.py",
		"django/core/cache/backends/filebased.py",
		"src/cmd/go/internal/cache/cache.go",
		"tools/cache/reflector.go",
		"activesupport/lib/active_support/cache/redis_cache_store.rb",
		`src\cache\foo.py`, `/home/me/cache/project/src/main.go`,
	} {
		if reason := InertReason(p); reason != "" {
			t.Errorf("%s excluded as %q", p, reason)
		}
	}
	for _, p := range []string{
		".cache/cache/tool.py", "cache/.cache/tool.py", "__pycache__/cache/tool.py",
		"cache/__pycache__/tool.py", ".next/cache/tool.js", "cache/.next/tool.js",
		".venv/lib/cache/store.py", "cache/.venv/lib/store.py", "vendor/cache/store.go",
		"cache/vendor/store.go", "node_modules/cache/store.js", "cache/node_modules/store.js",
		".pnp/cache/pkg/index.js", "web/.pnp/cache/pkg/index.js", "cache/.pnp/cache/pkg/index.js",
		`cache\node_modules\store.js`, "cache/dist/tool.js", "cache/build/tool.go",
	} {
		if reason := InertReason(p); reason != "vendored or build output" {
			t.Errorf("%s has reason %q, want vendor/build exclusion", p, reason)
		}
	}
}

func TestAdjustedVendorMatcherPreservesRemainingRules(t *testing.T) {
	// Check the optimized union against independent upstream rules. Prefixes exercise
	// both rooted and component-anchored patterns, including nested cache directories.
	for _, path := range policyPaths() {
		for _, prefix := range []string{"", "cache/", "src/cache/", "cache/cache/"} {
			p := prefix + strings.ReplaceAll(path, `\`, "/")
			want := false
			for _, m := range data.VendorMatchers {
				if m != nil && m.String() != enryCacheRule && m.MatchString(p) {
					want = true
					break
				}
			}
			if got := enryVendorWithoutCache.MatchString(p); got != want {
				t.Errorf("adjusted matcher(%q)=%v, individual rules=%v", p, got, want)
			}
			if got := isEnryVendor(p); got != want {
				t.Errorf("vendor check(%q)=%v, individual rules=%v", p, got, want)
			}
		}
	}
}

func TestSpecificCacheFragmentsAreBoundedDirectories(t *testing.T) {
	for _, fragment := range vendoredPathFragments {
		if len(fragment) < 3 || !strings.HasPrefix(fragment, "/") || !strings.HasSuffix(fragment, "/") {
			t.Fatalf("fragment %q must be bounded by directory separators", fragment)
		}
		for _, p := range []string{fragment[1:] + "store.py", "app" + fragment + "store.py", strings.ReplaceAll("app"+fragment+"store.py", "/", `\`)} {
			v, byEnry, rule := VendoredMatch(p)
			if !v || byEnry || rule != "" {
				t.Errorf("explicit cache %q: (%v, %v, %q)", p, v, byEnry, rule)
			}
		}
		lookalike := strings.TrimSuffix(fragment[1:], "/") + "able/store.py"
		if reason := InertReason(lookalike); reason != "" {
			t.Errorf("cache lookalike %q excluded as %q", lookalike, reason)
		}
	}
}

func TestEmptyVendorMatcherLeavesCacheSourceReviewable(t *testing.T) {
	previous := enryVendorWithoutCache
	enryVendorWithoutCache = compileEnryVendorMatcher(nil)
	t.Cleanup(func() { enryVendorWithoutCache = previous })
	if enryVendorWithoutCache != nil {
		t.Fatal("empty matcher set must not compile a match-all expression")
	}
	v, byEnry, rule := VendoredMatch("src/cache/store.py")
	if v || byEnry || rule != "" {
		t.Fatalf("empty rules excluded source: (%v, %v, %q)", v, byEnry, rule)
	}
}

// TestInertReason_ProdMeasuredTypes locks the file types LEO-748 found reaching /review
// in production with nothing a rule could find, and the neighbours that must stay
// reviewable because they execute or can hold a leaked secret.
func TestInertReason_ProdMeasuredTypes(t *testing.T) {
	for _, p := range []string{
		"docs/diagrams/flow.mmd", "docs/ai/diagrams/1-context.puml", "demo-video/captions.srt",
		"installer/EULA.rtf", ".cursor/rules/style.mdc", "scratchpad/body.part", "app.conf.backup",
		"scripts/ui/VectorBar.cs.uid", "sorbet/rbi/gems/tapioca@0.20.0.rbi",
		"assets/icon.png.import", "demo/captions.vtt", "models/ship.mtl",
		"SHA256SUMS", "dist/sha512sums",
		// backups: plain, and numbered so the extension check reads only the number
		"main.go.bak", "config.yaml.old", "app.ts.bkp",
		".claude.json.backup.1791213689107", "settings.py.bak.2", "nginx.conf.orig.1",
	} {
		if InertReason(p) == "" {
			t.Errorf("InertReason(%q) = \"\", want it dropped", p)
		}
	}
	for _, p := range []string{
		"views/index.njk", "modules/core/index.vt", "WEB-INF/views/tools.jsp", "shell.jspx",
		"exploit.xslt", ".env.example", ".gitleaksignore", "Dockerfile", "VERSION", "infra/main.tofu",
		// Godot resources and scenes can embed GDScript; shaders are GPU code
		"scenes/main.tscn", "themes/default.tres", "shaders/glow.frag", "shaders/glow.vert",
		// "copy" as in UI text, measured in prod as real source; and numbers that are not backups
		"lib/consent_copy.dart", "src/approval-copy.ts", "lib/v1.2", "migrations.0001",
	} {
		if r := InertReason(p); r != "" {
			t.Errorf("InertReason(%q) = %q, want it REVIEWABLE", p, r)
		}
	}
}
