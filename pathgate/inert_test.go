package pathgate

import "testing"

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
		{"django/core/cache/backends/filebased.py", true, `(^|/)cache/`},
		{`django\core\cache\backends\filebased.py`, true, `(^|/)cache/`},
		{"node_modules/lib/index.js", true, `(^|/)node_modules/`},
		{"cache/node_modules/lib/index.js", true, `(^|/)cache/`},
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
	for _, rule := range []string{"", "cache/", "/private/customer/path", "(?s).*"} {
		if IsEnryVendorRule(rule) {
			t.Errorf("accepted text that is not an upstream vendor pattern: %q", rule)
		}
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
