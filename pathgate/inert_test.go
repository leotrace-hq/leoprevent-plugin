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
