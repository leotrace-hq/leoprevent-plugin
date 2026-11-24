package pathgate

import "testing"

func TestExcludedPathMatchesRepositoryRelativeGlobs(t *testing.T) {
	// Arrange
	cases := []struct {
		patterns []string
		path     string
		want     bool
	}{
		{[]string{"prototypes/**"}, "prototypes/supplier-onboarding/check.mjs", true},
		{[]string{"prototypes/"}, "prototypes/a/b.html", true},
		{[]string{"prototypes/**"}, "apps/prototypes/x.ts", false},
		{[]string{"**/prototypes/**"}, "apps/prototypes/x.ts", true},
		{[]string{"docs/product/mockups/*.html"}, "docs/product/mockups/super-cargo-mvp.html", true},
		{[]string{"docs/product/mockups/*.html"}, "docs/product/mockups/v2/a.html", false},
		{[]string{"**/*.html"}, "index.html", true},
		{[]string{"**/*.html"}, "a/b/index.html", true},
		{[]string{"apps/api/**"}, "apps/apiary/x.ts", false},
		{[]string{"Prototypes/**"}, "prototypes/x.ts", false},
		{[]string{"../**"}, "prototypes/x.ts", false},
		{[]string{"**"}, "anything.ts", false},
	}

	for _, c := range cases {
		// Act
		_, got := ExcludedPath(c.patterns, c.path)

		// Assert
		if got != c.want {
			t.Errorf("ExcludedPath(%q, %q) = %v, want %v", c.patterns, c.path, got, c.want)
		}
	}
}

func TestNormaliseExcludedPathRejectsPatternsThatExcludeEverythingOrEscape(t *testing.T) {
	// Arrange
	bad := []string{"", "   ", "**", "/", "*/**", "../x/**", "a/../b", "a//b"}

	for _, p := range bad {
		// Act
		_, ok := NormaliseExcludedPath(p)

		// Assert
		if ok {
			t.Errorf("NormaliseExcludedPath(%q) accepted, want rejected", p)
		}
	}
}

func TestNormaliseExcludedPathCleansLeadingAndTrailingSlashes(t *testing.T) {
	// Arrange
	in := " ./prototypes/ "

	// Act
	got, ok := NormaliseExcludedPath(in)

	// Assert
	if !ok || got != "prototypes/**" {
		t.Errorf("NormaliseExcludedPath(%q) = %q, %v; want prototypes/**, true", in, got, ok)
	}
}
