package rulespec

import "testing"

const patternsYAML = `
- id: ssrf
  name: Server-Side Request Forgery
  type: pattern
  category: Injection
  description: Outbound request to an untrusted destination
  default_severity: high
  look_for: HTTP client calls with a user-controlled URL.
  does_not_apply_when: The URL is a hardcoded constant.
  suggestion: Resolve to IP and reject private ranges.
  cwe: [918]
  applies_to: [python, javascript]
`

const assumptionsYAML = `
- id: no-input-validation
  name: External Data Trust
  type: assumption
  default_severity: medium
  look_for: Treating an external response as trusted.
  suggestion: Validate it.
`

func TestParseRulesMapsFieldsAndOrder(t *testing.T) {
	rules, err := ParseRules([]byte(patternsYAML), []byte(assumptionsYAML))
	if err != nil {
		t.Fatalf("ParseRules: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("want 2 rules, got %d", len(rules))
	}
	// Patterns come before assumptions.
	if rules[0].ID != "ssrf" || rules[1].ID != "no-input-validation" {
		t.Fatalf("wrong order: %s, %s", rules[0].ID, rules[1].ID)
	}
	r := rules[0]
	// default_severity -> Severity; the rest map by tag.
	if r.Severity != "high" {
		t.Errorf("Severity = %q, want high (from default_severity)", r.Severity)
	}
	if r.Name != "Server-Side Request Forgery" || r.Type != "pattern" || r.Category != "Injection" {
		t.Errorf("scalar fields mismapped: %+v", r)
	}
	if r.DoesNotApplyWhen == "" || r.LookFor == "" || r.Suggestion == "" {
		t.Errorf("text fields empty: %+v", r)
	}
	if len(r.CWE) != 1 || r.CWE[0] != 918 {
		t.Errorf("CWE = %v, want [918]", r.CWE)
	}
	if len(r.AppliesTo) != 2 || r.AppliesTo[0] != "python" {
		t.Errorf("AppliesTo = %v", r.AppliesTo)
	}
}

func TestParseRulesMalformed(t *testing.T) {
	if _, err := ParseRules([]byte("not: [valid"), []byte(assumptionsYAML)); err == nil {
		t.Error("expected error on malformed patterns YAML")
	}
	if _, err := ParseRules([]byte(patternsYAML), []byte(": : :")); err == nil {
		t.Error("expected error on malformed assumptions YAML")
	}
}

func TestLanguageOf(t *testing.T) {
	cases := map[string]string{
		"app.py": "python", "a.js": "javascript", "a.mjs": "javascript",
		"a.ts": "typescript", "a.tsx": "typescript", "A.java": "java",
		"i.php": "php", "a.rb": "ruby", "page.html": "html", "main.go": "go",
		"unknown.xyz": "", "noext": "",
	}
	for path, want := range cases {
		if got := LanguageOf(path); got != want {
			t.Errorf("LanguageOf(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestAppliesToLangs(t *testing.T) {
	js := Rule{AppliesTo: []string{"javascript", "typescript"}}
	any := Rule{} // no applies_to → applies everywhere

	if !any.AppliesToLangs(map[string]bool{"go": true}) {
		t.Error("rule with no applies_to must apply to any language")
	}
	if !js.AppliesToLangs(map[string]bool{}) {
		t.Error("empty langs (unknown) must keep the rule (recall-preserving)")
	}
	if !js.AppliesToLangs(map[string]bool{"typescript": true}) {
		t.Error("js/ts rule must apply to a typescript change")
	}
	if js.AppliesToLangs(map[string]bool{"python": true}) {
		t.Error("js/ts rule must NOT apply to a python-only change")
	}
}

func TestFilterByLanguages(t *testing.T) {
	rules := []Rule{
		{ID: "generic"}, // applies everywhere
		{ID: "frontend", AppliesTo: []string{"html", "javascript"}},
		{ID: "java-only", AppliesTo: []string{"java"}},
	}
	// A python change: generic stays, frontend + java-only drop.
	got := FilterByLanguages(rules, []string{"app.py"})
	if len(got) != 1 || got[0].ID != "generic" {
		t.Fatalf("python change: want [generic], got %+v", got)
	}
	// A js change: generic + frontend stay, java-only drops.
	got = FilterByLanguages(rules, []string{"app.js"})
	if len(got) != 2 || got[0].ID != "generic" || got[1].ID != "frontend" {
		t.Fatalf("js change: want [generic, frontend], got %+v", got)
	}
	// Unknown extension → keep everything (recall-preserving).
	if got := FilterByLanguages(rules, []string{"data.xyz"}); len(got) != 3 {
		t.Fatalf("unknown ext must keep all rules, got %+v", got)
	}
	// Mixed languages: a rule applying to ANY present language is kept.
	got = FilterByLanguages(rules, []string{"app.py", "page.html"})
	if len(got) != 2 {
		t.Fatalf("py+html: want generic+frontend, got %+v", got)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// TestAutoFixAllowed: nil/absent defaults to true (existing rules keep auto-fix);
// only an explicit auto_fix:false makes a rule suggest-only.
func TestAutoFixAllowed(t *testing.T) {
	tru, fls := true, false
	if !(Rule{ID: "no-flag"}).AutoFixAllowed() {
		t.Error("absent auto_fix must default to allowed")
	}
	if !(Rule{ID: "explicit-true", AutoFix: &tru}).AutoFixAllowed() {
		t.Error("auto_fix:true must be allowed")
	}
	if (Rule{ID: "explicit-false", AutoFix: &fls}).AutoFixAllowed() {
		t.Error("auto_fix:false must be suggest-only (not allowed)")
	}
}

// TestParseRules_AutoFix: the auto_fix flag round-trips from the corpus YAML —
// absent ⇒ nil (allowed), false ⇒ suggest-only.
func TestParseRules_AutoFix(t *testing.T) {
	patterns := []byte("- id: with-fix\n  type: pattern\n  auto_fix: true\n- id: suggest-only\n  type: pattern\n  auto_fix: false\n- id: no-flag\n  type: pattern\n")
	rules, err := ParseRules(patterns, []byte("[]"))
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 3 {
		t.Fatalf("want 3 rules, got %d", len(rules))
	}
	if !rules[0].AutoFixAllowed() || !rules[2].AutoFixAllowed() {
		t.Error("auto_fix:true and absent must be auto-fix allowed")
	}
	if rules[1].AutoFixAllowed() {
		t.Error("auto_fix:false must be suggest-only")
	}
	if rules[2].AutoFix != nil {
		t.Error("absent auto_fix must parse to nil, not a zero-value pointer")
	}
}
