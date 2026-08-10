// Package rulespec is the shared rule contract: the Rule struct and the corpus
// parsing/meta-policy helpers used by BOTH the client (local-tier selection and
// review) and the server (selection + judging). It lives once so the rule
// definition can never drift between the two deployables.
//
// It holds NO rule content and embeds nothing — it only knows the shape of a
// rule and how to parse the corpus YAML. The corpus bytes are supplied by the
// caller (the server reads corpus/ from disk; the client receives content over
// the /rules endpoint).
package rulespec

import (
	"fmt"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Rule is a single model-judge criterion, fields verbatim from the corpus YAML.
// JSON tags are for the wire format (the /rules response); YAML tags are for
// parsing the corpus.
type Rule struct {
	ID               string   `yaml:"id" json:"id"`
	Name             string   `yaml:"name" json:"name"`
	Type             string   `yaml:"type" json:"type"` // "pattern" | "assumption"
	Category         string   `yaml:"category" json:"category,omitempty"`
	Description      string   `yaml:"description" json:"description,omitempty"`
	Severity         string   `yaml:"default_severity" json:"severity,omitempty"`
	LookFor          string   `yaml:"look_for" json:"look_for"`
	DoesNotApplyWhen string   `yaml:"does_not_apply_when" json:"does_not_apply_when,omitempty"`
	Suggestion       string   `yaml:"suggestion" json:"suggestion,omitempty"`
	CWE              []int    `yaml:"cwe" json:"cwe,omitempty"`
	AppliesTo        []string `yaml:"applies_to" json:"applies_to,omitempty"`
	// AutoFix gates whether findings for this rule may be FORCE-FIXED in-turn.
	// nil/absent ⇒ true (auto-fix allowed — the historical default for every rule).
	// Explicit `auto_fix: false` ⇒ suggest-only: findings are SURFACED to the
	// developer to fix-or-not, never silently rewritten in-turn — reserved for rules
	// whose fix carries high regression risk (e.g. reverse-proxy / web-server config
	// rewrites that can break routing). A pointer so an omitted flag is distinguishable
	// from an explicit false.
	AutoFix *bool `yaml:"auto_fix" json:"auto_fix,omitempty"`
}

// AutoFixAllowed reports whether findings for this rule may be force-fixed in-turn.
// Absent (nil) defaults to true so existing rules keep their auto-fix behaviour;
// only an explicit `auto_fix: false` makes a rule suggest-only.
func (r Rule) AutoFixAllowed() bool {
	return r.AutoFix == nil || *r.AutoFix
}

// ParseRules parses the corpus patterns + assumptions YAML into one rule list
// (patterns first, then assumptions — the order the corpus has always used).
func ParseRules(patternsYAML, assumptionsYAML []byte) ([]Rule, error) {
	var patterns, assumptions []Rule
	if err := yaml.Unmarshal(patternsYAML, &patterns); err != nil {
		return nil, fmt.Errorf("rulespec: patterns: %w", err)
	}
	if err := yaml.Unmarshal(assumptionsYAML, &assumptions); err != nil {
		return nil, fmt.Errorf("rulespec: assumptions: %w", err)
	}
	return append(patterns, assumptions...), nil
}

// metaPolicyMarker is a defensive guard: corpus/meta-policy.md is meta-policy
// only (the rule content lives in patterns.yaml + assumptions.yaml), but if a
// "## Patterns" prose section is ever reintroduced, everything from it onward is
// dropped so per-rule prose can't leak into the injected meta-policy.
const metaPolicyMarker = "## Patterns"

// MetaPolicy returns the meta-policy from corpus/meta-policy.md: the "don't
// replicate unsafe patterns / audit lookalike _check_/validate_/safe_ helpers"
// rules the reviewer applies on top of the per-rule criteria. The file is
// meta-policy only; the marker-strip below is a no-op safety net (see above).
func MetaPolicy(metaPolicyMD string) string {
	md := metaPolicyMD
	if i := strings.Index(md, metaPolicyMarker); i >= 0 {
		md = md[:i]
	}
	return strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(md), "---"))
}

// agentWorkflowMarker splits the meta-policy into judge-facing REVIEW PRINCIPLES
// (above the marker) and coding-agent WORKFLOW choreography (below it) —
// response formatting, 🚨 banners, wait-for-go-ahead steps. The workflow half
// must never reach the server-side judge: it instructs prose response formatting
// ("open your response with ## ⚠️ SECURITY WARNING") that directly contradicts
// the judge's return-ONLY-JSON contract — a variance and parse-failure source.
// The LOCAL tier keeps the full text (its reader IS the coding agent).
const agentWorkflowMarker = "## Agent workflow"

// MetaPolicyForJudge returns the meta-policy with the agent-workflow section
// stripped — what the server-side model judge should see. A meta-policy.md
// without the marker (an older corpus) is returned whole, preserving the
// previous behavior rather than guessing at a split.
func MetaPolicyForJudge(metaPolicyMD string) string {
	md := MetaPolicy(metaPolicyMD)
	if i := strings.Index(md, agentWorkflowMarker); i >= 0 {
		md = md[:i]
	}
	return strings.TrimSpace(md)
}

// extLanguage maps a file extension (lowercase, leading dot) to the canonical
// language token used in a rule's applies_to list. Extensions absent here yield
// "" (unknown), which is treated as recall-preserving (see AppliesToLangs).
var extLanguage = map[string]string{
	".py": "python",
	".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript",
	".ts": "typescript", ".tsx": "typescript",
	".java": "java",
	".php":  "php",
	".rb":   "ruby",
	".html": "html", ".htm": "html",
	// CI pipelines (GitHub Actions, GitLab CI) and Spring Boot config live in
	// YAML; mapping it lets yaml-scoped rules ride only on yaml diffs AND drops
	// other-language-scoped rules from yaml-only diffs. NB: tagging a rule with a
	// language implicitly EXCLUDES it from yaml-only diffs once this mapping
	// exists — a rule whose sink appears in config files must list yaml too
	// (e.g. spring-boot-actuator-exposure is [java, yaml]).
	".yml": "yaml", ".yaml": "yaml",
	// Mapped so a language-scoped rule can be DROPPED for these files even though
	// no current rule lists them (e.g. an html/js-only rule won't apply to .go).
	".go": "go", ".cs": "csharp", ".rs": "rust", ".kt": "kotlin",
	".c": "c", ".cc": "cpp", ".cpp": "cpp", ".h": "c", ".hpp": "cpp",
	".scala": "scala", ".swift": "swift", ".sql": "sql",
}

// LanguageOf returns the canonical language token for a file path, or "" if the
// extension is unknown.
func LanguageOf(path string) string {
	return extLanguage[strings.ToLower(filepath.Ext(path))]
}

// LanguagesOf returns the set of KNOWN languages across the given paths (unknown
// extensions contribute nothing).
func LanguagesOf(paths []string) map[string]bool {
	langs := map[string]bool{}
	for _, p := range paths {
		if l := LanguageOf(p); l != "" {
			langs[l] = true
		}
	}
	return langs
}

// AppliesToLangs reports whether the rule applies to at least one of langs. A
// rule with no applies_to applies to EVERY language; an empty langs set (no
// recognizable language among the changed files) keeps the rule — both are
// recall-preserving, so language filtering only ever drops a rule when we are
// confident its languages don't intersect the change.
func (r Rule) AppliesToLangs(langs map[string]bool) bool {
	if len(r.AppliesTo) == 0 || len(langs) == 0 {
		return true
	}
	for _, l := range r.AppliesTo {
		if langs[strings.ToLower(l)] {
			return true
		}
	}
	return false
}

// FilterByLanguages keeps only rules that apply to the languages of the changed
// files (by extension). Order is preserved; rules with no applies_to are always
// kept. Used by BOTH tiers so "which rules apply to THIS change" includes the
// per-rule language scope.
func FilterByLanguages(rules []Rule, paths []string) []Rule {
	langs := LanguagesOf(paths)
	out := make([]Rule, 0, len(rules))
	for _, r := range rules {
		if r.AppliesToLangs(langs) {
			out = append(out, r)
		}
	}
	return out
}
