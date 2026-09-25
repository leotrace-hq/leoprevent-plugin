// Package rulespec is the shared rule contract: the Rule struct and the corpus
// parsing helpers used by BOTH the client (local-tier selection and review) and
// the server (selection + judging). It lives once so the rule
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
	Type             string   `yaml:"type" json:"type"` // "pattern" | "hardening"
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
	// TaintBased says this rule is a TAINT-FLOW rule: it fires because an untrusted
	// value reaches a security-sensitive sink. It gates the taint-source severity
	// adjustment (LEO-175) and nothing else.
	//
	// ⚠️ ROUGHLY HALF THE CORPUS IS NOT TAINT-FLOW SHAPED, AND FOR THOSE THE TAINT
	// SOURCE IS AN ANSWER TO A QUESTION NOBODY ASKED. A rule about a configuration, a
	// crypto choice or a missing check has no untrusted value to trace: the flaw is
	// `DEBUG = True`, or `MD5`, or the absent role gate. Grading such a finding by
	// "where the value came from" mis-states it, and the mis-statement is a DOWNGRADE,
	// which is the invisible direction. Live examples the flag exists to fix:
	// `hardcoded-secrets`, `debug-mode-enabled` and `cleartext-sensitive-transport` all
	// fire ONLY on a constant, so every finding of theirs would report
	// `taint_source: literal` and lose two severity steps — a checked-in credential
	// graded `low` for the crime of being a constant, which is the entire rule.
	//
	// ⚠️ nil/absent ⇒ FALSE, i.e. NO ADJUSTMENT, and that default is the safe one: a
	// rule nobody has classified keeps its corpus severity rather than being quietly
	// graded down. It is the opposite default to AutoFix above, which defaults true to
	// preserve historical behaviour — here the historical behaviour IS no adjustment.
	//
	// ⚠️ IT IS STILL A POINTER, EVEN THOUGH ABSENT AND FALSE BEHAVE IDENTICALLY. The
	// two mean different things to a READER: absent is "nobody has looked at this
	// rule", explicit false is "somebody looked and it is not taint-flow". Every rule
	// in the corpus therefore declares one, and the corpus test asserts that — so a
	// rule added later cannot silently skip the adjustment, which would present as a
	// grade that never moves rather than as anything failing.
	TaintBased *bool `yaml:"taint_based" json:"taint_based,omitempty"`
}

// TaintSeverityApplies reports whether the taint-source severity adjustment applies to
// findings of this rule. Absent (nil) is FALSE — see the field comment for why the
// unclassified default must be "do not adjust".
func (r Rule) TaintSeverityApplies() bool {
	return r.TaintBased != nil && *r.TaintBased
}

// TaintClassified reports whether the rule DECLARES a taint_based value at all. Only
// the corpus completeness test reads this: the adjustment itself cannot tell an absent
// flag from an explicit false, and must not, but a reader and a test can.
func (r Rule) TaintClassified() bool { return r.TaintBased != nil }

// AutoFixAllowed reports whether findings for this rule may be force-fixed in-turn.
// Absent (nil) defaults to true so existing rules keep their auto-fix behaviour;
// only an explicit `auto_fix: false` makes a rule suggest-only.
func (r Rule) AutoFixAllowed() bool {
	return r.AutoFix == nil || *r.AutoFix
}

// ParseRules parses the corpus patterns + hardening YAML into one rule list
// (patterns first, then hardening — the order the corpus has always used).
func ParseRules(patternsYAML, hardeningYAML []byte) ([]Rule, error) {
	var patterns, hardening []Rule
	if err := yaml.Unmarshal(patternsYAML, &patterns); err != nil {
		return nil, fmt.Errorf("rulespec: patterns: %w", err)
	}
	if err := yaml.Unmarshal(hardeningYAML, &hardening); err != nil {
		return nil, fmt.Errorf("rulespec: hardening: %w", err)
	}
	return append(patterns, hardening...), nil
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
