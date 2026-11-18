package depcheck

import (
	"strings"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

const (
	ruleDirect   = "In an npm lockfile, change each direct package as its file says."
	ruleIndirect = "In an npm lockfile, if it still has an indirect package at a vulnerable version, update what brings it in."
	rulePriority = "These versions come from current advisory data."
)

// Two files' offers in parts make one offer (LEO-832): one question counting every package, one
// answered line, each rule once with the priority line last, then each file's changes under its
// name, in name order.
func TestSeveralFilesOffersAreMadeOne(t *testing.T) {
	r := results{
		offers: []string{"WEB OFFER", "API OFFER"},
		parts: []offerPart{
			{label: "apps/web/package-lock.json", changes: "Make each change in apps/web/package.json.\n- lodash", rules: []string{ruleDirect, rulePriority}, packages: 1},
			{label: "apps/api/package-lock.json", changes: "Make each change in apps/api/package.json.\n- axios\nIndirect:\n- minimist", rules: []string{ruleDirect, ruleIndirect, rulePriority}, packages: 2},
		},
	}
	got := r.offerText()
	for _, want := range []string{
		`"Fix the 3 dependencies in these 2 files that have a fix on the same major version?"`,
		"in 2 dependency files.",
		"If they say yes:\n" + ruleDirect + "\n" + ruleIndirect + "\n" + rulePriority + "\n\napps/api/package-lock.json:\nMake each change in apps/api/package.json.\n- axios\nIndirect:\n- minimist\n\napps/web/package-lock.json:\nMake each change in apps/web/package.json.\n- lodash",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("offer lacks %q:\n%s", want, got)
		}
	}
	for what, n := range map[string]int{"Ask once": 1, wire.OfferAnsweredLine: 1, ruleDirect: 1, rulePriority: 1, "OFFER": 0} {
		if c := strings.Count(got, what); c != n {
			t.Errorf("%q appears %d times, want %d:\n%s", what, c, n, got)
		}
	}
	r.goOffer = true
	if !strings.Contains(r.offerText(), "Fixing may raise the Go version in go.mod") {
		t.Error("a Go file's warning is kept")
	}
}

// One file's offer is the server's, unchanged; offers that didn't all come in parts (an older
// server) are each kept whole, so nothing is dropped.
func TestAnOfferIsCombinedOnlyWhenItCan(t *testing.T) {
	one := results{offers: []string{"API OFFER"}, parts: []offerPart{{label: "a", changes: "c", rules: []string{rulePriority}, packages: 1}}}
	if got := one.offerText(); got != "API OFFER" {
		t.Errorf("one file: %q", got)
	}
	mixed := results{offers: []string{"API OFFER", "WEB OFFER"}, parts: []offerPart{{label: "a", changes: "c", rules: []string{rulePriority}, packages: 1}}}
	if got := mixed.offerText(); got != "API OFFER\n\nWEB OFFER" {
		t.Errorf("not all in parts: %q", got)
	}
}

// A file sent in several requests counts once, its changes together under its name; on its own it
// isn't combined.
func TestAFileSentInPartsCountsOnce(t *testing.T) {
	r := results{
		offers: []string{"A1", "A2", "B"},
		parts: []offerPart{
			{label: "a/package-lock.json", changes: "- one", rules: []string{ruleDirect, rulePriority}, packages: 1},
			{label: "b/package-lock.json", changes: "- three", rules: []string{ruleDirect, rulePriority}, packages: 1},
			{label: "a/package-lock.json", changes: "- two", rules: []string{ruleDirect, rulePriority}, packages: 1},
		},
	}
	if got := r.offerText(); !strings.Contains(got, "Fix the 3 dependencies in these 2 files") || !strings.Contains(got, "a/package-lock.json:\n- one\n- two\n\nb/package-lock.json:\n- three") {
		t.Errorf("offer:\n%s", got)
	}
	split := results{offers: []string{"A1", "A2"}, parts: r.parts[:1]}
	split.parts = append(split.parts, r.parts[2])
	if got := split.offerText(); got != "A1\n\nA2" {
		t.Errorf("one file in two requests: %q", got)
	}
}

// Brief mode keeps its one question and its report, and gives the instructions as each rule once,
// then each file's changes.
func TestBriefModeSaysTheRulesOnce(t *testing.T) {
	r := results{
		offers: []string{"q" + offerYes + "API WHOLE", "q" + offerYes + "WEB WHOLE"},
		parts: []offerPart{
			{label: "api/package-lock.json", changes: "- axios", rules: []string{ruleDirect, rulePriority}, packages: 1},
			{label: "web/package-lock.json", changes: "- lodash", rules: []string{ruleDirect, rulePriority}, packages: 1},
		},
	}
	got := r.briefOffer(false)
	if strings.Contains(got, "WHOLE") || strings.Count(got, ruleDirect) != 1 || !strings.Contains(got, "Each file's instructions:\n\n"+ruleDirect+"\n"+rulePriority+"\n\napi/package-lock.json:\n- axios") {
		t.Errorf("brief offer:\n%s", got)
	}
}

// mergeRules keeps every list's order, so a rule only some files have goes before the rule they
// all end with.
func TestMergeRulesKeepsTheOrder(t *testing.T) {
	got := strings.Join(mergeRules([][]string{{"d", "p"}, {"d", "i", "p"}, {"g", "p"}}), ",")
	if got != "d,i,g,p" {
		t.Errorf("merged = %s", got)
	}
}
