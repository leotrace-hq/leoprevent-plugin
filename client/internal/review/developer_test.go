package review

import (
	"strings"
	"testing"
)

const depNotice = "🛡️ LeoPrevent · dependency check (1 package) · package-lock.json\nlodash 4.17.15 (was 4.17.10) has 3 high vulnerabilities (GHSA-35jh-r3h4-6jhm and 2 more). The advisories name 4.18.0 as the fix."

// The notice is quoted line by line, so it reads as LeoPrevent's and not the agent's.
func TestDeveloperMarkdownQuotesEveryLine(t *testing.T) {
	got := DeveloperMarkdown("a\n\nb\n")
	if got != "> a\n>\n> b" {
		t.Errorf("%q", got)
	}
}

// The relay prompts carry the exact markdown, and say it isn't something to act on.
func TestTheRelayPromptsCarryTheMarkdown(t *testing.T) {
	md := DeveloperMarkdown(depNotice)
	for name, p := range map[string]string{
		"relay":      DeveloperRelayPrompt(md),
		"addendum":   DeveloperAddendum(md),
		"firstClean": WithFirstClean(FirstCleanRelayPrompt(), md),
	} {
		if !strings.Contains(p, md) || !strings.Contains(p, "not something to act on") && name != "firstClean" {
			t.Errorf("%s: %q", name, p)
		}
	}
	if fc := WithFirstClean(FirstCleanRelayPrompt(), md); !strings.HasPrefix(fc, strings.TrimRight(FirstCleanRelayPrompt(), "\n")) {
		t.Error("the first-clean relay is kept as it is, with the notice after it")
	}
	if !strings.Contains(DeveloperRelayPrompt(md), "end your turn without doing any other work") {
		t.Error("a notice on its own: print and stop")
	}
}

// What was only relayed is removed from the agent's reply before /outcome: an exact copy, one
// with re-flowed whitespace, wherever it sits. A paraphrase can't be found and is left as it is.
func TestWithoutRelayedRemovesTheDictatedNotice(t *testing.T) {
	md := DeveloperMarkdown(depNotice)
	review := "> 🛡️ LeoPrevent · automated security review\n> Reviewed 1 changed file."
	fix := "I fixed the SQL injection in app.py by using a parameterised query."
	cases := map[string]struct{ reply, want string }{
		"exact, between the review block and the fix": {
			review + "\n\n" + md + "\n\n" + fix, review + "\n\n" + fix},
		"exact, at the end": {fix + "\n\n" + md, fix},
		"re-flowed: indented, trailing spaces, a blank line inside": {
			review + "\n\n  > 🛡️ LeoPrevent · dependency check (1 package) · package-lock.json  \n\n  > lodash 4.17.15 (was 4.17.10) has 3 high vulnerabilities (GHSA-35jh-r3h4-6jhm and 2 more). The advisories name 4.18.0 as the fix.\n\n" + fix,
			review + "\n\n" + fix},
		"not there": {fix, fix},
		"paraphrased: left alone": {
			"The dependency check says lodash needs 4.18.0.\n\n" + fix,
			"The dependency check says lodash needs 4.18.0.\n\n" + fix},
		"only part of it: left alone": {
			"> 🛡️ LeoPrevent · dependency check (1 package) · package-lock.json\n\n" + fix,
			"> 🛡️ LeoPrevent · dependency check (1 package) · package-lock.json\n\n" + fix},
	}
	for name, c := range cases {
		if got := WithoutRelayed(c.reply, md); got != c.want {
			t.Errorf("%s:\ngot  %q\nwant %q", name, got, c.want)
		}
	}
	if got := WithoutRelayed(fix, ""); got != fix {
		t.Error("nothing relayed: the reply is untouched")
	}
}
