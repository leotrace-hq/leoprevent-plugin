package review

import (
	"strings"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

var (
	preexisting = wire.Finding{
		Rule: "sql-injection", Name: "SQL Injection", Location: "legacy/db.py:88",
		Issue: "query built by concatenation", Fix: "use a parameterised query",
		Preexisting: true,
	}
	introduced = wire.Finding{
		Rule: "ssrf", Name: "Server-Side Request Forgery", Location: "app/fetch.py:12",
		Issue: "user-controlled URL", Fix: "resolve and allowlist the host",
	}
	suggestOnlyPre = wire.Finding{
		Rule: "proxy-path-handling", Name: "Proxy Path Handling", Location: "nginx.conf:31",
		Issue: "path passed through unnormalised", Fix: "normalise before proxy_pass",
		Preexisting: true, SuggestOnly: true,
	}
)

// promptNoDirective is BuildFindingsPrompt with NO paragraph from the server — the ordinary
// case (the policy is off, or the server predates the field), and the shape every test
// written before LEO-171 asserts against.
func promptNoDirective(fs []wire.Finding) string { return BuildFindingsPrompt(fs, "") }

// serverText stands in for whatever paragraph the server sends. It is a FIXTURE, not a copy
// of the real one: the real text is server-side (api.PreexistingRemediationDirective) and
// its wording properties are asserted there, where a deploy can change them. The plugin
// module cannot import the server module anyway — the dependency points one way, which is
// what keeps the published client compiling on its own.
//
// What these tests own is that the client renders whatever it is handed, in the right
// group, and that nothing else about its behaviour moves when the text does.
const serverText = "SERVER-SUPPLIED-PARAGRAPH: fix these existing flaws as part of this change:"

// theClientsOwnWording is the paragraph this binary ships. It is the conservative
// report-it-to-the-developer text, and it is the ONLY wording the client holds.
const theClientsOwnWording = "Pre-existing issues NOT introduced by your change this turn. Do NOT edit these pre-existing lines."

// TestNoServerParagraphIsTodaysBehaviour: THE DEFAULT, and the assertion that has to hold
// for the rollout to be a no-op. With nothing from the server the prompt is what it has
// always been.
func TestNoServerParagraphIsTodaysBehaviour(t *testing.T) {
	got := promptNoDirective([]wire.Finding{preexisting})
	if !strings.Contains(got, theClientsOwnWording) {
		t.Fatalf("with no server paragraph the client's own wording must render verbatim.\ngot:\n%s", got)
	}
}

// TestServerParagraphReplacesTheClientsOwn: the mechanism. The server's text is rendered
// and the client's default is NOT also emitted — the two are contradictory ("fix these" vs
// "do NOT edit these"), so a prompt carrying both would be worse than either.
func TestServerParagraphReplacesTheClientsOwn(t *testing.T) {
	got := BuildFindingsPrompt([]wire.Finding{preexisting}, serverText)
	if !strings.Contains(got, serverText) {
		t.Fatalf("the server's paragraph must be rendered.\ngot:\n%s", got)
	}
	if strings.Contains(got, theClientsOwnWording) {
		t.Errorf("the client's own wording must NOT also appear.\ngot:\n%s", got)
	}
	for _, want := range []string{"legacy/db.py:88", "use a parameterised query"} {
		if !strings.Contains(got, want) {
			t.Errorf("prompt is missing %q.\ngot:\n%s", want, got)
		}
	}
}

// TestServerParagraphIsRenderedVerbatim: the point of putting it on the wire. The client
// must not paraphrase, re-case, wrap or truncate it, or a server-side reword would arrive
// altered and the deploy would not mean what it said.
func TestServerParagraphIsRenderedVerbatim(t *testing.T) {
	weird := "Fix these. Mind the ' quote, the \"double\", the 50% and the (parens)."
	got := BuildFindingsPrompt([]wire.Finding{preexisting}, weird)
	if !strings.Contains(got, weird) {
		t.Fatalf("the server's paragraph must be rendered verbatim.\ngot:\n%s", got)
	}
}

// TestTheClientNeverBranchesOnTheServersParagraph: ⚠️ THE CONSTRAINT THIS DESIGN EXISTS
// FOR. The client must not know that a second policy exists, so NOTHING about its behaviour
// may move when the paragraph does — not the grouping, not the count that feeds the
// developer's notice, not the header. Only the paragraph itself differs.
//
// Fails against the earlier design, which carried a per-finding flag and counted the group
// separately: that put a copy of a server-side policy in every install, to be updated in
// step, and surfaced the difference in the developer's own notice.
func TestTheClientNeverBranchesOnTheServersParagraph(t *testing.T) {
	fs := []wire.Finding{introduced, preexisting, suggestOnlyPre}
	off := promptNoDirective(fs)
	on := BuildFindingsPrompt(fs, serverText)

	// Identical but for the one paragraph.
	if normalised := strings.Replace(on, serverText, theClientsOwnWording, 1); !strings.HasPrefix(normalised, strings.Split(off, theClientsOwnWording)[0]) {
		t.Errorf("everything before the pre-existing paragraph must be identical.\noff:\n%s\non:\n%s", off, on)
	}
	// The developer-facing notice must be the same sentence either way.
	if a, b := ForceFixedCount(fs), ForceFixedCount(fs); a != b || a != 1 {
		t.Fatalf("ForceFixedCount = %d, want 1 (the introduced finding only)", a)
	}
	if ReviewContextMessage(3, fs, ForceFixedCount(fs)) == "" {
		t.Fatal("notice should render")
	}
	// And the header must not change.
	if strings.SplitN(off, "\n", 2)[0] != strings.SplitN(on, "\n", 2)[0] {
		t.Errorf("the header must not depend on the server's paragraph.\noff: %q\non:  %q",
			strings.SplitN(off, "\n", 2)[0], strings.SplitN(on, "\n", 2)[0])
	}
}

// TestForceFixedCountIgnoresPreexistingEntirely: the developer-facing notice must read the
// same whichever policy is in force, because the client cannot know which it is. Counting
// pre-existing findings here would require the policy compiled into the client.
func TestForceFixedCountIgnoresPreexistingEntirely(t *testing.T) {
	if got := ForceFixedCount([]wire.Finding{preexisting}); got != 0 {
		t.Errorf("ForceFixedCount = %d, want 0 — a pre-existing finding never counts here", got)
	}
	if got := ForceFixedCount([]wire.Finding{suggestOnlyPre}); got != 0 {
		t.Errorf("ForceFixedCount = %d, want 0 for suggest-only", got)
	}
	if got := ForceFixedCount([]wire.Finding{introduced}); got != 1 {
		t.Errorf("ForceFixedCount = %d, want 1 for an introduced finding", got)
	}
}

// TestSuggestOnlyIsNeverReachedByTheServersParagraph: `auto_fix:false` is a property of the
// FIX (high regression risk), not of who wrote the code. It is a separate group on the
// client, so the server's paragraph can never apply to it — which is why the wire needs no
// exclusion flag for it.
func TestSuggestOnlyIsNeverReachedByTheServersParagraph(t *testing.T) {
	got := BuildFindingsPrompt([]wire.Finding{suggestOnlyPre}, serverText)
	if strings.Contains(got, serverText) {
		t.Fatalf("a suggest-only finding must not be introduced by the server's paragraph.\ngot:\n%s", got)
	}
	if !strings.Contains(got, "for the developer to decide on") {
		t.Errorf("a suggest-only finding keeps its own paragraph.\ngot:\n%s", got)
	}
}

// TestNoCopyClaimsLeoPreventEditsCode: ⚠️ LeoPrevent never applies anything — every edit in
// every group is the agent's. It has exactly two things it can say about a finding: fix it
// now, or tell the developer about it. Copy implying a third actor teaches the agent the
// wrong model of who acts and misleads the developer reading the same line.
//
// Fails against the previous suggest-only wording, "LeoPrevent does NOT auto-apply it".
func TestNoCopyClaimsLeoPreventEditsCode(t *testing.T) {
	all := []wire.Finding{introduced, preexisting, suggestOnlyPre}
	for _, prompt := range []string{promptNoDirective(all), BuildFindingsPrompt(all, serverText)} {
		for _, banned := range []string{
			"LeoPrevent does NOT auto-apply",
			"LeoPrevent does not auto-apply",
			"nothing to auto-fix",
		} {
			if strings.Contains(prompt, banned) {
				t.Errorf("copy must not imply LeoPrevent edits code; found %q.\ngot:\n%s", banned, prompt)
			}
		}
	}
}

// TestMixedFindingsKeepThreeSeparateGroups: the realistic turn. Each class gets its own
// instruction and no finding appears under another's, because the instructions contradict
// each other: one says fix it now, one says the developer decides, one says whatever the
// server sent.
func TestMixedFindingsKeepThreeSeparateGroups(t *testing.T) {
	other := preexisting
	other.Location = "legacy/other.py:5"
	got := BuildFindingsPrompt([]wire.Finding{introduced, preexisting, suggestOnlyPre, other}, serverText)

	for _, loc := range []string{"app/fetch.py:12", "legacy/db.py:88", "nginx.conf:31", "legacy/other.py:5"} {
		if n := strings.Count(got, loc); n != 1 {
			t.Errorf("location %s appears %d times, want 1.\ngot:\n%s", loc, n, got)
		}
	}
	for _, instruction := range []string{
		"Apply each directly, don't ask",
		"for the developer to decide on",
		serverText,
	} {
		if n := strings.Count(got, instruction); n != 1 {
			t.Errorf("instruction %q appears %d times, want 1.\ngot:\n%s", instruction, n, got)
		}
	}
	// Both pre-existing findings are under the ONE server paragraph, in order.
	if a, b := strings.Index(got, serverText), strings.Index(got, "legacy/other.py:5"); a < 0 || b < a {
		t.Errorf("both pre-existing findings must sit under the server's paragraph.\ngot:\n%s", got)
	}
}

// TestServerParagraphOnlyPromptKeepsTheRewakeMarker: a turn whose own change is clean, whose
// only items are pre-existing, still has to re-wake. The first line carries the marker Codex
// matches its own re-wake on (transcript.reWakeMarker), so losing it there would make the
// agent read our instruction as a new user request.
func TestServerParagraphOnlyPromptKeepsTheRewakeMarker(t *testing.T) {
	got := BuildFindingsPrompt([]wire.Finding{preexisting}, serverText)
	if !strings.HasPrefix(got, "🔒 LeoPrevent: security review") {
		t.Fatalf("must keep the re-wake marker prefix.\ngot:\n%s", got)
	}
}

// TestHeaderClaimsNeitherDispositionNorProvenance: ⚠️ FOUND BY A LIVE DEV RUN
// (0.2.23-dev.85be7e3). Two versions of the no-force-fix header have now been wrong, in
// opposite ways, and this pins against both.
//
//   - "nothing to auto-fix" implied LeoPrevent applies fixes, and prejudged a server-side
//     decision the client cannot see — it flatly contradicts a server paragraph asking for
//     a fix.
//   - "nothing to fix in the code you changed" traded that for a PROVENANCE claim, which
//     the live run falsified at once: a brand-new file's helper fired an auto_fix:false
//     rule, so the finding was introduced, landed in the suggest-only group (which the flag
//     outranks the class for), and the header announced there was nothing wrong with code
//     the agent had just written.
//
// Both facts are unsafe to assert from here, so the header asserts neither and each group's
// own paragraph disposes.
func TestHeaderClaimsNeitherDispositionNorProvenance(t *testing.T) {
	// The live shape: introduced (new file) AND suggest-only.
	introducedSuggestOnly := wire.Finding{
		Rule: "no-input-validation", Name: "Missing Input / External-Data Validation",
		Location: "scratch.ts:2", Issue: "url passed straight to fetch", Fix: "allowlist the host",
		SuggestOnly: true,
	}
	for _, fs := range [][]wire.Finding{
		{introducedSuggestOnly},
		{preexisting},
		{suggestOnlyPre},
	} {
		for _, prompt := range []string{promptNoDirective(fs), BuildFindingsPrompt(fs, serverText)} {
			header := strings.SplitN(prompt, "\n", 2)[0]
			if !strings.HasPrefix(header, "🔒 LeoPrevent: security review") {
				t.Fatalf("header must keep the re-wake marker: %q", header)
			}
			for _, banned := range []string{
				"nothing to auto-fix",                    // disposition, and implies we apply fixes
				"nothing to fix in the code you changed", // provenance, falsified live
				"your change itself is clean",            // same provenance claim, older wording
			} {
				if strings.Contains(header, banned) {
					t.Errorf("header asserts something it cannot know (%q): %q", banned, header)
				}
			}
		}
	}
}

// TestSuggestOnlyCopyDoesNotBlameProxyConfig: the parenthetical "(e.g. reverse-proxy /
// web-server config)" was written when auto_fix:false was assumed to mean proxy rules. It
// does not — `no-input-validation` carries the flag too — and a live run put an app-level
// SSRF finding under it. The AGENT spotted the mismatch and said so in its reply, which is
// a good catch and a bad sign: copy that argues with its own finding costs the finding its
// credibility.
func TestSuggestOnlyCopyDoesNotBlameProxyConfig(t *testing.T) {
	got := promptNoDirective([]wire.Finding{suggestOnlyPre})
	for _, banned := range []string{"reverse-proxy", "web-server config", "shared config"} {
		if strings.Contains(got, banned) {
			t.Errorf("suggest-only copy must not name proxy config as the reason; found %q.\ngot:\n%s", banned, got)
		}
	}
	// The real shared reason, and the prohibition matching the local tier's wording.
	if !strings.Contains(got, "high risk of breaking existing behaviour") {
		t.Errorf("suggest-only copy must state the actual reason.\ngot:\n%s", got)
	}
	if !strings.Contains(got, "do not change this code without their go-ahead") {
		t.Errorf("suggest-only copy must tell the agent to leave the code alone.\ngot:\n%s", got)
	}
}
