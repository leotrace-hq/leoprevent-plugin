package claude

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/review"
)

const notice = "🛡️ LeoPrevent · dependency check (1 package) · package-lock.json\nlodash 4.17.15 has 1 high vulnerability. The advisories name 4.18.0 as the fix."

func relay(t *testing.T, surface, out string) (map[string]any, string) {
	t.Helper()
	t.Setenv(entrypointEnv, surface)
	t.Cleanup(review.SetNonceForTest("test0nce"))
	got, dictated, err := New().RelayForDeveloper([]byte(out), notice, "", "")
	if err != nil {
		t.Fatal(err)
	}
	var hook map[string]any
	if err := json.Unmarshal(got, &hook); err != nil {
		t.Fatalf("not JSON: %s", got)
	}
	return hook, dictated
}

// The terminal shows a systemMessage, so the notice joins it and the agent is never asked.
func TestRelayInTheTerminalIsASystemMessage(t *testing.T) {
	hook, dictated := relay(t, "cli", "")
	if hook["systemMessage"] != notice || hook["decision"] != nil || dictated != "" {
		t.Errorf("nothing else: %v, %q", hook, dictated)
	}
	hook, dictated = relay(t, "cli", `{"decision":"block","reason":"FIX THESE","systemMessage":"🛡️ LeoPrevent · security review (1 file)"}`)
	if hook["reason"] != "FIX THESE" || hook["systemMessage"] != "🛡️ LeoPrevent · security review (1 file)\n\n"+notice || dictated != "" {
		t.Errorf("with a review wake: %v", hook)
	}
}

// The desktop app doesn't show a systemMessage, so the agent prints the notice: on its own a
// print-and-stop wake; with the first-clean relay, one reply; with a review wake, the review's
// instructions kept and an addendum; with a plain notice, that notice kept and a wake added.
func TestRelayInTheDesktopAppAsksTheAgentToPrintIt(t *testing.T) {
	md := review.DeveloperMarkdown(notice)

	hook, dictated := relay(t, "claude-desktop", "")
	if hook["decision"] != "block" || hook["reason"] != review.DeveloperRelayPrompt(md) || dictated != md || hook["systemMessage"] != notice {
		t.Errorf("nothing else: %v", hook)
	}

	fc, _ := json.Marshal(map[string]string{"decision": "block", "reason": review.FirstCleanRelayPrompt(), "systemMessage": "first clean"})
	hook, _ = relay(t, "claude-desktop", string(fc))
	if hook["reason"] != review.WithFirstClean(review.FirstCleanRelayPrompt(), md) || strings.Count(hook["reason"].(string), "End your reply with exactly") != 1 {
		t.Errorf("with the first-clean relay, one reply: %v", hook["reason"])
	}

	wake := `{"decision":"block","reason":"FIX THESE FINDINGS","systemMessage":"banner","hookSpecificOutput":{"hookEventName":"Stop","additionalContext":"Begin your reply with exactly this markdown..."}}`
	hook, dictated = relay(t, "claude-desktop", wake)
	reason := hook["reason"].(string)
	if !strings.HasPrefix(reason, "FIX THESE FINDINGS\n\n") || !strings.HasSuffix(reason, review.DeveloperAddendum(md)) || dictated != md {
		t.Errorf("with a review wake: %q", reason)
	}
	if ctx := hook["hookSpecificOutput"].(map[string]any)["additionalContext"]; ctx != "Begin your reply with exactly this markdown..." {
		t.Errorf("the review's own context is untouched: %v", ctx)
	}

	hook, _ = relay(t, "claude-desktop", `{"systemMessage":"⚠️ LeoPrevent · can't reach the security server."}`)
	if hook["decision"] != "block" || hook["reason"] != review.DeveloperRelayPrompt(md) ||
		hook["systemMessage"] != "⚠️ LeoPrevent · can't reach the security server.\n\n"+notice {
		t.Errorf("with a plain notice: %v", hook)
	}
}

// The agent prints the markdown, with its links; the systemMessage keeps the plain text.
func TestTheDesktopAppPrintsTheMarkdown(t *testing.T) {
	t.Setenv(entrypointEnv, "claude-desktop")
	t.Cleanup(review.SetNonceForTest("test0nce"))
	linked := strings.Replace(notice, "1 high vulnerability.", "1 high vulnerability ([GHSA-x](https://osv.dev/vulnerability/GHSA-x)).", 1)
	got, dictated, err := New().RelayForDeveloper(nil, notice, linked, "")
	if err != nil {
		t.Fatal(err)
	}
	var hook map[string]any
	_ = json.Unmarshal(got, &hook)
	md := review.DeveloperMarkdown(linked)
	if dictated != md || hook["reason"] != review.DeveloperRelayPrompt(md) || hook["systemMessage"] != notice {
		t.Errorf("printed %q; hook %v", dictated, hook)
	}
	t.Setenv(entrypointEnv, "cli")
	got, _, _ = New().RelayForDeveloper(nil, notice, linked, "")
	if strings.Contains(string(got), "osv.dev") {
		t.Errorf("the terminal shows the plain text: %s", got)
	}
}
