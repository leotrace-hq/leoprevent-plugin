package hermes

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/agent"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/review"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

func TestShellHookEventsMapOntoTheLifecycle(
	t *testing.T,
) {
	// Arrange
	a := New()
	repo := t.TempDir()
	t.Setenv("HERMES_HOME", t.TempDir())
	t.Setenv("TERMINAL_CWD", "")
	repoJSON, err := json.Marshal(repo)
	if err != nil {
		t.Fatal(err)
	}
	// Windows paths contain backslashes, which must stay escaped in the hook JSON.
	cwd := func(s string) []byte { return []byte(strings.ReplaceAll(s, `"/repo"`, string(repoJSON))) }

	// Act
	prompt, perr := a.ParseEvent(cwd(`{"hook_event_name":"pre_llm_call","tool_name":null,"tool_input":null,"session_id":"s","cwd":"/repo","profile":"default","extra":{"turn_id":"t1","user_message":"add a query","is_first_turn":true}}`))
	tool, terr := a.ParseEvent(cwd(`{"hook_event_name":"pre_tool_call","tool_name":"write_file","tool_input":{"path":"/other/app.py","content":"x"},"session_id":"s","cwd":"/repo","extra":{}}`))
	shell, serr := a.ParseEvent(cwd(`{"hook_event_name":"pre_tool_call","tool_name":"terminal","tool_input":{"command":"cat > /other/db.py <<'EOF'"},"session_id":"s","cwd":"/repo","extra":{}}`))
	stop, verr := a.ParseEvent(cwd(`{"hook_event_name":"pre_verify","session_id":"s","cwd":"/repo","extra":{"attempt":0,"final_response":"Done.","changed_paths":["app.py"]}}`))
	again, aerr := a.ParseEvent(cwd(`{"hook_event_name":"pre_verify","session_id":"s","cwd":"/repo","extra":{"attempt":1,"final_response":"Fixed it."}}`))

	// Assert
	if perr != nil || !prompt.IsUserPromptSubmit() || prompt.PromptID != "t1" || prompt.Cwd != repo || prompt.SessionID != "s" {
		t.Fatalf("pre_llm_call=%+v err=%v", prompt, perr)
	}
	if terr != nil || !tool.IsPreToolUse() || len(tool.EditPaths) != 1 || tool.EditPaths[0] != "/other/app.py" {
		t.Fatalf("pre_tool_call=%+v err=%v", tool, terr)
	}
	if serr != nil || !shell.IsPreToolUse() || len(shell.EditPaths) == 0 {
		t.Fatalf("terminal pre_tool_call=%+v err=%v", shell, serr)
	}
	if verr != nil || stop.Name != "Stop" || stop.StopHookActive || stop.LastAssistantMessage != "Done." {
		t.Fatalf("pre_verify=%+v err=%v", stop, verr)
	}
	if aerr != nil || !again.StopHookActive || again.LastAssistantMessage != "Fixed it." {
		t.Fatalf("re-woken pre_verify=%+v err=%v", again, aerr)
	}
}

func TestUnknownEventNeverReachesStop(
	t *testing.T,
) {
	for _, name := range []string{"post_tool_call", "post_llm_call", "on_session_end", "Stop", "PreToolUse", ""} {
		t.Run(name, func(t *testing.T) {
			// Act
			_, err := New().ParseEvent([]byte(`{"hook_event_name":"` + name + `","session_id":"s"}`))

			// Assert
			if err == nil {
				t.Fatalf("%q was accepted, so it would fall through to a review", name)
			}
		})
	}
}

func TestReviewUsesTheBlockDialectPreVerifyAccepts(
	t *testing.T,
) {
	// Act
	out, err := New().DeliverReview("repair", "review", 1, nil, "")

	// Assert
	var payload map[string]any
	if err != nil || json.Unmarshal(out, &payload) != nil || payload["decision"] != "block" || !strings.HasPrefix(payload["reason"].(string), "repair") {
		t.Fatalf("output=%s err=%v", out, err)
	}
}

func TestReviewAsksHermesToShowTheFindingsNotice(
	t *testing.T,
) {
	// Arrange
	findings := []wire.Finding{{Rule: "sql-injection", Name: "SQL Injection", Location: "app.py:3"}}

	// Act
	out, err := New().DeliverReview("repair", "review", 1, findings, "")

	// Assert
	var payload map[string]any
	if err != nil || json.Unmarshal(out, &payload) != nil {
		t.Fatalf("output=%s err=%v", out, err)
	}
	reason, _ := payload["reason"].(string)
	if !strings.Contains(reason, "🛡️ **LeoPrevent**") || !strings.Contains(reason, "Reviewed 1 changed file") {
		t.Fatalf("the fix instructions never ask Hermes to show the developer the finding: %q", reason)
	}
	if !strings.Contains(reason, "final, user-visible response") {
		t.Fatalf("Hermes can put a pre-repair notice into hidden reasoning: %q", reason)
	}
	if strings.Contains(reason, "\n> ") {
		t.Fatalf("Hermes decorates blockquotes with unwanted quotation marks: %q", reason)
	}
}

func TestDeveloperNoticeUsesParagraphsWithoutChangingRepairInstructions(t *testing.T) {
	out, err := review.RewakeJSON("Repair this quoted source:\n> keep this line", "review")
	if err != nil {
		t.Fatal(err)
	}
	merged, printed, err := New().RelayForDeveloper(out, "dependency notice", "**LeoPrevent**\n\nDependency notice with \"quoted text\".", "")
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]string
	if err := json.Unmarshal(merged, &payload); err != nil {
		t.Fatal(err)
	}
	if printed != "**LeoPrevent**\n\nDependency notice with \"quoted text\"." {
		t.Fatalf("notice text or presentation changed unexpectedly: %q", printed)
	}
	if !strings.Contains(payload["reason"], printed) || !strings.Contains(payload["reason"], "> keep this line") {
		t.Fatalf("notice missing or unrelated repair instructions modified: %q", payload["reason"])
	}
	if got := review.WithoutRelayed(printed+"\n\nFixed the query.", printed); got != "Fixed the query." {
		t.Fatalf("the outcome still includes the relayed notice: %q", got)
	}
}

func TestNoticeNeverContinuesTheTurn(
	t *testing.T,
) {
	// Act
	out, err := New().DeliverNotice("unreviewed")

	// Assert
	var payload map[string]any
	if err != nil || json.Unmarshal(out, &payload) != nil {
		t.Fatalf("output=%s err=%v", out, err)
	}
	if payload["decision"] != nil || payload["action"] != nil {
		t.Fatalf("a notice would keep the agent going: %s", out)
	}
}

func TestPromptNoticeIsInjectedAsContext(
	t *testing.T,
) {
	// Act
	out, err := New().DeliverPromptNotice("terminal line", "> tell the developer\n>\n> a second paragraph")
	empty, eerr := New().DeliverPromptNotice(" ", "")

	// Assert
	var payload map[string]any
	if err != nil || json.Unmarshal(out, &payload) != nil || payload["context"] != "tell the developer\n\na second paragraph" || payload["action"] != nil {
		t.Fatalf("output=%s err=%v", out, err)
	}
	if eerr != nil || empty != nil {
		t.Fatalf("empty notice=%s err=%v", empty, eerr)
	}
}

func TestEnvironmentIsTheHermesRuntime(
	t *testing.T,
) {
	// Act
	got := New().Environment(agent.Event{}).Name

	// Assert
	if got != wire.EnvHermesCLI {
		t.Fatalf("environment=%q", got)
	}
}
