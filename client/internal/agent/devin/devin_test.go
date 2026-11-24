package devin

import (
	"encoding/json"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/agent"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

func TestLifecycleAndBlockingDialect(
	t *testing.T,
) {
	t.Setenv("DEVIN_PROJECT_DIR", t.TempDir())
	a := New()
	ev, err := a.ParseEvent([]byte(`{"hook_event_name":"UserPromptSubmit","session_id":"session","prompt_id":"turn"}`))
	if err != nil || !ev.IsUserPromptSubmit() || ev.Cwd == "" || ev.PromptID != "turn" {
		t.Fatalf("event=%+v err=%v", ev, err)
	}
	ev, err = a.ParseEvent([]byte(`{"hook_event_name":"PreToolUse","tool_input":{"file_path":"src/app.py"}}`))
	if err != nil || !ev.IsPreToolUse() || len(ev.EditPaths) != 1 {
		t.Fatalf("event=%+v err=%v", ev, err)
	}
	ev, err = a.ParseEvent([]byte(`{"hook_event_name":"Stop","stop_hook_active":true}`))
	if err != nil || !ev.StopHookActive {
		t.Fatalf("guard=%+v err=%v", ev, err)
	}
	if _, err := a.ParseEvent([]byte(`{"hook_event_name":"SessionEnd"}`)); err == nil {
		t.Fatal("unknown event reached Stop")
	}
	out, err := a.DeliverReview("repair", "review", 1, nil, "")
	var payload map[string]any
	if err != nil || json.Unmarshal(out, &payload) != nil || payload["decision"] != "block" || payload["reason"] != "repair" {
		t.Fatalf("output=%s err=%v", out, err)
	}
	out, err = a.DeliverNotice("unreviewed")
	var notice map[string]any
	if err != nil || json.Unmarshal(out, &notice) != nil {
		t.Fatal(err)
	}
	if notice["decision"] != nil {
		t.Fatal("notice blocks")
	}
}

func TestEnvironmentNamesTheVerifiedLocalRuntime(
	t *testing.T,
) {
	if got := New().Environment(agent.Event{}).Name; got != wire.EnvDevinCLI {
		t.Fatalf("environment=%q", got)
	}
}
