package cursor

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/agent"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
	"time"
)

func TestFollowupPreservesBaselineAndGuardsOnlyItsReply(
	t *testing.T,
) {
	session := t.Name() + t.TempDir()
	payload := func(name, prompt string) []byte {
		data, _ := json.Marshal(map[string]any{"hook_event_name": name, "conversation_id": session, "workspace_roots": []string{t.TempDir()}, "prompt": prompt, "status": "completed"})
		return data
	}
	a := New()
	ev, err := a.ParseEvent(payload("beforeSubmitPrompt", "add code"))
	if err != nil || !ev.IsUserPromptSubmit() || ev.Cwd == "" || ev.ReviewContinuation {
		t.Fatalf("event=%+v err=%v", ev, err)
	}
	out, err := a.DeliverReview("repair", "review", 1, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(continuationPath(session)) })
	var review map[string]string
	if err := json.Unmarshal(out, &review); err != nil {
		t.Fatal(err)
	}
	if review["followup_message"] == "" || review["decision"] != "" {
		t.Fatalf("review=%s", out)
	}
	a = New()
	ev, err = a.ParseEvent(payload("beforeSubmitPrompt", review["followup_message"]))
	if err != nil || !ev.ReviewContinuation {
		t.Fatalf("followup=%+v err=%v", ev, err)
	}
	ev, err = New().ParseEvent(payload("preToolUse", ""))
	if err != nil || !ev.IsPreToolUse() {
		t.Fatalf("tool=%+v err=%v", ev, err)
	}
	ev, err = New().ParseEvent(payload("stop", ""))
	if err != nil || !ev.StopHookActive {
		t.Fatalf("guard=%+v err=%v", ev, err)
	}
	ev, err = New().ParseEvent(payload("stop", ""))
	if err != nil || ev.StopHookActive {
		t.Fatalf("spent guard=%+v err=%v", ev, err)
	}
	_, _ = a.DeliverReview("repair", "review", 1, nil, "")
	ev, err = New().ParseEvent(payload("beforeSubmitPrompt", "new developer prompt"))
	if err != nil || ev.ReviewContinuation {
		t.Fatalf("new prompt=%+v err=%v", ev, err)
	}
	ev, _ = New().ParseEvent(payload("stop", ""))
	if ev.StopHookActive {
		t.Fatal("new prompt inherited guard")
	}
}

func TestRejectsUnknownAndFailedEvents(
	t *testing.T,
) {
	for _, payload := range []string{`{`, `{"hook_event_name":"afterFileEdit"}`, `{"hook_event_name":"stop","status":"error"}`, `{"hook_event_name":"stop","status":"aborted"}`} {
		if _, err := New().ParseEvent([]byte(payload)); err == nil {
			t.Fatalf("accepted %s", payload)
		}
	}
	a := New()
	if _, err := a.DeliverReview("repair", "", 0, nil, ""); err == nil {
		t.Fatal("missing session accepted")
	}
	out, _ := a.DeliverNotice("skip")
	if string(out) != "{}" {
		t.Fatalf("unsupported stop output=%s", out)
	}
	out, _ = a.DeliverPromptNotice("skip", "context")
	var notice map[string]any
	_ = json.Unmarshal(out, &notice)
	if notice["continue"] != true || notice["followup_message"] != nil {
		t.Fatalf("notice=%s", out)
	}
}

func TestContinuationExpires(
	t *testing.T,
) {
	session := t.Name() + t.TempDir()
	a := &Adapter{sessionID: session}
	if _, err := a.DeliverReview("repair", "", 0, nil, ""); err != nil {
		t.Fatal(err)
	}
	path := continuationPath(session)
	t.Cleanup(func() { _ = os.Remove(path) })
	data, _ := json.Marshal(continuation{Digest: digest("repair"), At: time.Now().Add(-7 * time.Hour)})
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, ok := readContinuation(session); ok {
		t.Fatal("expired guard accepted")
	}
}

func TestEnvironmentNamesTheVerifiedLocalRuntime(
	t *testing.T,
) {
	if got := New().Environment(agent.Event{}).Name; got != wire.EnvCursorIDE {
		t.Fatalf("environment=%q", got)
	}
}

func TestWindowsWorkspaceRootBecomesADrivePath(
	t *testing.T,
) {
	for in, want := range map[string]string{
		"/e:/development/app": filepath.Clean("e:/development/app"),
		"/C:":                 filepath.Clean("C:/"),
		"/src/app":            "/src/app",
		"/1:/app":             "/1:/app",
		`e:\development\app`:  `e:\development\app`,
	} {
		data, _ := json.Marshal(map[string]any{"hook_event_name": "stop", "status": "completed", "workspace_roots": []string{in}})
		ev, err := New().ParseEvent(data)
		if err != nil || ev.Cwd != want {
			t.Fatalf("%q: cwd=%q want %q err=%v", in, ev.Cwd, want, err)
		}
	}
}

func TestTheReplyToAFollowUpIsRecordedForTheFixCheck(
	t *testing.T,
) {
	// Arrange
	session := t.Name() + t.TempDir()
	payload := func(name, text string) []byte {
		data, _ := json.Marshal(map[string]any{"hook_event_name": name, "conversation_id": session, "workspace_roots": []string{t.TempDir()}, "text": text, "status": "completed"})
		return data
	}
	a := New()
	_, _ = a.ParseEvent(payload("afterAgentResponse", "Added the endpoint."))
	if _, err := a.DeliverReview("repair", "review", 1, nil, ""); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(continuationPath(session)); _ = os.Remove(replyPath(session)) })

	// Act
	ev, err := New().ParseEvent(payload("afterAgentResponse", "That value is a test fixture, so I left it."))
	stop, _ := New().ParseEvent(payload("stop", ""))
	reply, replyErr := New().AgentReply(stop)

	// Assert
	if err != nil || !ev.IsAgentResponse() {
		t.Fatalf("event=%+v err=%v", ev, err)
	}
	if replyErr != nil || reply != "That value is a test fixture, so I left it." {
		t.Fatalf("reply=%q err=%v", reply, replyErr)
	}
}
