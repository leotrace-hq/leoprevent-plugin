package engine

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/agent/claude"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/notify"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/outcome"
)

// THE REPOSITORY-CONTEXT REMINDER (LEO-161): the server's sentence rides a block, last, at most
// once per session, and never turns a clean turn into a block.

const hint = "When it suits, let the developer know that connecting GitHub in LeoPrevent would help."

func hintStdin(t *testing.T, session string) string {
	tp := writeTranscript(t,
		`{"type":"user","message":{"role":"user","content":"add a route"}}`,
		`{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","name":"Write","input":{"file_path":"/p/app.py","content":"resp = requests.get(url)"}}]}}`,
	)
	return fmt.Sprintf(`{"stop_hook_active":false,"session_id":%q,"transcript_path":%q,"cwd":""}`, session, tp)
}

func reason(t *testing.T, stdout string) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(stdout), &m); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, stdout)
	}
	r, _ := m["reason"].(string)
	return r
}

func TestContextHintIsAppendedLastToABlockOncePerSession(t *testing.T) {
	session := "engine-context-hint"
	notify.Clear(session)
	t.Cleanup(func() { notify.Clear(session); outcome.Clear(session) })

	r := &fakeReviewer{prompt: "FIX THIS", contextHint: hint, pending: &outcome.Pending{ReviewID: "rid-h"}}
	_, stdout, _ := runWith(claude.New(), r, hintStdin(t, session))
	got := reason(t, stdout)
	if !strings.HasSuffix(strings.TrimSpace(got), hint) {
		t.Fatalf("the hint must be the last thing in the re-wake, got %q", got)
	}
	if !strings.HasPrefix(got, "FIX THIS") {
		t.Errorf("the findings must still lead, got %q", got)
	}

	_, stdout, _ = runWith(claude.New(), r, hintStdin(t, session))
	if strings.Contains(reason(t, stdout), hint) {
		t.Error("the hint must be asked at most once per session")
	}
}

func TestContextHintNeverTurnsACleanTurnIntoABlock(t *testing.T) {
	session := "engine-context-hint-clean"
	notify.Clear(session)
	t.Cleanup(func() { notify.Clear(session) })

	r := &fakeReviewer{prompt: "", contextHint: hint}
	code, stdout, _ := runWith(claude.New(), r, hintStdin(t, session))
	if code != 0 || stdout != "" {
		t.Fatalf("a clean review with a hint must stay silent, got code=%d stdout=%q", code, stdout)
	}
	// And the throttle was not spent on a turn that delivered nothing.
	if !notify.FirstThisSession(session, contextHintKey) {
		t.Error("a clean turn must not use up the once-per-session reminder")
	}
}
