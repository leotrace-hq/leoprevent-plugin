package copilot

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestATranscriptOutsideCopilotsRootsIsNeverRead pins LEO-334 for Copilot: a transcript
// path outside VS Code's User dirs and the Copilot CLI's home is dropped in ParseEvent, so
// the post-block reply is not read out of it, even with a block stamped. Fail-open: the
// seams return their empty values, never an error.
func TestATranscriptOutsideCopilotsRootsIsNeverRead(t *testing.T) {
	sid := "outside-" + sanitize(t.Name())
	clearGuard(sid)
	t.Cleanup(func() { clearGuard(sid) })

	a := New()
	if _, err := a.ParseEvent([]byte(`{"sessionId":"` + sid + `","stopReason":"end_turn"}`)); err != nil {
		t.Fatal(err)
	}
	before := time.Now().UTC().Add(-time.Minute)
	if _, err := a.DeliverReview("fix the SSRF", "banner", 1, nil, ""); err != nil {
		t.Fatal(err)
	}
	// copilotTurn writes under a COPILOT_HOME it sets; point the root elsewhere afterwards.
	tp := copilotTurn(t, before, time.Now().UTC().Add(time.Minute))
	t.Setenv("COPILOT_HOME", filepath.Join(t.TempDir(), "copilot"))

	second := New()
	ev, err := second.ParseEvent(stopStdin(t, "camel", sid, tp, false))
	if err != nil {
		t.Fatal(err)
	}
	if ev.TranscriptPath != "" {
		t.Fatalf("a transcript outside the roots was kept: %q", ev.TranscriptPath)
	}
	if got, err := second.AgentReply(ev); err != nil || strings.Contains(got, "false positive") {
		t.Errorf("AgentReply read a rejected transcript: %q, %v", got, err)
	}
	if m, err := second.TurnMeta(ev); err != nil || m.AgentModel != "" {
		t.Errorf("TurnMeta = %+v, %v; want zero meta", m, err)
	}
}
