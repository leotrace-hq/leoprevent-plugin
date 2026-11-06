package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/agent"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/agent/codex"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/notify"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/review"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/vcs"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

func codexStop(cwd, session, transcriptPath string) string {
	return fmt.Sprintf(`{"hook_event_name":"Stop","stop_hook_active":false,"session_id":%q,"cwd":%q,"transcript_path":%q}`,
		session, cwd, transcriptPath)
}

// TestCodeModeEditIsReviewedOnTheTranscriptFallback is the LEO-394 turn end to end: no
// git baseline, and Codex edited a file through code mode's tools.apply_patch. The
// fallback used to read nothing and record no_change; the edit now reaches review.
func TestCodeModeEditIsReviewedOnTheTranscriptFallback(t *testing.T) {
	cwd, session := t.TempDir(), "engine-leo394-codemode"
	t.Cleanup(func() { notify.Clear(session) })
	rel := "libs/langchain/langchain/tools/requests_tool.py"
	if err := os.MkdirAll(filepath.Join(cwd, filepath.Dir(rel)), 0o700); err != nil {
		t.Fatal(err)
	}
	body := "import requests\n\ndef fetch(url: str) -> str:\n    resp = requests.get(url, timeout=10, verify=False)\n    return resp.text\n"
	if err := os.WriteFile(filepath.Join(cwd, rel), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	fixture, err := filepath.Abs("../transcript/testdata/rollout-codex-code-mode.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(agent.AllowTranscriptRootForTest(filepath.Dir(fixture)))

	r := &fakeReviewer{}
	code, _, _ := runWith(codex.New(), r, codexStop(cwd, session, fixture))

	if code != 0 || !r.called {
		t.Fatalf("code=%d reviewed=%v: the code-mode edit must be reviewed", code, r.called)
	}
	if len(r.gotChanges) != 1 || r.gotChanges[0].FilePath != rel {
		t.Fatalf("changes = %+v, want %s", r.gotChanges, rel)
	}
}

// TestEditCallsNobodyCouldReadAreReportedNotRecordedAsQuiet: no git baseline, the
// transcript shows an apply_patch call, and the fallback read no change from it. That
// is a failure to see the turn, so it is reported (notice once per session, a distinct
// baseline_skip) instead of passing as no_change.
func TestEditCallsNobodyCouldReadAreReportedNotRecordedAsQuiet(t *testing.T) {
	cwd, session := t.TempDir(), "engine-leo394-unread"
	t.Cleanup(func() { notify.Clear(session) })
	tp := writeTranscript(t,
		`{"type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"fix it"}]}}`,
		`{"type":"response_item","payload":{"type":"custom_tool_call","name":"apply_patch","input":"*** Begin Patch\n*** Frobnicate File: x.py\n*** End Patch"}}`,
	)

	r := &fakeReviewer{}
	code, stdout, _ := runWith(codex.New(), r, codexStop(cwd, session, tp))

	if code != 0 || r.called {
		t.Fatalf("code=%d reviewed=%v: must fail open with nothing to review", code, r.called)
	}
	if got := noticeText(t, stdout); got != review.SkipNotice(review.SkipUnreadEdits) {
		t.Errorf("notice = %q, want the unread-edits notice", got)
	}
	if r.telemetryReason != wire.TelemetryNoChange ||
		r.telemetryMeta.BaselineSkip != string(vcs.SkipNotGitRepo)+"; "+unreadEditsSkip {
		t.Errorf("telemetry reason=%q baseline_skip=%q", r.telemetryReason, r.telemetryMeta.BaselineSkip)
	}

	// Once per session: a second such Stop is recorded but prints nothing.
	if _, stdout, _ := runWith(codex.New(), &fakeReviewer{}, codexStop(cwd, session, tp)); stdout != "" {
		t.Errorf("second notice in one session: %q", stdout)
	}
}

// A codex turn with no edit calls at all stays the silent no_change it always was.
func TestCodexQuestionTurnWithoutGitStaysSilent(t *testing.T) {
	cwd, session := t.TempDir(), "engine-leo394-question"
	t.Cleanup(func() { notify.Clear(session) })
	tp := writeTranscript(t,
		`{"type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"what does apply_patch do?"}]}}`,
	)
	r := &fakeReviewer{}
	code, stdout, _ := runWith(codex.New(), r, codexStop(cwd, session, tp))
	if code != 0 || stdout != "" || strings.Contains(r.telemetryMeta.BaselineSkip, unreadEditsSkip) {
		t.Errorf("code=%d stdout=%q baseline_skip=%q", code, stdout, r.telemetryMeta.BaselineSkip)
	}
}
