package engine

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/agent/claude"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/config"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/review"
)

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "leoprevent-engine-test")
	if err != nil {
		os.Exit(1)
	}
	config.SetUserConfigDirForTest(dir)
	_ = os.Unsetenv("CLAUDE_CODE_REMOTE")
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func cleanTurn(t *testing.T, r *fakeReviewer, session string) (int, string) {
	t.Helper()
	tp := writeTranscript(t,
		`{"type":"user","message":{"role":"user","content":"add a route"}}`,
		`{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","name":"Write","input":{"file_path":"/p/app.py","content":"x = 1"}}]}}`,
	)
	stdin := fmt.Sprintf(`{"stop_hook_active":false,"session_id":%q,"transcript_path":%q,"cwd":""}`, session, tp)
	code, stdout, _ := runWith(claude.New(), r, stdin)
	return code, stdout
}

func withLicense(t *testing.T, key string) {
	t.Helper()
	old := licenseKey
	licenseKey = func() string { return key }
	t.Cleanup(func() { licenseKey = old })
}

func TestFirstCleanReviewShowsNoticeOnceAcrossSessions(t *testing.T) {
	restore := config.SetUserConfigDirForTest(t.TempDir())
	t.Cleanup(restore)
	t.Setenv("CLAUDE_CODE_ENTRYPOINT", "cli")

	_, first := cleanTurn(t, &fakeReviewer{}, "fc-a")
	if !strings.Contains(first, review.FirstCleanNotice()) || strings.Contains(first, `"decision"`) {
		t.Fatalf("first clean turn must show a non-blocking notice, got %q", first)
	}
	if _, again := cleanTurn(t, &fakeReviewer{}, "fc-a"); again != "" {
		t.Errorf("same session must stay silent, got %q", again)
	}
	if _, other := cleanTurn(t, &fakeReviewer{}, "fc-b"); other != "" {
		t.Errorf("a new session must stay silent, got %q", other)
	}
}

func TestBlockedTurnDoesNotSpendTheFirstCleanNotice(t *testing.T) {
	restore := config.SetUserConfigDirForTest(t.TempDir())
	t.Cleanup(restore)

	_, blocked := cleanTurn(t, &fakeReviewer{prompt: "FIX THIS"}, "fc-blocked")
	if strings.Contains(blocked, review.FirstCleanNotice()) {
		t.Fatalf("a blocked turn must not carry the clean notice, got %q", blocked)
	}
	if _, clean := cleanTurn(t, &fakeReviewer{}, "fc-after"); !strings.Contains(clean, review.FirstCleanNotice()) {
		t.Errorf("the first clean turn after a block must still show it, got %q", clean)
	}
}

func TestFirstCleanNoticeIsPerLicence(t *testing.T) {
	restore := config.SetUserConfigDirForTest(t.TempDir())
	t.Cleanup(restore)

	withLicense(t, "lp_live_a")
	if _, out := cleanTurn(t, &fakeReviewer{}, "fc-l1"); !strings.Contains(out, review.FirstCleanNotice()) {
		t.Fatalf("licence A's first clean turn must show it, got %q", out)
	}
	if _, out := cleanTurn(t, &fakeReviewer{}, "fc-l2"); out != "" {
		t.Errorf("licence A must not see it twice, got %q", out)
	}
	withLicense(t, "lp_live_b")
	if _, out := cleanTurn(t, &fakeReviewer{}, "fc-l3"); !strings.Contains(out, review.FirstCleanNotice()) {
		t.Errorf("licence B on the same machine must see it once, got %q", out)
	}
}

func TestFirstCleanReviewIsRelayedByTheAgentOutsideTheTerminal(t *testing.T) {
	// Arrange
	restore := config.SetUserConfigDirForTest(t.TempDir())
	t.Cleanup(restore)
	t.Setenv("CLAUDE_CODE_ENTRYPOINT", "claude-desktop")

	// Act
	_, first := cleanTurn(t, &fakeReviewer{}, "fc-desktop")
	_, again := cleanTurn(t, &fakeReviewer{}, "fc-desktop-2")

	// Assert
	if !strings.Contains(first, `"decision":"block"`) || !strings.Contains(first, "automated security review") {
		t.Fatalf("the desktop app hides a systemMessage, so the first clean turn must re-wake the agent to say it, got %q", first)
	}
	if again != "" {
		t.Errorf("the relay is one-time, got %q on a later clean turn", again)
	}
}

func TestFirstCleanNoticeIsSkippedInCloudSessions(t *testing.T) {
	for _, tc := range []struct {
		name       string
		remote     string
		entrypoint string
	}{
		{name: "remote flag", remote: "true", entrypoint: "cli"},
		{name: "remote entrypoint", remote: "", entrypoint: "remote"},
		{name: "remote desktop entrypoint", remote: "", entrypoint: "remote_desktop"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Arrange
			restore := config.SetUserConfigDirForTest(t.TempDir())
			t.Cleanup(restore)
			t.Setenv("CLAUDE_CODE_REMOTE", tc.remote)
			t.Setenv("CLAUDE_CODE_ENTRYPOINT", tc.entrypoint)

			// Act
			_, out := cleanTurn(t, &fakeReviewer{}, "fc-cloud-"+tc.entrypoint)

			// Assert
			if out != "" {
				t.Errorf("a cloud sandbox forgets the marker every session, so the notice must stay silent, got %q", out)
			}
		})
	}
}
