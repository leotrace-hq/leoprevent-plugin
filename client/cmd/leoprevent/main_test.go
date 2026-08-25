package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/notify"
)

// runWith drives run() with the given args + stdin, capturing stdout/stderr. It
// points the log at a temp file so the test doesn't write the user's client.log.
func runWith(t *testing.T, args []string, stdin string) (code int, stdout, stderr string) {
	t.Helper()
	t.Setenv("LEOPREVENT_LOG", filepath.Join(t.TempDir(), "client.log"))
	var out, errb bytes.Buffer
	code = run(args, strings.NewReader(stdin), &out, &errb)
	return code, out.String(), errb.String()
}

// run ALWAYS returns 0 (fail-open). These pin the routing glue main() can't test.

func TestRunUnknownFlagFailsOpen(t *testing.T) {
	code, stdout, stderr := runWith(t, []string{"--bogus-flag"}, "")
	if code != 0 || stdout != "" {
		t.Errorf("unknown flag must fail open silently on stdout, got code=%d stdout=%q", code, stdout)
	}
	if !strings.Contains(stderr, "failing open") {
		t.Errorf("expected a fail-open notice on stderr, got %q", stderr)
	}
}

func TestRunMissingAgentFailsOpen(t *testing.T) {
	code, stdout, stderr := runWith(t, nil, `{"hook_event_name":"Stop"}`)
	if code != 0 || stdout != "" {
		t.Errorf("missing --agent must fail open, got code=%d stdout=%q", code, stdout)
	}
	if !strings.Contains(stderr, "--agent") {
		t.Errorf("stderr should name the --agent requirement, got %q", stderr)
	}
}

func TestRunUserPromptSubmitCapturesSilently(t *testing.T) {
	// cwd empty → vcs.CaptureBaseline is a no-op; the route must still exit silent.
	code, stdout, stderr := runWith(t, []string{"--agent=claude"},
		`{"hook_event_name":"UserPromptSubmit","session_id":"s1","cwd":""}`)
	if code != 0 || stdout != "" || stderr != "" {
		t.Errorf("UserPromptSubmit must be fully silent, got code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestRunStopWithoutConfigFailsOpen(t *testing.T) {
	// A Stop event routes past UserPromptSubmit to config.Load, which fails (no
	// leoprevent.json next to the test binary) → fail open. This proves the Stop
	// branch is reached. It must STILL fail open (exit 0, no block), but a
	// misconfigured client silently disabling every review is exactly the
	// silent-skip BUG-2 closes, so it now also surfaces a NON-BLOCKING notice
	// (systemMessage only, no "decision") so the dev knows the turn went unreviewed.
	// The skip notice is throttled once-per-session-per-reason via a persistent temp
	// marker; clear it so a rerun isn't silently suppressed (test isolation).
	notify.Clear("s-cfg")
	t.Cleanup(func() { notify.Clear("s-cfg") })
	code, stdout, stderr := runWith(t, []string{"--agent=claude"},
		`{"hook_event_name":"Stop","session_id":"s-cfg","stop_hook_active":false}`)
	if code != 0 {
		t.Errorf("Stop without config must fail open (exit 0), got code=%d", code)
	}
	if !strings.Contains(stderr, "failing open") {
		t.Errorf("expected config fail-open on stderr, got %q", stderr)
	}
	// Non-blocking notice: a systemMessage that names the miss, and NEVER a block.
	if !strings.Contains(stdout, "systemMessage") || !strings.Contains(stdout, "NOT reviewed") {
		t.Errorf("expected a misconfigured skip notice on stdout, got %q", stdout)
	}
	if strings.Contains(stdout, "decision") {
		t.Errorf("notice must be NON-BLOCKING (no decision field), got %q", stdout)
	}
}

func TestNewAgentDispatch(t *testing.T) {
	cases := []struct {
		name string
		want string // adapter Name(), or "" if nil
	}{
		{"claude", "claude"},
		{"codex", "codex"},
		{"", ""},       // no implicit default — explicit --agent required
		{"cursor", ""}, // not built yet → nil
		{"bogus", ""},  // unknown → nil
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := newAgent(tc.name)
			if tc.want == "" {
				if a != nil {
					t.Errorf("newAgent(%q) = %s, want nil", tc.name, a.Name())
				}
				return
			}
			if a == nil || a.Name() != tc.want {
				t.Errorf("newAgent(%q) = %v, want %s", tc.name, a, tc.want)
			}
		})
	}
}

// TestPreToolUseNeverReachesReview is the guard on the sharpest failure this event can
// cause, and it is not a missed baseline.
//
// Everything that is not UserPromptSubmit falls through to the review path, and the
// manifests now register PreToolUse on every write tool. So a PreToolUse that is not
// routed away runs a selector, a judge and a possible BLOCK on EVERY file the agent
// edits, mid-turn — the PreToolUse hard gate the non-negotiables forbid, arrived at by
// accident.
//
// Asserted as SILENCE, which is exactly what TestRunStopWithoutConfigFailsOpen shows the
// Stop branch does NOT produce: reaching config.Load with no leoprevent.json emits a
// misconfigured notice on stdout. Empty stdout therefore proves the Stop branch was never
// entered. Every session id is unique because that notice is throttled once per session
// per reason, and a shared id would let the throttle hide a real regression.
func TestPreToolUseNeverReachesReview(t *testing.T) {
	for _, tc := range []struct{ name, agent, stdin string }{
		{"claude", "--agent=claude",
			`{"hook_event_name":"PreToolUse","session_id":"ptu-claude","cwd":"/tmp",` +
				`"tool_name":"Write","tool_input":{"file_path":"/tmp/x/app.py"}}`},
		{"codex", "--agent=codex",
			`{"hook_event_name":"PreToolUse","session_id":"ptu-codex","cwd":"/tmp",` +
				`"tool_name":"Write","tool_input":{"file_path":"/tmp/x/app.py"}}`},
		// VS Code speaks the snake_case dialect...
		{"copilot-vscode", "--agent=copilot",
			`{"hook_event_name":"PreToolUse","session_id":"ptu-cop-vs","cwd":"/tmp",` +
				`"tool_name":"Write","tool_input":{"file_path":"/tmp/x/app.py"}}`},
		// ...the CLI camelCase, with its own spelling of the event.
		{"copilot-cli", "--agent=copilot",
			`{"hookEventName":"preToolUse","sessionId":"ptu-cop-cli","cwd":"/tmp",` +
				`"toolName":"Write","toolInput":{"filePath":"/tmp/x/app.py"}}`},
		// And the CLI documents no event-name field at all, so a payload carrying only
		// a tool must still be inferred as PreToolUse rather than read as a Stop.
		{"copilot-cli-inferred", "--agent=copilot",
			`{"sessionId":"ptu-cop-inf","cwd":"/tmp",` +
				`"toolName":"Edit","toolInput":{"filePath":"/tmp/x/app.py"}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := runWith(t, []string{tc.agent}, tc.stdin)
			if code != 0 {
				t.Errorf("must exit 0, got %d", code)
			}
			if stdout != "" {
				t.Errorf("PreToolUse reached the review path: it must decide nothing and "+
					"print nothing, got stdout=%q", stdout)
			}
			if stderr != "" {
				t.Errorf("PreToolUse must be silent, got stderr=%q", stderr)
			}
		})
	}
}
