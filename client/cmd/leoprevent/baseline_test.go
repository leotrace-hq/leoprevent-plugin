package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/config"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/update"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/vcs"
)

// baselineRepo makes a temp git repo with one committed file, isolates config and the
// client log, and returns the repo, a unique session id and the log path.
func baselineRepo(t *testing.T) (dir, session, logPath string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir = t.TempDir()
	for _, args := range [][]string{
		{"init", "-q", "-b", "master"},
		{"add", "-A"},
		{"commit", "-q", "-m", "init"},
	} {
		if args[0] == "add" {
			if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte("import os\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	t.Cleanup(config.SetUserConfigDirForTest(t.TempDir()))
	t.Cleanup(update.SetUserConfigDirForTest(t.TempDir()))
	session = strings.ReplaceAll(t.Name(), "/", "_")
	t.Cleanup(func() { vcs.ClearBaseline(dir, session) })
	logPath = filepath.Join(t.TempDir(), "client.log")
	t.Setenv("LEOPREVENT_LOG", logPath)
	return dir, session, logPath
}

func promptSubmit(t *testing.T, dir, session, promptID, prompt string) {
	t.Helper()
	payload := map[string]string{"hook_event_name": "UserPromptSubmit", "session_id": session, "cwd": dir, "prompt": prompt}
	if promptID != "" {
		payload["prompt_id"] = promptID
	}
	stdin, _ := json.Marshal(payload)
	var out, errb bytes.Buffer
	if code := run([]string{"--agent=claude"}, bytes.NewReader(stdin), &out, &errb); code != 0 {
		t.Fatalf("UserPromptSubmit exit %d", code)
	}
}

func edit(t *testing.T, dir string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte("import os\nx = eval(y)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// changedAtStop is what the Stop path diffs: the working tree against the baseline.
func changedAtStop(t *testing.T, dir, session string) []string {
	t.Helper()
	changes, ok, skip, err := vcs.ChangedFiles(dir, session)
	if err != nil || !ok {
		t.Fatalf("ChangedFiles ok=%v skip=%q err=%v", ok, skip, err)
	}
	var paths []string
	for _, c := range changes {
		paths = append(paths, c.FilePath)
	}
	return paths
}

const notification = "<task-notification>\n<task-id>b1</task-id>\n<status>completed</status>\n</task-notification>"

// TestTaskNotificationMidTurnKeepsBaseline is the 2026-10-02 benchmark miss: the agent
// edits, a background task's notification arrives as a UserPromptSubmit carrying the
// turn's own prompt_id, and the Stop must still see the edits.
func TestTaskNotificationMidTurnKeepsBaseline(t *testing.T) {
	dir, session, logPath := baselineRepo(t)
	promptSubmit(t, dir, session, "p1", "fix the bug")
	edit(t, dir)
	promptSubmit(t, dir, session, "p1", notification)

	if got := changedAtStop(t, dir, session); len(got) != 1 || got[0] != "app.py" {
		t.Fatalf("Stop after a mid-turn notification must see the turn's edit, got %v", got)
	}
	log, _ := os.ReadFile(logPath)
	if !strings.Contains(string(log), "git baseline kept") {
		t.Errorf("a kept baseline must be visible at INFO in client.log, got:\n%s", log)
	}
	if !strings.Contains(string(log), "git baseline captured") {
		t.Errorf("a captured baseline must be visible at INFO in client.log, got:\n%s", log)
	}
}

// Without a prompt_id to compare, the notification prefix alone keeps the baseline.
func TestTaskNotificationWithoutPromptIDKeepsBaseline(t *testing.T) {
	dir, session, _ := baselineRepo(t)
	promptSubmit(t, dir, session, "", "fix the bug")
	edit(t, dir)
	promptSubmit(t, dir, session, "", notification)

	if got := changedAtStop(t, dir, session); len(got) != 1 || got[0] != "app.py" {
		t.Fatalf("Stop after a notification with no prompt_id must see the turn's edit, got %v", got)
	}
}

// A genuine new prompt (a fresh prompt_id, or no id and no notification) still
// re-baselines, so the previous turn's already-reviewed edit is not reviewed again.
func TestNewPromptStillRebaselines(t *testing.T) {
	for _, tc := range []struct{ name, first, second, prompt string }{
		{"fresh prompt_id", "p1", "p2", "next task"},
		{"no prompt_id", "", "", "next task"},
		{"notification opening a new turn", "p1", "p2", notification},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, session, _ := baselineRepo(t)
			promptSubmit(t, dir, session, tc.first, "fix the bug")
			edit(t, dir)
			promptSubmit(t, dir, session, tc.second, tc.prompt)

			if got := changedAtStop(t, dir, session); len(got) != 0 {
				t.Fatalf("a new turn must re-baseline past the previous turn's edit, got %v", got)
			}
		})
	}
}
