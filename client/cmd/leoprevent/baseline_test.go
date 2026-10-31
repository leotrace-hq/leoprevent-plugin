package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/agent"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/config"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/notify"
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

const handBack = "<agent-message>\nThe background agent finished.\n</agent-message>"

func writeFile(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func stopWithTasks(t *testing.T, dir, session, out string, tasks ...string) {
	t.Helper()
	ev := agent.Event{Name: "Stop", Cwd: dir, SessionID: session}
	for _, task := range tasks {
		id, kind, _ := strings.Cut(task, ":")
		ev.BackgroundTasks = append(ev.BackgroundTasks, agent.BackgroundTask{ID: id, Type: kind, Status: "running"})
		if kind == "subagent" {
			ev.BackgroundWork = true
		}
	}
	stopReviewing(ev, out, func() {})
}

func stopReviewing(ev agent.Event, out string, review func()) {
	pending := noteBackgroundWork(ev)
	review()
	if pending {
		rebaselineAfterStop(ev, []byte(out))
	}
}

func stopThroughHook(t *testing.T, dir, session, tasks string) {
	t.Helper()
	stdin := `{"hook_event_name":"Stop","session_id":"` + session + `","cwd":` + strconv.Quote(dir) + `,"background_tasks":` + tasks + `}`
	var out, errb bytes.Buffer
	if code := run([]string{"--agent=claude"}, strings.NewReader(stdin), &out, &errb); code != 0 {
		t.Fatalf("Stop exit %d", code)
	}
}

func TestBackgroundSubagentWriteAfterStopIsReviewed(t *testing.T) {
	// Arrange
	dir, session, logPath := baselineRepo(t)
	promptSubmit(t, dir, session, "p1", "start a background agent, then edit app.py")
	edit(t, dir)
	stopWithTasks(t, dir, session, "", "a1:subagent")
	writeFile(t, dir, "background.py", "import subprocess\nsubprocess.run(cmd, shell=True)\n")

	// Act
	promptSubmit(t, dir, session, "p2", handBack)

	// Assert
	if got := changedAtStop(t, dir, session); len(got) != 1 || got[0] != "background.py" {
		t.Fatalf("the hand-back Stop must review the subagent's file and only it, got %v", got)
	}
	log, _ := os.ReadFile(logPath)
	if !strings.Contains(string(log), "git baseline kept: background work still running") {
		t.Errorf("a baseline kept for background work must be visible at INFO, got:\n%s", log)
	}
}

func TestBackgroundWorkStaysPendingAcrossStops(t *testing.T) {
	// Arrange
	dir, session, _ := baselineRepo(t)
	promptSubmit(t, dir, session, "p1", "start a background agent")
	stopWithTasks(t, dir, session, "", "a1:subagent")
	promptSubmit(t, dir, session, "p2", notification)
	edit(t, dir)
	stopWithTasks(t, dir, session, "", "a1:subagent")
	writeFile(t, dir, "background.py", "x = 1\n")

	// Act
	promptSubmit(t, dir, session, "p3", handBack)

	// Assert
	if got := changedAtStop(t, dir, session); len(got) != 1 || got[0] != "background.py" {
		t.Fatalf("each Stop while work is pending must review only what is new since the last one, got %v", got)
	}
}

func TestSubagentsOwnShellKeepsWorkPending(t *testing.T) {
	// Arrange
	dir, session, _ := baselineRepo(t)
	promptSubmit(t, dir, session, "p1", "start a background agent, then edit app.py")
	edit(t, dir)
	stopWithTasks(t, dir, session, "", "a1:subagent")
	promptSubmit(t, dir, session, "p2", notification)
	stopWithTasks(t, dir, session, "", "b1:shell")
	writeFile(t, dir, "background.py", "import subprocess\nsubprocess.run(cmd, shell=True)\n")

	// Act
	promptSubmit(t, dir, session, "p3", handBack)

	// Assert
	if got := changedAtStop(t, dir, session); len(got) != 1 || got[0] != "background.py" {
		t.Fatalf("a shell the subagent started must keep the work pending until the hand-back, got %v", got)
	}
}

func TestEarlierShellDoesNotHoldWorkPending(t *testing.T) {
	// Arrange
	dir, session, _ := baselineRepo(t)
	promptSubmit(t, dir, session, "p1", "start the dev server")
	stopWithTasks(t, dir, session, "", "dev:shell")
	promptSubmit(t, dir, session, "p2", "start a background agent")
	stopWithTasks(t, dir, session, "", "dev:shell", "a1:subagent")
	stopWithTasks(t, dir, session, "", "dev:shell")
	edit(t, dir)

	// Act
	promptSubmit(t, dir, session, "p3", "next task")

	// Assert
	if got := changedAtStop(t, dir, session); len(got) != 0 {
		t.Fatalf("a shell already running before the subagent must not hold the work pending, got %v", got)
	}
}

func TestShellAloneNeverStartsPending(t *testing.T) {
	// Arrange
	dir, session, _ := baselineRepo(t)
	promptSubmit(t, dir, session, "p1", "start the dev server")
	stopWithTasks(t, dir, session, "", "dev:shell", "b2:shell")
	edit(t, dir)

	// Act
	promptSubmit(t, dir, session, "p2", "next task")

	// Assert
	if got := changedAtStop(t, dir, session); len(got) != 0 {
		t.Fatalf("background shells alone must not start pending, got %v", got)
	}
}

func TestFailedOpenStopStillKeepsBackgroundWorkPending(t *testing.T) {
	// Arrange
	dir, session, _ := baselineRepo(t)
	t.Cleanup(func() { notify.Clear(session) })
	promptSubmit(t, dir, session, "p1", "start a background agent, then edit app.py")
	edit(t, dir)
	stopThroughHook(t, dir, session, `[{"id":"a1","type":"subagent","status":"running"}]`)
	writeFile(t, dir, "background.py", "x = 1\n")

	// Act
	promptSubmit(t, dir, session, "p2", handBack)

	// Assert
	if got := changedAtStop(t, dir, session); len(got) != 2 {
		t.Fatalf("a Stop that failed open must keep the turn's baseline so its edits and the subagent's are reviewed next, got %v", got)
	}
}

func TestWriteDuringReviewIsReviewedNext(t *testing.T) {
	// Arrange
	dir, session, _ := baselineRepo(t)
	promptSubmit(t, dir, session, "p1", "start a background agent, then edit app.py")
	edit(t, dir)
	ev := agent.Event{Name: "Stop", Cwd: dir, SessionID: session, BackgroundWork: true,
		BackgroundTasks: []agent.BackgroundTask{{ID: "a1", Type: "subagent", Status: "running"}}}
	stopReviewing(ev, "", func() {
		writeFile(t, dir, "background.py", "import subprocess\nsubprocess.run(cmd, shell=True)\n")
	})

	// Act
	promptSubmit(t, dir, session, "p2", handBack)

	// Assert
	if got := changedAtStop(t, dir, session); len(got) != 1 || got[0] != "background.py" {
		t.Fatalf("a file the subagent wrote while the Stop was being reviewed must be in the next diff, got %v", got)
	}
}

func TestBlockedStopDiscardsStagedBaseline(t *testing.T) {
	// Arrange
	dir, session, _ := baselineRepo(t)
	promptSubmit(t, dir, session, "p1", "start a background agent, then edit app.py")
	edit(t, dir)
	stopWithTasks(t, dir, session, `{"decision":"block","reason":"fix it"}`, "a1:subagent")
	writeFile(t, dir, "fix.py", "x = 1\n")

	// Act
	stopWithTasks(t, dir, session, "", "a1:subagent")
	promptSubmit(t, dir, session, "p2", handBack)

	// Assert
	if got := changedAtStop(t, dir, session); len(got) != 0 {
		t.Fatalf("the guard Stop must promote its own snapshot, not the blocked Stop's, got %v", got)
	}
}

func TestBlockedStopWithBackgroundWorkKeepsBaseline(t *testing.T) {
	// Arrange
	dir, session, _ := baselineRepo(t)
	promptSubmit(t, dir, session, "p1", "fix the bug")
	edit(t, dir)

	// Act
	stopWithTasks(t, dir, session, `{"decision":"block","reason":"fix it"}`, "a1:subagent")

	// Assert
	if got := changedAtStop(t, dir, session); len(got) != 1 || got[0] != "app.py" {
		t.Fatalf("a blocked Stop must leave the baseline for the fix check, got %v", got)
	}
}

func TestStopWithNoBackgroundWorkEndsPending(t *testing.T) {
	// Arrange
	dir, session, _ := baselineRepo(t)
	promptSubmit(t, dir, session, "p1", "start a background agent")
	stopWithTasks(t, dir, session, "", "a1:subagent")
	stopWithTasks(t, dir, session, "")
	edit(t, dir)

	// Act
	promptSubmit(t, dir, session, "p2", "next task")

	// Assert
	if got := changedAtStop(t, dir, session); len(got) != 0 {
		t.Fatalf("once background work is done a new prompt must re-baseline, got %v", got)
	}
}

func TestBlocksStop(t *testing.T) {
	for _, tc := range []struct {
		name string
		out  string
		want bool
	}{
		{"no output", "", false},
		{"notice only", `{"systemMessage":"skipped"}`, false},
		{"block", `{"decision":"block","reason":"x"}`, true},
		{"unparseable", "not json", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Act
			got := blocksStop([]byte(tc.out))

			// Assert
			if got != tc.want {
				t.Fatalf("blocksStop(%q) = %v, want %v", tc.out, got, tc.want)
			}
		})
	}
}
