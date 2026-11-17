package hermes

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func hermesHomeWithSession(
	t *testing.T,
	sessionID, cwd string,
) string {
	t.Helper()
	if _, err := exec.LookPath("sqlite3"); err != nil {
		t.Skip("sqlite3 is not installed")
	}
	home := t.TempDir()
	sql := "CREATE TABLE sessions (id TEXT PRIMARY KEY, cwd TEXT); INSERT INTO sessions VALUES ('" + sessionID + "', '" + cwd + "');"
	if out, err := exec.Command("sqlite3", filepath.Join(home, "state.db"), sql).CombinedOutput(); err != nil {
		t.Fatalf("sqlite3: %v %s", err, out)
	}
	return home
}

func parse(
	t *testing.T,
	name, sessionID, cwd string,
	extra map[string]any,
) string {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"hook_event_name": name,
		"session_id":      sessionID,
		"cwd":             cwd,
		"tool_input":      map[string]string{"path": "src/app.py"},
		"extra":           extra,
	})
	if err != nil {
		t.Fatal(err)
	}
	ev, err := New().ParseEvent(payload)
	if err != nil {
		t.Fatal(err)
	}
	return ev.Cwd
}

func TestGatewaySessionWorkspaceWinsOverTheInstallDirectory(
	t *testing.T,
) {
	// Arrange
	project := t.TempDir()
	home := hermesHomeWithSession(t, "local-abc123", project)
	install := filepath.Join(home, "hermes-agent")
	if err := os.MkdirAll(install, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HERMES_HOME", home)
	t.Setenv("TERMINAL_CWD", "")

	for _, name := range []string{eventPreLLMCall, eventPreToolCall, eventPreVerify} {
		t.Run(name, func(t *testing.T) {
			// Act
			got := parse(t, name, "local-abc123", install, map[string]any{})

			// Assert
			if got != project {
				t.Fatalf("cwd=%q, want the session workspace %q", got, project)
			}
		})
	}
}

func TestTerminalCwdIsUsedWhenTheSessionHasNoRecord(
	t *testing.T,
) {
	// Arrange
	project := t.TempDir()
	home := t.TempDir()
	t.Setenv("HERMES_HOME", home)
	t.Setenv("TERMINAL_CWD", project)

	// Act
	got := parse(t, eventPreLLMCall, "unknown", filepath.Join(home, "hermes-agent"), map[string]any{})

	// Assert
	if got != project {
		t.Fatalf("cwd=%q, want TERMINAL_CWD %q", got, project)
	}
}

func TestTheInstallDirectoryIsNeverTheWorkspace(
	t *testing.T,
) {
	// Arrange
	home := t.TempDir()
	install := filepath.Join(home, "hermes-agent")
	if err := os.MkdirAll(install, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HERMES_HOME", home)
	t.Setenv("TERMINAL_CWD", install)

	// Act
	got := parse(t, eventPreLLMCall, "unknown", install, map[string]any{})

	// Assert
	if got != "" {
		t.Fatalf("cwd=%q: Hermes's own install would be reviewed and dependency-scanned", got)
	}
}

func TestStopFallsBackToTheFilesHermesWrote(
	t *testing.T,
) {
	// Arrange
	project := t.TempDir()
	home := t.TempDir()
	t.Setenv("HERMES_HOME", home)
	t.Setenv("TERMINAL_CWD", "")

	// Act
	got := parse(t, eventPreVerify, "unknown", filepath.Join(home, "hermes-agent"), map[string]any{
		"attempt":       0,
		"changed_paths": []string{filepath.Join(project, "app.py")},
	})

	// Assert
	if got != project {
		t.Fatalf("cwd=%q, want the written file's directory %q", got, project)
	}
}

func TestASessionIDOutsideTheAllowlistIsNeverQueried(
	t *testing.T,
) {
	// Arrange
	project := t.TempDir()
	home := hermesHomeWithSession(t, "x' OR '1'='1", project)
	t.Setenv("HERMES_HOME", home)
	t.Setenv("TERMINAL_CWD", "")

	// Act
	got := sessionCwd(home, "x' OR '1'='1")

	// Assert
	if got != "" {
		t.Fatalf("a quoted session id reached the query: %q", got)
	}
}
