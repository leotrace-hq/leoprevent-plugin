package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/config"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/outcome"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

func TestAgentCloudReviewAndRepairOutcome(
	t *testing.T,
) {
	for _, name := range []string{"cursor", "devin", "copilot"} {
		t.Run(name, func(t *testing.T) {
			var mu sync.Mutex
			var reviewed wire.ReviewRequest
			var repaired wire.OutcomeRequest
			var paths []string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				paths = append(paths, r.URL.Path)
				if r.Header.Get("Authorization") != "Bearer test-license" {
					t.Error("review credential missing")
				}
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/review":
					if err := json.NewDecoder(r.Body).Decode(&reviewed); err != nil {
						t.Error(err)
					}
					_, _ = w.Write([]byte(`{"verdict":"triggered","review_id":"test-review","findings":[{"rule":"sql-injection","name":"SQL Injection","location":"app.py:3","issue":"SQL input is concatenated","fix":"Parameterize the query"}]}`))
				case "/outcome":
					if err := json.NewDecoder(r.Body).Decode(&repaired); err != nil {
						t.Error(err)
					}
					_, _ = w.Write([]byte(`{}`))
				default:
					_, _ = w.Write([]byte(`{}`))
				}
			}))
			defer srv.Close()
			t.Setenv(config.EnvServerURL, srv.URL)
			t.Setenv(config.EnvTier, config.TierCloud)
			t.Setenv(config.EnvLicenseKey, "test-license")
			t.Cleanup(config.SetUserConfigDirForTest(t.TempDir()))
			dir := t.TempDir()
			session := name + filepath.Base(dir)
			t.Cleanup(func() { outcome.Clear(session); outcome.ClearLedger(session) })
			if out, err := exec.Command("git", "-C", dir, "init", "-q").CombinedOutput(); err != nil {
				t.Fatalf("git: %v %s", err, out)
			}
			payload := func(event, prompt string, active bool) string {
				p := map[string]any{"hook_event_name": event, "session_id": session, "cwd": dir, "prompt": prompt, "stop_hook_active": active}
				if name == "cursor" {
					p["conversation_id"], p["workspace_roots"], p["status"] = session, []string{dir}, "completed"
					if event == "UserPromptSubmit" {
						p["hook_event_name"] = "beforeSubmitPrompt"
					} else {
						p["hook_event_name"] = "stop"
					}
				}
				data, _ := json.Marshal(p)
				return string(data)
			}
			args := []string{"--agent=" + name}
			_, _, _ = runWith(t, args, payload("UserPromptSubmit", "add query", false))
			file := filepath.Join(dir, "app.py")
			if err := os.WriteFile(file, []byte("import sqlite3\nconn = sqlite3.connect('app.db')\nconn.execute('SELECT * FROM users WHERE name = ' + name)\n"), 0600); err != nil {
				t.Fatal(err)
			}
			code, out, stderr := runWith(t, args, payload("Stop", "", false))
			var feedback map[string]any
			if code != 0 || json.Unmarshal([]byte(out), &feedback) != nil {
				t.Fatalf("review code=%d out=%s stderr=%s", code, out, stderr)
			}
			if name == "cursor" {
				prompt, ok := feedback["followup_message"].(string)
				if !ok || prompt == "" {
					t.Fatalf("missing followup: %s", out)
				}
				_, _, _ = runWith(t, args, payload("UserPromptSubmit", prompt, false))
			} else if feedback["decision"] != "block" {
				t.Fatalf("missing block: %s", out)
			}
			if name == "copilot" {
				nested, ok := feedback["hookSpecificOutput"].(map[string]any)
				if !ok || nested["decision"] != "block" {
					t.Fatalf("VS Code feedback missing: %s", out)
				}
			}
			if err := os.WriteFile(file, []byte("import sqlite3\nconn = sqlite3.connect('app.db')\nconn.execute('SELECT * FROM users WHERE name = ?', (name,))\n"), 0600); err != nil {
				t.Fatal(err)
			}
			code, _, stderr = runWith(t, args, payload("Stop", "", true))
			if code != 0 {
				t.Fatalf("guard code=%d stderr=%s", code, stderr)
			}
			mu.Lock()
			defer mu.Unlock()
			if len(paths) != 2 || paths[0] != "/review" || paths[1] != "/outcome" {
				t.Fatalf("requests=%v", paths)
			}
			if reviewed.Meta.Agent != name || len(reviewed.Changes) != 1 {
				t.Fatalf("review=%+v", reviewed)
			}
			if repaired.ReviewID != "test-review" || len(repaired.After) != 1 || !strings.Contains(repaired.After[0].FullContent, "(name,)") {
				t.Fatalf("outcome=%+v", repaired)
			}
		})
	}
}
