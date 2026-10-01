package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/config"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/outcome"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

func TestPromptRecoveryRouting(
	t *testing.T,
) {
	for _, agentName := range []string{"claude", "codex"} {
		for _, tier := range []string{config.TierCloud, config.TierLocal} {
			t.Run(agentName+"/"+tier, func(t *testing.T) {
				var mu sync.Mutex
				var requests []string
				var got wire.OutcomeRequest
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					mu.Lock()
					defer mu.Unlock()
					requests = append(requests, r.URL.Path)
					if r.URL.Path == "/outcome" {
						if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
							t.Error(err)
						}
						w.Header().Set("Content-Type", "application/json")
						fmt.Fprint(w, `{"scored":true}`)
						return
					}
					w.WriteHeader(http.StatusAccepted)
				}))
				defer srv.Close()
				t.Setenv(config.EnvServerURL, srv.URL)
				t.Setenv(config.EnvTier, tier)
				t.Setenv(config.EnvLicenseKey, "test-license")
				dir := t.TempDir()
				session := "route-" + filepath.Base(dir)
				t.Cleanup(func() { outcome.Clear(session); outcome.ClearLedger(session) })
				if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte("fixed"), 0600); err != nil {
					t.Fatal(err)
				}
				p := outcome.Pending{ReviewID: "original", Before: []wire.ChangedFile{{Path: "app.py", FullContent: "vulnerable"}}, Sources: []outcome.Source{{Path: "app.py", Root: dir, Relative: "app.py"}}, OriginalMeta: wire.TurnMeta{Agent: agentName, Prompt: "original prompt"}}
				if err := outcome.Remember(session, p); err != nil {
					t.Fatal(err)
				}
				payload := fmt.Sprintf(`{"hook_event_name":"UserPromptSubmit","session_id":%q,"cwd":%q}`, session, dir)
				code, _, _ := runWith(t, []string{"--agent=" + agentName}, payload)
				if code != 0 {
					t.Fatal("prompt failed")
				}
				mu.Lock()
				count := len(requests)
				mu.Unlock()
				if count != 0 {
					t.Fatal("prompt must not send network requests")
				}
				stored, _ := outcome.Load(session)
				if (stored.Recovery != nil) != (tier == config.TierCloud) {
					t.Fatalf("wrong capture for %s", tier)
				}
				if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte("new turn"), 0600); err != nil {
					t.Fatal(err)
				}
				payload = fmt.Sprintf(`{"hook_event_name":"Stop","session_id":%q,"cwd":%q,"stop_hook_active":false}`, session, dir)
				code, _, _ = runWith(t, []string{"--agent=" + agentName}, payload)
				if code != 0 {
					t.Fatal("stop failed")
				}
				mu.Lock()
				defer mu.Unlock()
				if tier == config.TierLocal {
					if len(requests) != 0 {
						t.Fatalf("local tier sent requests: %v", requests)
					}
					return
				}
				if got.ReviewID != "original" || got.Prompt != "original prompt" || len(got.After) != 1 || got.After[0].FullContent != "fixed" {
					t.Fatalf("wrong outcome: %+v", got)
				}
				if got.DurationMs != 0 || got.AgentResponse != "" {
					t.Fatal("recovery borrowed new turn metadata")
				}
			})
		}
	}
}
