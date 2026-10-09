package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/config"
)

// statsHarness points `leoprevent stats` at a stub dashboard and captures its stdout.
//
// It drives runStats through config.Load rather than calling the reader directly, because
// the thing worth pinning is the whole command: an env override this path does not read, or
// a flag it drops on the floor, are both invisible to a test of the pieces.
type statsHarness struct {
	mu      sync.Mutex
	queries []url.Values
	respond func(view string) (int, string)
}

func (h *statsHarness) run(t *testing.T, args ...string) (code int, stdout string) {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		h.mu.Lock()
		h.queries = append(h.queries, q)
		h.mu.Unlock()
		status, body := h.respond(q.Get("view"))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	tmp := t.TempDir()
	defer config.SetUserConfigDirForTest(tmp)()
	t.Setenv("LEOPREVENT_LOG", filepath.Join(tmp, "client.log"))
	t.Setenv("LEOPREVENT_SERVER_URL", "https://server.invalid")
	t.Setenv("LEOPREVENT_DASHBOARD_URL", srv.URL)
	t.Setenv("LEOPREVENT_LICENSE_KEY", "lp_live_test")

	// A file rather than a pipe: runStats writes to os.Stdout synchronously, and a pipe
	// nobody is draining deadlocks the moment the document outgrows its buffer.
	out := filepath.Join(tmp, "stdout")
	f, err := os.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stdout
	os.Stdout = f
	code = runStats(args)
	os.Stdout = saved
	_ = f.Close()

	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	return code, string(raw)
}

func okDashboard(view string) (int, string) {
	switch view {
	case "stats":
		return 200, `{"view":"stats","scope":"me","turns":41,"flaws":{"caught":3,"newFlaws":2,"existingFlaws":1}}`
	case "findings":
		return 200, `{"view":"findings","matched":3,"truncated":false,"findings":[{"rule":"ssrf","origin":"new"}]}`
	}
	return 400, `{"error":"view must be one of: stats, findings, repos, rules"}`
}

// TestStatsPrintsBothViewsVerbatim pins the document the agent reads.
//
// The keys matter as much as the values: commands/stats.md tells the agent which half is
// which, so a rename here silently leaves it summarising a shape its instructions do not
// describe. The bodies are asserted FIELD BY FIELD rather than by string equality, because
// the point is that nothing in this binary reshaped them.
func TestStatsPrintsBothViewsVerbatim(t *testing.T) {
	h := &statsHarness{respond: okDashboard}
	code, out := h.run(t)
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stdout: %s", code, out)
	}

	var doc struct {
		Stats    map[string]any `json:"stats"`
		Findings map[string]any `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("stdout is not one JSON document: %v\n%s", err, out)
	}
	if doc.Stats["view"] != "stats" || doc.Findings["view"] != "findings" {
		t.Errorf("the two bodies are not under the keys stats.md names: %s", out)
	}
	if doc.Stats["turns"] != float64(41) {
		t.Errorf("stats body altered on the way through: %v", doc.Stats)
	}
	flaws, _ := doc.Stats["flaws"].(map[string]any)
	if flaws["newFlaws"] != float64(2) || flaws["existingFlaws"] != float64(1) {
		// The new/existing split is the one thing the summary must not collapse, and a
		// Go-side reshape is exactly how it would get collapsed.
		t.Errorf("the new-vs-existing split did not survive: %v", flaws)
	}
	if doc.Findings["matched"] != float64(3) {
		t.Errorf("findings body altered on the way through: %v", doc.Findings)
	}
}

// TestStatsDefaultsToTheDevelopersOwnFiguresAndAShortList pins what an argument-free call asks for.
func TestStatsDefaultsToTheDevelopersOwnFiguresAndAShortList(t *testing.T) {
	h := &statsHarness{respond: okDashboard}
	if code, out := h.run(t); code != 0 {
		t.Fatalf("exit = %d, want 0; stdout: %s", code, out)
	}
	if len(h.queries) != 2 {
		t.Fatalf("made %d requests, want 2 (stats + findings)", len(h.queries))
	}
	for _, q := range h.queries {
		if q.Get("scope") != "me" {
			t.Errorf("view %q asked for scope %q, want me — team is a colleague's activity and is never the default",
				q.Get("view"), q.Get("scope"))
		}
		// Absent, not 30: the window's default belongs to the API, beside the clamp that
		// bounds it. A number sent from here would be a second one, drifting silently.
		if q.Has("days") {
			t.Errorf("view %q sent days=%q; the default window is the API's to pick",
				q.Get("view"), q.Get("days"))
		}
	}
	var findings url.Values
	for _, q := range h.queries {
		if q.Get("view") == "findings" {
			findings = q
		}
	}
	if findings == nil {
		t.Fatal("no findings request was made, so the summary would carry counts and no flaws")
	}
	if findings.Get("limit") != "10" {
		t.Errorf("findings limit = %q, want 10", findings.Get("limit"))
	}
}

// TestStatsRefusesAnUnrecognisedScope pins the one place this command is STRICTER than the API.
//
// `/api/agent` reads anything that is not `team` as `me`, which is the safe direction for a
// value arriving over the wire. Here the value was typed, so the same fallback would answer a
// question about the team with one about the developer and say nothing about having done so.
// The assertion that matters is that NOTHING WAS ASKED: a refusal after the read has already
// happened is the wrong answer arriving one line later.
func TestStatsRefusesAnUnrecognisedScope(t *testing.T) {
	h := &statsHarness{respond: okDashboard}
	code, out := h.run(t, "--scope", "tem")
	if code != 2 {
		t.Errorf("exit = %d, want 2 (usage)", code)
	}
	if len(h.queries) != 0 {
		t.Errorf("the dashboard was read %d times despite the bad scope", len(h.queries))
	}
	if out != "" {
		t.Errorf("printed a summary for a refused call: %s", out)
	}
}

// TestStatsPrintsNothingWhenEitherReadFails is the false-all-clear guard.
//
// ⚠️ THE ASSERTION IS THE EMPTY STDOUT, NOT THE EXIT CODE. Printing the half that worked
// would put real figures above an empty findings list, which reads as a clean period — the
// one failure this product exists to avoid, and the agent would report it as good news
// because nothing in the document says a read was lost.
func TestStatsPrintsNothingWhenEitherReadFails(t *testing.T) {
	for _, broken := range []string{"stats", "findings"} {
		t.Run(broken, func(t *testing.T) {
			h := &statsHarness{respond: func(view string) (int, string) {
				if view == broken {
					return 503, `{"error":"the dashboard is unavailable"}`
				}
				return okDashboard(view)
			}}
			code, out := h.run(t)
			if code != 1 {
				t.Errorf("exit = %d, want 1", code)
			}
			if out != "" {
				t.Errorf("printed a partial summary when the %s read failed: %s", broken, out)
			}
		})
	}
}

// TestStatsRefusesABodyThatIsNotJSON covers the 200 that is an edge proxy rather than the API.
func TestStatsRefusesABodyThatIsNotJSON(t *testing.T) {
	h := &statsHarness{respond: func(view string) (int, string) {
		if view == "findings" {
			return 200, "<html>Access denied</html>"
		}
		return okDashboard(view)
	}}
	code, out := h.run(t)
	if code != 1 {
		t.Errorf("exit = %d, want 1", code)
	}
	if out != "" {
		t.Errorf("printed something for an unparseable body: %s", out)
	}
}

// TestStatsNamesAMissingDashboardURL pins that the refusal is actionable rather than a 401
// repeated inside every answer the agent gives.
func TestStatsNamesAMissingDashboardURL(t *testing.T) {
	tmp := t.TempDir()
	defer config.SetUserConfigDirForTest(tmp)()
	t.Setenv("LEOPREVENT_LOG", filepath.Join(tmp, "client.log"))
	t.Setenv("LEOPREVENT_SERVER_URL", "https://server.invalid")
	t.Setenv("LEOPREVENT_LICENSE_KEY", "lp_live_test")
	t.Setenv("LEOPREVENT_DASHBOARD_URL", "")

	if code := runStats(nil); code != 1 {
		t.Errorf("exit = %d, want 1 with no dashboard_url", code)
	}
}

// TestStatsForwardsTheFiltersItAdvertises pins the flags commands/stats.md tells the agent to use.
func TestStatsForwardsTheFiltersItAdvertises(t *testing.T) {
	h := &statsHarness{respond: okDashboard}
	code, _ := h.run(t, "--days", "7", "--limit", "3", "--scope", "team", "--repo", "leoprevent")
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	for _, q := range h.queries {
		if q.Get("days") != "7" || q.Get("scope") != "team" {
			t.Errorf("view %q: days=%q scope=%q, want 7/team on both views",
				q.Get("view"), q.Get("days"), q.Get("scope"))
		}
		// repo and limit narrow a LIST, so they belong on findings and nowhere else — the
		// stats view has no rows and would simply ignore them, which is the kind of quietly
		// meaningless parameter worth not sending.
		if q.Get("view") == "stats" && (q.Has("repo") || q.Has("limit")) {
			t.Errorf("the stats view was sent list filters: %v", q)
		}
		if q.Get("view") == "findings" && (q.Get("repo") != "leoprevent" || q.Get("limit") != "3") {
			t.Errorf("findings lost its filters: %v", q)
		}
	}
}

// TestStatsUsageNamesEveryFlag keeps the refusal a complete answer: a developer told only
// that --scope was wrong still has to guess what else the command takes.
func TestStatsUsageNamesEveryFlag(t *testing.T) {
	for _, flag := range []string{"--days", "--limit", "--scope", "--repo"} {
		if !strings.Contains(statsUsageLine, flag) {
			t.Errorf("the usage line never mentions %s", flag)
		}
	}
}
