package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/config"
)

type findingsHit struct {
	method string
	path   string
	query  url.Values
	body   map[string]string
}

func runFindingsAgainst(t *testing.T, status int, respond string, args ...string) (int, string, []findingsHit) {
	t.Helper()
	var hits []findingsHit
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit := findingsHit{method: r.Method, path: r.URL.Path, query: r.URL.Query()}
		if r.Method == http.MethodPost {
			raw, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(raw, &hit.body)
		}
		hits = append(hits, hit)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(respond))
	}))
	defer srv.Close()

	tmp := t.TempDir()
	defer config.SetUserConfigDirForTest(tmp)()
	t.Setenv("LEOPREVENT_LOG", filepath.Join(tmp, "client.log"))
	t.Setenv("LEOPREVENT_SERVER_URL", "https://server.invalid")
	t.Setenv("LEOPREVENT_DASHBOARD_URL", srv.URL)
	t.Setenv("LEOPREVENT_LICENSE_KEY", "lp_live_test")

	out := filepath.Join(tmp, "stdout")
	f, err := os.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stdout
	os.Stdout = f
	code := runFindings(args)
	os.Stdout = saved
	_ = f.Close()

	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	return code, string(raw), hits
}

func TestFindingsListsOpenUndecidedFindingsAcrossAllTimeByDefault(t *testing.T) {
	// Act
	code, out, hits := runFindingsAgainst(t, 200, `{"view":"findings","findings":[]}`)

	// Assert
	if code != 0 {
		t.Fatalf("code = %d", code)
	}
	if len(hits) != 1 || hits[0].path != "/api/agent" {
		t.Fatalf("hits = %+v", hits)
	}
	q := hits[0].query
	if q.Get("view") != "findings" || q.Get("open") != "1" || q.Get("days") != "all" || q.Get("limit") != "20" {
		t.Errorf("query = %v", q)
	}
	if strings.TrimSpace(out) != `{"view":"findings","findings":[]}` {
		t.Errorf("stdout = %q", out)
	}
}

func TestFindingsAllListsEveryFindingOverTheDefaultWindow(t *testing.T) {
	// Act
	code, _, hits := runFindingsAgainst(t, 200, `{}`, "--all", "--scope", "team", "--repo", "api")

	// Assert
	if code != 0 {
		t.Fatalf("code = %d", code)
	}
	q := hits[0].query
	if q.Has("open") || q.Has("days") {
		t.Errorf("--all should send neither open nor days: %v", q)
	}
	if q.Get("scope") != "team" || q.Get("repo") != "api" {
		t.Errorf("query = %v", q)
	}
}

func TestFindingsIgnorePostsTheReason(t *testing.T) {
	// Act
	code, out, hits := runFindingsAgainst(t, 200, `{"id":"rev_1-0","state":"ignored"}`,
		"ignore", "rev_1-0", "--reason", "Test fixture only", "--scope", "team")

	// Assert
	if code != 0 {
		t.Fatalf("code = %d", code)
	}
	if len(hits) != 1 || hits[0].method != http.MethodPost || hits[0].path != "/api/agent/triage" {
		t.Fatalf("hits = %+v", hits)
	}
	want := map[string]string{"id": "rev_1-0", "state": "ignored", "note": "Test fixture only", "scope": "team"}
	for k, v := range want {
		if hits[0].body[k] != v {
			t.Errorf("body[%s] = %q, want %q", k, hits[0].body[k], v)
		}
	}
	if !strings.Contains(out, `"state":"ignored"`) {
		t.Errorf("stdout = %q", out)
	}
}

func TestFindingsReopenNeedsNoReason(t *testing.T) {
	// Act
	code, _, hits := runFindingsAgainst(t, 200, `{"id":"rev_1-0","state":"open","triage":null}`, "reopen", "rev_1-0")

	// Assert
	if code != 0 {
		t.Fatalf("code = %d", code)
	}
	if hits[0].body["state"] != "open" {
		t.Errorf("body = %v", hits[0].body)
	}
	if _, ok := hits[0].body["note"]; ok {
		t.Error("an empty note should be omitted")
	}
}

func TestFindingsTriageRefusesBadInputBeforeAnyRequest(t *testing.T) {
	cases := [][]string{
		{"ignore", "rev_1-0"},
		{"resolve", "rev_1-0", "--reason", "   "},
		{"ignore"},
		{"ignore", "--reason", "x"},
		{"ignore", "rev_1-0", "--reason", "x", "--scope", "everyone"},
		{"--scope", "everyone"},
		{"stray"},
	}
	for _, args := range cases {
		// Act
		code, _, hits := runFindingsAgainst(t, 200, `{}`, args...)

		// Assert
		if code != 2 {
			t.Errorf("%v: code = %d, want 2", args, code)
		}
		if len(hits) != 0 {
			t.Errorf("%v: made %d requests", args, len(hits))
		}
	}
}

func TestFindingsReportsTheDashboardsRefusal(t *testing.T) {
	// Act
	code, out, _ := runFindingsAgainst(t, 409, `{"error":"Only an open finding can be ignored or resolved."}`,
		"resolve", "rev_1-0", "--reason", "Fixed upstream")

	// Assert
	if code != 1 {
		t.Errorf("code = %d, want 1", code)
	}
	if out != "" {
		t.Errorf("stdout should be empty on a refusal, got %q", out)
	}
}
