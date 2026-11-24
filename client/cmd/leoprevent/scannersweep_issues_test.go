package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/apiclient"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

func TestGithubIssuesSweepUsesItsOwnRoutes(
	t *testing.T,
) {
	// Arrange
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		json.NewEncoder(w).Encode(map[string]any{"connected": true, "notice": "n"})
	}))
	defer srv.Close()
	client := apiclient.New(srv.URL, "lp_test")

	// Act
	_, _ = client.SweepPlan(issuesSweep.route, wire.SweepPlanRequest{Repo: "r"})
	_, _ = client.Sweep(issuesSweep.route, wire.SweepRequest{})
	_ = sweepNotice(issuesSweep, client, wire.SweepNoticeRequest{Kind: wire.SweepNoticePlan})

	// Assert
	want := []string{"/github-issues/sweep/plan", "/github-issues/sweep", "/github-issues/sweep/notice"}
	if strings.Join(paths, ",") != strings.Join(want, ",") {
		t.Errorf("paths %v, want %v", paths, want)
	}
	if issuesSweep.lane != wire.LaneGithubIssuesSweep || !issuesSweep.filters || githubSweep.filters {
		t.Errorf("issues sweep = %+v", issuesSweep)
	}
}

func TestGithubIssuesSweepSendsTheFilterAndNoIssueContent(
	t *testing.T,
) {
	// Arrange
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(b))
		json.NewEncoder(w).Encode(map[string]any{"connected": true})
	}))
	defer srv.Close()
	client := apiclient.New(srv.URL, "lp_test")

	// Act
	_, _ = client.SweepPlan(issuesSweep.route, wire.SweepPlanRequest{Repo: "r", IssueLabel: "semgrep", IssueAuthor: "bot"})
	_, _ = client.Sweep(issuesSweep.route, wire.SweepRequest{IssueLabel: "semgrep"})

	// Assert
	if len(bodies) != 2 || !strings.Contains(bodies[0], `"issue_label":"semgrep"`) || !strings.Contains(bodies[0], `"issue_author":"bot"`) || !strings.Contains(bodies[1], `"issue_label":"semgrep"`) {
		t.Fatalf("bodies = %v", bodies)
	}
	if strings.Contains(bodies[0], "reported") {
		t.Errorf("the plan must not carry issue content: %s", bodies[0])
	}
}

func TestLabelFilterIsRefusedForAnotherScanner(
	t *testing.T,
) {
	// Arrange
	args := []string{"--label", "semgrep"}

	// Act
	code := runScannerSweep(snykSweep, args)

	// Assert
	if code != 2 {
		t.Errorf("exit %d, want the usage error", code)
	}
}

func TestSweepPicksGithubIssuesApartFromGithub(
	t *testing.T,
) {
	// Arrange
	var picked []string
	for _, arg := range []string{"github", "GitHub-Issues"} {
		for _, tool := range sweepTools {
			if strings.EqualFold(arg, tool.route) {
				picked = append(picked, tool.route)
			}
		}
	}

	// Act
	got := strings.Join(picked, ",")

	// Assert
	if got != "github,github-issues" {
		t.Errorf("picked %q", got)
	}
}
