package engine

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/agent/claude"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/policycheck"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/scratch"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

// policyReviewer is a reviewer whose server has the organisation's exclusion check.
type policyReviewer struct {
	*fakeReviewer
	answer policycheck.Answer
	err    error
	asked  []string
}

func (p *policyReviewer) PolicyCheck(repo string) (policycheck.Answer, error) {
	p.asked = append(p.asked, repo)
	return p.answer, p.err
}

func TestExcludedRepositorySendsNothing(t *testing.T) {
	t.Cleanup(scratch.SetUserCacheDirForTest(t.TempDir()))
	r := &policyReviewer{fakeReviewer: &fakeReviewer{prompt: "FIX"}, answer: policycheck.Answer{Excluded: true, Reason: "no-remote",
		Notice: &wire.ServerNotice{ID: "repo_excluded", Message: "server copy: excluded"}}}
	code, out := cleanTurnWith(t, r, "pg-excl")
	if code != 0 || r.fakeReviewer.called {
		t.Fatalf("an excluded repository is never sent: code=%d called=%v", code, r.fakeReviewer.called)
	}
	if !strings.Contains(out, "server copy: excluded") || strings.Contains(out, `"decision"`) {
		t.Fatalf("a non-blocking notice with the server's words, got %q", out)
	}
	if len(r.asked) != 1 || r.asked[0] != "" {
		t.Fatalf("a folder with no remote is asked as \"\": %v", r.asked)
	}
	// Cached: the same repository is not asked again within ten minutes, and the notice is
	// shown once per session.
	if _, again := cleanTurnWith(t, r, "pg-excl"); again != "" || len(r.asked) != 1 {
		t.Fatalf("cached and throttled: out=%q asked=%v", again, r.asked)
	}
}

func TestPolicyCheckFailureWithKnownExclusionsSkipsTheTurn(t *testing.T) {
	t.Cleanup(scratch.SetUserCacheDirForTest(t.TempDir()))
	now := time.Now()
	// An earlier answer told this license its Org excludes something.
	policycheck.Check(&policyReviewer{answer: policycheck.Answer{HasExclusions: true}}, licenseKey(), []string{"github.com/acme/other"}, now)

	r := &policyReviewer{fakeReviewer: &fakeReviewer{}, err: errors.New("dial tcp: refused")}
	_, out := cleanTurnWith(t, r, "pg-fail")
	if r.fakeReviewer.called || !strings.Contains(out, "couldn't be reached") || strings.Contains(out, `"decision"`) {
		t.Fatalf("can't check a known-excluding license means skip with a notice: called=%v out=%q", r.fakeReviewer.called, out)
	}
	if strings.ContainsRune(out, '—') {
		t.Fatal("no em dashes in the notice")
	}
}

func TestPolicyCheckFailureWithNoKnownExclusionsReviews(t *testing.T) {
	t.Cleanup(scratch.SetUserCacheDirForTest(t.TempDir()))
	r := &policyReviewer{fakeReviewer: &fakeReviewer{}, err: errors.New("dial tcp: refused")}
	_, out := cleanTurnWith(t, r, "pg-open")
	if !r.fakeReviewer.called || strings.Contains(out, "organisation") {
		t.Fatalf("a license with no known exclusions fails open and reviews: called=%v out=%q", r.fakeReviewer.called, out)
	}
	// The failure is cached briefly: the next turn doesn't wait on the server again.
	r.fakeReviewer.called = false
	_, _ = cleanTurnWith(t, r, "pg-open")
	if !r.fakeReviewer.called || len(r.asked) != 1 {
		t.Fatalf("reviewed without asking again: called=%v asked=%v", r.fakeReviewer.called, r.asked)
	}
}

func TestAbsentPolicyCheckReviewsAsBefore(t *testing.T) {
	t.Cleanup(scratch.SetUserCacheDirForTest(t.TempDir()))
	r := &policyReviewer{fakeReviewer: &fakeReviewer{}, answer: policycheck.Answer{Absent: true}}
	_, _ = cleanTurnWith(t, r, "pg-absent")
	if !r.fakeReviewer.called {
		t.Fatal("a server without the check (404) reviews as before")
	}
}

func cleanTurnWith(t *testing.T, r Reviewer, session string) (int, string) {
	t.Helper()
	tp := writeTranscript(t,
		`{"type":"user","message":{"role":"user","content":"add a route"}}`,
		`{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","name":"Write","input":{"file_path":"/p/app.py","content":"x = 1"}}]}}`,
	)
	stdin := fmt.Sprintf(`{"stop_hook_active":false,"session_id":%q,"transcript_path":%q,"cwd":""}`, session, tp)
	code, stdout, _ := runWith(claude.New(), r, stdin)
	return code, stdout
}
