package policycheck

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/apiclient"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/scratch"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

func serve(t *testing.T, status int, body string) API {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/policy/check" {
			t.Errorf("path %s", r.URL.Path)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return API{Client: apiclient.New(srv.URL, "lp_test")}
}

func TestAPIReadsTheServer(t *testing.T) {
	if a, err := serve(t, 200, `{"excluded":true,"reason":"no-remote"}`).PolicyCheck(""); err != nil || !a.Excluded || a.Reason != "no-remote" {
		t.Fatalf("excluded: %+v %v", a, err)
	}
	if a, err := serve(t, 404, `not found`).PolicyCheck("x"); err != nil || a.Excluded || !a.Absent {
		t.Fatalf("404 is the feature absent: %+v %v", a, err)
	}
	if a, err := serve(t, 401, `{"error":"invalid license"}`).PolicyCheck("x"); err != nil || a.Excluded {
		t.Fatalf("a bad key is the review's to report: %+v %v", a, err)
	}
}

func TestAPIServerFaultIsAnError(t *testing.T) {
	if _, err := serve(t, 503, `{"error":"down"}`).PolicyCheck("x"); err == nil {
		t.Fatal("a 5xx means the check couldn't be made")
	}
}

type stub struct {
	answers map[string]Answer
	err     error
	calls   int
}

func (s *stub) PolicyCheck(repo string) (Answer, error) {
	s.calls++
	return s.answers[repo], s.err
}

func TestCheckCachesPerLicenseAndRepo(t *testing.T) {
	t.Cleanup(scratch.SetUserCacheDirForTest(t.TempDir()))
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	s := &stub{answers: map[string]Answer{"github.com/a/x": {Excluded: true, Reason: "github.com/a/*"}}}
	if r := Check(s, "k1", []string{"github.com/a/ok", "github.com/a/x"}, now); !r.Skip || r.NoticeID != NoticeExcluded || r.Notice != DefaultExcludedNotice {
		t.Fatalf("%+v", r)
	}
	if Check(s, "k1", []string{"github.com/a/x"}, now.Add(5*time.Minute)); s.calls != 2 {
		t.Fatalf("cached within ten minutes: %d calls", s.calls)
	}
	Check(s, "k1", []string{"github.com/a/x"}, now.Add(11*time.Minute))
	Check(s, "k2", []string{"github.com/a/x"}, now.Add(11*time.Minute))
	if s.calls != 4 {
		t.Fatalf("expired, and another license, ask again: %d calls", s.calls)
	}
	if r := Check(nil, "k", nil, now); r.Skip {
		t.Fatal("no checker never skips")
	}
}

func TestAPIReadsHasExclusions(t *testing.T) {
	a, err := serve(t, 200, `{"excluded":false,"has_exclusions":true,"unchecked_notice":{"id":"policy_unchecked","message":"server copy"}}`).PolicyCheck("x")
	if err != nil || !a.HasExclusions || a.UncheckedNotice == nil || a.UncheckedNotice.Message != "server copy" {
		t.Fatalf("%+v %v", a, err)
	}
	if a, _ := serve(t, 401, `{"error":"invalid license"}`).PolicyCheck("x"); !a.NoVerdict || a.Absent {
		t.Fatalf("a bad key says nothing about exclusions: %+v", a)
	}
}

func TestFailureWithKnownExclusionsSkips(t *testing.T) {
	t.Cleanup(scratch.SetUserCacheDirForTest(t.TempDir()))
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	s := &stub{answers: map[string]Answer{"github.com/a/ok": {HasExclusions: true,
		UncheckedNotice: &wire.ServerNotice{ID: NoticeUnchecked, Message: "server copy: unchecked"}}}}
	if r := Check(s, "k", []string{"github.com/a/ok"}, now); r.Skip {
		t.Fatalf("not excluded: %+v", r)
	}
	s.err = errors.New("timeout")
	r := Check(s, "k", []string{"github.com/a/other"}, now.Add(time.Minute))
	if !r.Skip || r.NoticeID != NoticeUnchecked || r.Notice != "server copy: unchecked" {
		t.Fatalf("a license known to exclude something skips when it can't check: %+v", r)
	}
}

func TestFailureWithNoKnownExclusionsProceeds(t *testing.T) {
	t.Cleanup(scratch.SetUserCacheDirForTest(t.TempDir()))
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	s := &stub{err: errors.New("timeout")}
	if r := Check(s, "unknown", []string{"github.com/a/x"}, now); r.Skip || r.Unchecked == "" {
		t.Fatalf("an unknown license fails open, and says why for the log: %+v", r)
	}
	s.err = nil
	s.answers = map[string]Answer{"github.com/a/y": {HasExclusions: false}}
	Check(s, "none", []string{"github.com/a/y"}, now)
	s.err = errors.New("503")
	if r := Check(s, "none", []string{"github.com/a/z"}, now.Add(time.Minute)); r.Skip {
		t.Fatalf("a license with no exclusions fails open: %+v", r)
	}
	// Learned exclusions, then the Org drops them: the next answer clears the memory.
	s.err = nil
	s.answers = map[string]Answer{"github.com/a/1": {HasExclusions: true}, "github.com/a/2": {}}
	Check(s, "was", []string{"github.com/a/1"}, now)
	Check(s, "was", []string{"github.com/a/2"}, now)
	s.err = errors.New("503")
	if r := Check(s, "was", []string{"github.com/a/3"}, now); r.Skip {
		t.Fatalf("the last answer wins: %+v", r)
	}
}

func TestAbsentRecordsNoExclusions(t *testing.T) {
	t.Cleanup(scratch.SetUserCacheDirForTest(t.TempDir()))
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	s := &stub{answers: map[string]Answer{"github.com/a/1": {HasExclusions: true}, "github.com/a/2": {Absent: true}}}
	Check(s, "k", []string{"github.com/a/1"}, now)
	if r := Check(s, "k", []string{"github.com/a/2"}, now); r.Skip {
		t.Fatalf("404 is not excluded: %+v", r)
	}
	s.err = errors.New("timeout")
	if r := Check(s, "k", []string{"github.com/a/3"}, now); r.Skip {
		t.Fatalf("404 recorded has_exclusions=false: %+v", r)
	}
}

func TestNoVerdictKeepsTheMemory(t *testing.T) {
	t.Cleanup(scratch.SetUserCacheDirForTest(t.TempDir()))
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	s := &stub{answers: map[string]Answer{"github.com/a/1": {HasExclusions: true}, "github.com/a/2": {NoVerdict: true}}}
	Check(s, "k", []string{"github.com/a/1"}, now)
	Check(s, "k", []string{"github.com/a/2"}, now)
	s.err = errors.New("timeout")
	if r := Check(s, "k", []string{"github.com/a/3"}, now); !r.Skip {
		t.Fatalf("a 401 doesn't forget the exclusions: %+v", r)
	}
}

func TestFailureIsCachedBriefly(t *testing.T) {
	t.Cleanup(scratch.SetUserCacheDirForTest(t.TempDir()))
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	s := &stub{err: errors.New("timeout")}
	Check(s, "k", []string{"github.com/a/x"}, now)
	if r := Check(s, "k", []string{"github.com/a/x", "github.com/a/y"}, now.Add(30*time.Second)); s.calls != 1 || r.Skip || r.Unchecked == "" {
		t.Fatalf("a failure is reused within FailTTL, never re-asked: calls=%d %+v", s.calls, r)
	}
	if Check(s, "other", []string{"github.com/a/x"}, now.Add(30*time.Second)); s.calls != 2 {
		t.Fatalf("per license: calls=%d", s.calls)
	}
	s.err = nil
	Check(s, "k", []string{"github.com/a/x"}, now.Add(FailTTL))
	if s.calls != 3 {
		t.Fatalf("asked again once FailTTL passes: calls=%d", s.calls)
	}
	s.err = errors.New("timeout")
	Check(s, "k", []string{"github.com/a/y"}, now.Add(FailTTL+time.Second))
	if s.calls != 4 {
		t.Fatalf("a success clears the remembered failure: calls=%d", s.calls)
	}
}
