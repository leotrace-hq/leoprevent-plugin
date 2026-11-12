package apiclient

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/receipts"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/scratch"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

func TestReceiptsRetryUntilAcknowledgedOnNextExistingCall(t *testing.T) {
	t.Cleanup(scratch.SetUserCacheDirForTest(t.TempDir()))
	calls := 0
	var id string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		entries := wire.DecodeReviewReceipts(r.Header.Get(wire.ReviewReceiptsHeader))
		if len(entries) != 1 {
			t.Errorf("receipts=%d", len(entries))
			return
		}
		if id != "" && id != entries[0].Receipt.ID {
			t.Error("retry minted a new receipt")
		}
		id = entries[0].Receipt.ID
		if calls == 1 {
			w.WriteHeader(503)
			return
		}
		w.Header().Set(wire.ReviewReceiptsAckHeader, id)
		w.Write([]byte(`{"scored":true}`))
	}))
	defer srv.Close()
	c := New(srv.URL, "key")
	if err := c.QueueReviewReceipt("github.com/acme/app", wire.ReviewReceipt{ElapsedMs: 12}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Outcome(wire.OutcomeRequest{}); err != nil {
		t.Fatal(err)
	}
	if calls != 2 || len(receipts.Batch(receipts.Scope(srv.URL, "key"), time.Now())) != 0 {
		t.Fatal("retry/ack behavior")
	}
}

func TestReceiptUsesEarliestCallAndSurvivesOldServer(t *testing.T) {
	t.Cleanup(scratch.SetUserCacheDirForTest(t.TempDir()))
	supported := false
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/policy/check" {
			t.Errorf("earliest call=%s", r.URL.Path)
		}
		entries := wire.DecodeReviewReceipts(r.Header.Get(wire.ReviewReceiptsHeader))
		if len(entries) != 1 {
			t.Errorf("entries=%d", len(entries))
			return
		}
		if supported {
			w.Header().Set(wire.ReviewReceiptsAckHeader, entries[0].Receipt.ID)
		}
		json.NewEncoder(w).Encode(wire.PolicyCheckResponse{})
	}))
	defer srv.Close()
	c := New(srv.URL, "key")
	if err := c.QueueReviewReceipt("repo", wire.ReviewReceipt{}); err != nil {
		t.Fatal(err)
	}
	if _, err := New(srv.URL, "key").PolicyCheck(wire.PolicyCheckRequest{}); err != nil {
		t.Fatal(err)
	}
	if len(receipts.Batch(receipts.Scope(srv.URL, "key"), time.Now())) != 1 {
		t.Fatal("old server cleared queue")
	}
	supported = true
	if _, err := New(srv.URL, "key").PolicyCheck(wire.PolicyCheckRequest{}); err != nil {
		t.Fatal(err)
	}
	if calls != 2 || len(receipts.Batch(receipts.Scope(srv.URL, "key"), time.Now())) != 0 {
		t.Fatal("new server did not acknowledge")
	}
}

func TestReceiptDoesNotFollowRedirectOrEnrollmentOrLocalTier(t *testing.T) {
	t.Cleanup(scratch.SetUserCacheDirForTest(t.TempDir()))
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(wire.ReviewReceiptsHeader) != "" {
			t.Error("receipt followed redirect")
		}
		w.WriteHeader(202)
	}))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/rules" {
			if r.Header.Get(wire.ReviewReceiptsHeader) != "" {
				t.Error("receipt leaked through local tier")
			}
			w.Write([]byte(`{}`))
			return
		}
		if r.URL.Path == "/enroll" {
			if r.Header.Get(wire.ReviewReceiptsHeader) != "" {
				t.Error("receipt used enrollment credential")
			}
			w.Write([]byte(`{"license_key":"new-key"}`))
			return
		}
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	c := New(source.URL, "key")
	if err := c.QueueReviewReceipt("repo", wire.ReviewReceipt{}); err != nil {
		t.Fatal(err)
	}
	if err := c.Telemetry(wire.TelemetryRequest{}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Enroll("enrollment", wire.EnrollRequest{}); err != nil {
		t.Fatal(err)
	}
	if err := c.post("/rules", time.Second, wire.RulesRequest{}, &wire.RulesResponse{}); err != nil {
		t.Fatal(err)
	}
	if len(receipts.Batch(receipts.Scope(source.URL, "key"), time.Now())) != 1 {
		t.Fatal("redirect or enrollment cleared queue")
	}
}

func TestReceiptRedirectStillHasDefaultHopLimit(t *testing.T) {
	t.Cleanup(scratch.SetUserCacheDirForTest(t.TempDir()))
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls > 1 && r.Header.Get(wire.ReviewReceiptsHeader) != "" {
			t.Error("receipt survived redirect")
		}
		http.Redirect(w, r, "/again", http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	c := New(srv.URL, "key")
	if err := c.QueueReviewReceipt("repo", wire.ReviewReceipt{}); err != nil {
		t.Fatal(err)
	}
	if err := c.Telemetry(wire.TelemetryRequest{}); err == nil || !strings.Contains(err.Error(), "stopped after 10 redirects") {
		t.Fatalf("redirect limit lost: %v", err)
	}
	if calls != 10 {
		t.Fatalf("requests=%d", calls)
	}
	if len(receipts.Batch(receipts.Scope(srv.URL, "key"), time.Now())) != 1 {
		t.Fatal("redirect cleared queue")
	}
}
