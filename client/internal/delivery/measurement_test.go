package delivery

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/apiclient"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/receipts"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/scratch"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/config"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
	"github.com/leotrace-hq/leoprevent-plugin/limits"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

func TestReviewQueuesReceiptWithoutAnotherNetworkRequest(t *testing.T) {
	t.Cleanup(scratch.SetUserCacheDirForTest(t.TempDir()))
	calls := 0
	var delivered []wire.ReviewReceiptEnvelope
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path == "/review" {
			if r.Header.Get(wire.ReviewReceiptsHeader) != "" {
				t.Error("receipt cannot exist until review completes")
			}
			json.NewEncoder(w).Encode(wire.ReviewResponse{ReviewID: "0123456789abcdef01234567", Verdict: wire.VerdictClean})
			return
		}
		if r.URL.Path != "/telemetry" {
			t.Errorf("unexpected extra request: %s", r.URL.Path)
		}
		delivered = wire.DecodeReviewReceipts(r.Header.Get(wire.ReviewReceiptsHeader))
		if len(delivered) == 1 {
			w.Header().Set(wire.ReviewReceiptsAckHeader, delivered[0].Receipt.ID)
		}
		w.WriteHeader(202)
	}))
	defer srv.Close()
	h, err := New(&config.Config{Tier: config.TierCloud, ServerURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	_, err = h.Review("", []transcript.Change{{FilePath: "a.go", AddedText: "package main"}}, wire.TurnMeta{Repo: "github.com/acme/app", Prompt: "private", InputTokens: 999}, "")
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("review made %d requests", calls)
	}
	scope := receipts.Scope(srv.URL, "")
	if len(receipts.Batch(scope, time.Now())) != 1 {
		t.Fatal("receipt was not saved")
	}
	// A fresh client represents the next hook process; a real no-review turn carries it.
	if err := apiclient.New(srv.URL, "").Telemetry(wire.TelemetryRequest{Reason: "no_change"}); err != nil {
		t.Fatal(err)
	}
	if calls != 2 || len(delivered) != 1 || !delivered[0].Receipt.Succeeded || len(delivered[0].Receipt.ReviewIDs) != 1 {
		t.Fatalf("calls=%d delivered=%+v", calls, delivered)
	}
	b, _ := json.Marshal(delivered)
	if strings.Contains(string(b), "private") || strings.Contains(string(b), "input_tokens") {
		t.Fatal("receipt duplicated turn metadata")
	}
	if len(receipts.Batch(scope, time.Now())) != 0 {
		t.Fatal("acknowledged receipt retained")
	}
}

func TestOlderServerReceivesOnlyRealTurnsAndKeepsUnacknowledgedReceipt(t *testing.T) {
	t.Cleanup(scratch.SetUserCacheDirForTest(t.TempDir()))
	reviews, turns := 0, 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/review":
			reviews++
			json.NewEncoder(w).Encode(wire.ReviewResponse{Verdict: wire.VerdictClean})
		case "/telemetry":
			var req wire.TelemetryRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Error(err)
			}
			if req.Reason != "no_change" {
				t.Error("phantom turn")
			}
			turns++
			w.WriteHeader(202)
		default:
			t.Errorf("extra request: %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	h, err := New(&config.Config{Tier: config.TierCloud, ServerURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.Review("", []transcript.Change{{FilePath: "a.go", AddedText: "package main"}}, wire.TurnMeta{}, ""); err != nil {
		t.Fatal(err)
	}
	if reviews != 1 || turns != 0 {
		t.Fatal("review emitted a phantom turn")
	}
	if err := apiclient.New(srv.URL, "").Telemetry(wire.TelemetryRequest{Reason: "no_change"}); err != nil {
		t.Fatal(err)
	}
	if reviews != 1 || turns != 1 || len(receipts.Batch(receipts.Scope(srv.URL, ""), time.Now())) != 1 {
		t.Fatal("old-server acknowledgment or turn behavior changed")
	}
}

func TestCloudBatchReceiptsKeepRetriesAndFailedAttempts(t *testing.T) {
	t.Cleanup(scratch.SetUserCacheDirForTest(t.TempDir()))
	for _, failSecond := range []bool{false, true} {
		t.Run(map[bool]string{false: "retry succeeds", true: "second batch fails"}[failSecond], func(t *testing.T) {
			t.Setenv("LEOPREVENT_AUDIT", "0")
			var requests []wire.ReviewRequest
			var receipt wire.ReviewReceiptEnvelope
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/telemetry" {
					entries := wire.DecodeReviewReceipts(r.Header.Get(wire.ReviewReceiptsHeader))
					if len(entries) != 1 {
						t.Errorf("receipts=%d", len(entries))
					} else {
						receipt = entries[0]
					}
					w.WriteHeader(202)
					return
				}
				var req wire.ReviewRequest
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					t.Error(err)
				}
				requests = append(requests, req)
				if len(requests) == 2 {
					if failSecond {
						w.WriteHeader(402)
					} else {
						w.WriteHeader(503)
					}
					w.Write([]byte(`{"error":"synthetic failure"}`))
					return
				}
				json.NewEncoder(w).Encode(wire.ReviewResponse{ReviewID: req.ReviewID, Verdict: wire.VerdictClean})
			}))
			defer srv.Close()
			h, err := New(&config.Config{Tier: config.TierCloud, ServerURL: srv.URL})
			if err != nil {
				t.Fatal(err)
			}
			big := strings.Repeat("x", limits.MaxReviewBytes/2+1024)
			_, err = h.Review("", []transcript.Change{{FilePath: "a.go", AddedText: big}, {FilePath: "b.go", AddedText: big}}, wire.TurnMeta{}, "")
			if (err != nil) != failSecond {
				t.Fatalf("review error: %v", err)
			}
			want := 3
			if failSecond {
				want = 2
			}
			if len(requests) != want {
				t.Fatalf("requests = %d, want %d", len(requests), want)
			}
			first, second := requests[0].ReviewID, requests[1].ReviewID
			if len(first) != 24 || len(second) != 24 || first == second {
				t.Fatalf("invalid batch identities: %q %q", first, second)
			}
			if !failSecond && requests[2].ReviewID != second {
				t.Fatal("retry changed batch identity")
			}
			if requests[1].Meta.ContinuesReviewID != first {
				t.Fatal("continuation lost head")
			}
			if err := apiclient.New(srv.URL, "").Telemetry(wire.TelemetryRequest{Reason: "no_change"}); err != nil {
				t.Fatal(err)
			}
			r := receipt.Receipt
			if len(r.ReviewIDs) != 2 || r.ReviewIDs[0] != first || r.ReviewIDs[1] != second || r.Succeeded == failSecond {
				t.Fatalf("incorrect receipt: %+v", r)
			}
		})
	}
}

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "delivery-tests-")
	if err != nil {
		panic(err)
	}
	restore := scratch.SetUserCacheDirForTest(dir)
	code := m.Run()
	restore()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func TestQueueFailureNeverChangesReview(t *testing.T) {
	t.Cleanup(scratch.SetUserCacheDirForTest(t.TempDir()))
	// A regular file makes the queue directory unusable without changing permissions.
	if err := os.WriteFile(scratch.Dir("review-receipts"), []byte("unavailable"), 0600); err != nil {
		t.Fatal(err)
	}
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		json.NewEncoder(w).Encode(wire.ReviewResponse{Verdict: wire.VerdictClean})
	}))
	defer srv.Close()
	h, err := New(&config.Config{Tier: config.TierCloud, ServerURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.Review("", []transcript.Change{{FilePath: "a.go", AddedText: "package main"}}, wire.TurnMeta{}, ""); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatal("queue failure added a network request")
	}
}

func TestReceiptDistinguishesRefusalsFromFailures(t *testing.T) {
	t.Cleanup(scratch.SetUserCacheDirForTest(t.TempDir()))
	for status, reason := range map[int]string{401: "unauthorized", 403: "unauthorized", 402: "payment_required", 409: "policy_or_seat", 429: "rate_limited", 503: "server_error"} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
				w.Write([]byte(`{"error":"private response","retryable":false}`))
			}))
			defer srv.Close()
			h, err := New(&config.Config{Tier: config.TierCloud, ServerURL: srv.URL})
			if err != nil {
				t.Fatal(err)
			}
			if _, err = h.Review("", []transcript.Change{{FilePath: "a.go", AddedText: "package main"}}, wire.TurnMeta{}, ""); err == nil {
				t.Fatal("failure disappeared")
			}
			entries := receipts.Batch(receipts.Scope(srv.URL, ""), time.Now())
			if len(entries) != 1 || entries[0].Entry.Receipt.Succeeded || entries[0].Entry.Receipt.FailureReason != reason {
				t.Fatalf("incorrect failure receipt: %+v", entries)
			}
		})
	}
	if got := receiptFailureReason(classifyServerErr(context.DeadlineExceeded)); got != "timed_out" {
		t.Fatalf("timeout classified %q", got)
	}
}

func TestReviewAndTelemetryDoNotLogDeveloperIdentity(t *testing.T) {
	t.Cleanup(scratch.SetUserCacheDirForTest(t.TempDir()))
	t.Setenv("LEOPREVENT_AUDIT", "0")
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/telemetry" {
			w.WriteHeader(202)
			return
		}
		json.NewEncoder(w).Encode(wire.ReviewResponse{Verdict: wire.VerdictClean})
	}))
	defer srv.Close()
	reviewer, err := New(&config.Config{Tier: config.TierCloud, ServerURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	h := reviewer.(Cloud)
	meta := wire.TurnMeta{Developer: "Private Person <private@example.test>"}
	if _, err = h.Review("", []transcript.Change{{FilePath: "a.go", AddedText: "package main"}}, meta, ""); err != nil {
		t.Fatal(err)
	}
	if err = h.ShipTelemetry(meta, "no_change", 0); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(logs.String(), "Private Person") || strings.Contains(logs.String(), "private@example.test") {
		t.Fatalf("identity leaked: %s", logs.String())
	}
}
