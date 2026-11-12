package wire

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

const (
	ReviewReceiptsHeader    = "X-LeoPrevent-Review-Receipts"
	ReviewReceiptsAckHeader = "X-LeoPrevent-Review-Receipts-Ack"
	MaxReceiptHeaderBytes   = 6144
	MaxReceiptBatch         = 4
	ReceiptMaxAge           = 7 * 24 * time.Hour
)

// ReviewReceipt measures context resolution, batches, retries and response handling.
// CompletedAt is the client's observation time, distinct from eventual delivery.
type ReviewReceipt struct {
	ID            string    `json:"id"`
	ReviewIDs     []string  `json:"review_ids"`
	ElapsedMs     int64     `json:"elapsed_ms"`
	Succeeded     bool      `json:"succeeded"`
	FailureReason string    `json:"failure_reason,omitempty"`
	Lane          string    `json:"lane,omitempty"`
	CompletedAt   time.Time `json:"completed_at"`
}

// UnmarshalJSON keeps missing/null measurements distinct from explicit zero/false.
// The same check protects both the incoming header and locally cached receipts.
func (r *ReviewReceipt) UnmarshalJSON(data []byte) error {
	type plain ReviewReceipt
	var decoded struct {
		plain
		ElapsedMs *int64 `json:"elapsed_ms"`
		Succeeded *bool  `json:"succeeded"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	if decoded.ElapsedMs == nil || decoded.Succeeded == nil {
		return errors.New("receipt requires elapsed_ms and succeeded")
	}
	*r = ReviewReceipt(decoded.plain)
	r.ElapsedMs, r.Succeeded = *decoded.ElapsedMs, *decoded.Succeeded
	return nil
}

// ReviewReceiptEnvelope deliberately cannot hold code, prompts, credentials or agent usage.
type ReviewReceiptEnvelope struct {
	Repo          string        `json:"repo,omitempty"`
	ClientVersion string        `json:"client_version,omitempty"`
	Receipt       ReviewReceipt `json:"receipt"`
}

func ValidReviewReceipt(e ReviewReceiptEnvelope, now time.Time) bool {
	r := e.Receipt
	// Empty remains valid for clients predating failure classification. Do not persist
	// arbitrary error text or server notices supplied by a client.
	switch r.FailureReason {
	case "":
	case "unauthorized", "payment_required", "policy_or_seat", "rate_limited", "server_error", "request_rejected", "timed_out", "unreachable", "unknown":
		if r.Succeeded {
			return false
		}
	default:
		return false
	}
	validID := func(id string) bool { b, err := hex.DecodeString(id); return err == nil && len(b) == 12 }
	if !validID(r.ID) || len(r.ReviewIDs) > 100 || r.ElapsedMs < 0 || r.ElapsedMs > 86400000 || len(e.Repo) > 1024 || len(e.ClientVersion) > 128 || len(r.Lane) > 64 || r.CompletedAt.IsZero() || r.CompletedAt.Before(now.Add(-ReceiptMaxAge)) || r.CompletedAt.After(now.Add(5*time.Minute)) {
		return false
	}
	for _, id := range r.ReviewIDs {
		if !validID(id) {
			return false
		}
	}
	return true
}

// Headers carry a small batch alongside an existing request, never an extra request.
func EncodeReviewReceipts(entries []ReviewReceiptEnvelope) string {
	if len(entries) == 0 || len(entries) > MaxReceiptBatch {
		return ""
	}
	b, err := json.Marshal(entries)
	if err != nil {
		return ""
	}
	encoded := base64.RawURLEncoding.EncodeToString(b)
	if len(encoded) > MaxReceiptHeaderBytes {
		return ""
	}
	return encoded
}
func DecodeReviewReceipts(header string) []ReviewReceiptEnvelope {
	if header == "" || len(header) > MaxReceiptHeaderBytes {
		return nil
	}
	b, err := base64.RawURLEncoding.DecodeString(header)
	if err != nil {
		return nil
	}
	var raw []json.RawMessage
	if json.Unmarshal(b, &raw) != nil || len(raw) > MaxReceiptBatch {
		return nil
	}
	var entries []ReviewReceiptEnvelope
	for _, item := range raw {
		var entry ReviewReceiptEnvelope
		if json.Unmarshal(item, &entry) == nil {
			entries = append(entries, entry)
		}
	}
	return entries
}
