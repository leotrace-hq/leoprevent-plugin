package apiclient

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"time"

	"github.com/leotrace-hq/leoprevent-plugin/buildinfo"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/receipts"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

// QueueReviewReceipt does local I/O only. The next existing request carries it,
// potentially later in this hook, or from a fresh process on the next turn.
func (c *Client) QueueReviewReceipt(repo string, receipt wire.ReviewReceipt) error {
	var id [12]byte
	if _, err := rand.Read(id[:]); err != nil {
		return err
	}
	receipt.ID = hex.EncodeToString(id[:])
	receipt.CompletedAt = time.Now().UTC()
	e := wire.ReviewReceiptEnvelope{Repo: repo, ClientVersion: buildinfo.Version, Receipt: receipt}
	return receipts.Save(receipts.Scope(c.baseURL, c.licenseKey), e, time.Now())
}

func (c *Client) doWithReceipts(req *http.Request) (*http.Response, error) {
	// The retired local tier must not gain cloud measurement egress if its client is reused.
	if req.URL.Path == "/rules" {
		return c.http.Do(req)
	}
	pending := receipts.Batch(receipts.Scope(c.baseURL, c.licenseKey), time.Now())
	if len(pending) == 0 {
		return c.http.Do(req)
	}
	entries := make([]wire.ReviewReceiptEnvelope, 0, len(pending))
	for _, p := range pending {
		entries = append(entries, p.Entry)
	}
	header := wire.EncodeReviewReceipts(entries)
	req.Header.Set(wire.ReviewReceiptsHeader, header)
	// Custom metadata headers must not follow redirects to a different recipient.
	// Drop them on every redirect, including same-origin redirects, and retain the queue.
	client := *c.http
	previous := client.CheckRedirect
	client.CheckRedirect = func(next *http.Request, via []*http.Request) error {
		next.Header.Del(wire.ReviewReceiptsHeader)
		if previous != nil {
			return previous(next, via)
		}
		// net/http stops using its default redirect limit when CheckRedirect is set.
		// Returning nil here unconditionally would allow an endless redirect chain.
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		return nil
	}
	resp, err := client.Do(req)
	// Keep the origin check as defense in depth for custom transports/callbacks.
	if err == nil && resp != nil && resp.Request != nil && resp.Request.Header.Get(wire.ReviewReceiptsHeader) == header && resp.Request.URL.Host == req.URL.Host && resp.Request.URL.Scheme == req.URL.Scheme {
		receipts.Ack(pending, resp.Header.Get(wire.ReviewReceiptsAckHeader))
	}
	return resp, err
}
