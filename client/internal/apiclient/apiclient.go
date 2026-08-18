// Package apiclient calls the leoprevent server endpoints (/review, /rules).
// Both calls sit on the Stop-hook hot path, so they carry timeouts; any
// transport or status error surfaces to the engine, which fails open.
package apiclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/leotrace-hq/leoprevent-plugin/buildinfo"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/outcome"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/update"
	"github.com/leotrace-hq/leoprevent-plugin/limits"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

// The request-side header we stamp is wire.ClientVersionHeader — shared with the
// server, which reads it when a body fails to decode. latestVersionHeader is what the
// server stamps back on every response — the latest client version it knows about —
// which drives the one-time update nag (see internal/update).
const latestVersionHeader = "X-LeoPrevent-Latest-Version"

// noteLatest records the latest-version header the server advertised, if any.
// Best-effort: it feeds the nag shown on the next UserPromptSubmit, never this call.
func noteLatest(resp *http.Response) {
	if v := resp.Header.Get(latestVersionHeader); v != "" {
		update.RecordLatest(v)
	}
}

// Client talks to one server base URL.
type Client struct {
	baseURL    string
	licenseKey string
	http       *http.Client
}

// New builds a client for the given base URL (trailing slash trimmed). licenseKey
// is the customer credential sent as a Bearer token on every request; an empty key
// sends no Authorization header (the server then rejects when auth is enabled, and
// the engine fails open).
func New(baseURL, licenseKey string) *Client {
	return &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		licenseKey: licenseKey,
		http:       &http.Client{},
	}
}

// StatusError is returned when the server is reached but replies with a non-200
// status. It carries the code so callers can classify the failure (401/403 = the
// license is missing/invalid/unentitled, 5xx = a server fault) for a precise
// developer-facing skip notice — without string-matching the error message.
// Transport failures (server down, DNS, timeout) are NOT StatusError; they surface
// as the wrapped net error from http.Client.Do.
type StatusError struct {
	Path   string
	Status int
	// Body is a bounded snippet of the server's response, the ONLY place it says WHY
	// it refused the call ("invalid request body: json: unknown field \"os\""). It used
	// to be closed unread, so a rejected payload surfaced on both sides as a bare
	// "status 400" and the cause had to be reverse-engineered by capturing a live
	// request and bisecting its fields. Empty when unreadable or absent.
	Body string
}

func (e *StatusError) Error() string {
	if e.Body == "" {
		return fmt.Sprintf("apiclient: POST %s: status %d", e.Path, e.Status)
	}
	return fmt.Sprintf("apiclient: POST %s: status %d: %s", e.Path, e.Status, e.Body)
}

// maxErrBodySnippet bounds what we keep of an error body: plenty for a server error
// string, never enough for an upstream proxy's HTML error page to flood the hook log.
const maxErrBodySnippet = 512

// errBodySnippet reads a bounded, single-line snippet of a non-2xx response body. It
// does not close the body — the caller owns that, as before.
func errBodySnippet(resp *http.Response) string {
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxErrBodySnippet))
	if err != nil {
		return ""
	}
	return strings.Join(strings.Fields(string(b)), " ")
}

// reviewTimeout is limits.ClientReviewDeadline — it exceeds the server's
// worst-case select+judge sum so a slow judge can't make the CLIENT cancel mid-call
// and silently skip the review, and stays under the 600s Stop-hook timeout so the
// hook fails open last. The ordering invariant is documented on the limits package.
const reviewTimeout = limits.ClientReviewDeadline

// rulesTimeout is short: /rules just serves content.
const rulesTimeout = 10 * time.Second

// enrollTimeout is short for the same reason the review deadline is generous: enrolment does no
// model work, just a handful of indexed writes, and it sits on the developer's Stop path. A slow
// enrolment must cost the turn its review rather than the developer's patience.
const enrollTimeout = 10 * time.Second

// outcomeTimeout bounds the SYNCHRONOUS /outcome re-verify at the post-fix Stop: the
// server re-judges the agent's fix and returns the verdict so the client can warn the
// developer in-turn. The dev DOES wait here — but only on a blocked-and-fixed turn,
// and only up to this deadline, past which the client fails open (allow the stop, no
// notice). Sized at limits.OutcomeVerifyDeadline (< the Stop-hook timeout).
const outcomeTimeout = limits.OutcomeVerifyDeadline

// telemetryTimeout matches outcomeTimeout: /telemetry is fire-and-forget on a
// no-review Stop where the developer must NOT wait. The server just appends one
// audit record and 202s. Slow/unreachable → timeout → engine logs and ignores.
const telemetryTimeout = 5 * time.Second

// Review posts the changed code (+ optional cross-file imported context + the
// coding agent's turn metadata) to /review (cloud tier) and returns the verdict and
// findings. Rules never come back — only findings.
func (c *Client) Review(changes []wire.ChangedFile, context []wire.ContextFile, meta wire.TurnMeta) (wire.ReviewResponse, error) {
	var out wire.ReviewResponse
	err := c.post("/review", reviewTimeout, wire.ReviewRequest{Changes: changes, Context: context, Meta: meta}, &out)
	return out, err
}

// Enroll exchanges an organisation enrolment token for this machine's own per-user license key.
//
// ⚠️ IT DOES NOT USE c.licenseKey, AND THAT IS THE WHOLE POINT: this is the call a machine makes
// when it has no license key yet, so the Authorization header carries the ENROLMENT token instead.
// A client built with an empty license key can still make this one call.
//
// Bounded by enrollTimeout and returns a plain error on any non-200, so the caller can fail open
// the way the rest of this client does: an enrolment that does not work costs a turn its review,
// never the developer's session.
func (c *Client) Enroll(token string, req wire.EnrollRequest) (wire.EnrollResponse, error) {
	var out wire.EnrollResponse
	payload, err := json.Marshal(req)
	if err != nil {
		return out, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), enrollTimeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/enroll", bytes.NewReader(payload))
	if err != nil {
		return out, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return out, fmt.Errorf("apiclient: POST /enroll: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		// The body is deliberately uninformative — the server answers every refusal identically —
		// so there is nothing to unpack: the status is the whole answer.
		return out, fmt.Errorf("apiclient: POST /enroll: status %d", resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return out, fmt.Errorf("apiclient: POST /enroll: decode: %w", err)
	}
	if out.LicenseKey == "" {
		return out, fmt.Errorf("apiclient: POST /enroll: the response carried no key")
	}
	return out, nil
}

// Rules posts rule IDs to /rules (local tier) and returns their content plus
// the meta-policy. No code is ever sent.
func (c *Client) Rules(ids []string) (wire.RulesResponse, error) {
	var out wire.RulesResponse
	err := c.post("/rules", rulesTimeout, wire.RulesRequest{IDs: ids}, &out)
	return out, err
}

// Outcome posts the agent's fix to /outcome and waits for the SYNCHRONOUS re-verify
// (bounded by outcomeTimeout = OutcomeVerifyDeadline; fail-open past it). The server
// re-judges and returns the introduced findings still firing, so the caller can warn
// the developer in-turn. A response the server did NOT actually re-judge — the 202
// capacity skip, or a 200 whose Scored flag is false (nil model / rules missing /
// re-judge failure) — surfaces as an error wrapping outcome.ErrUnscored: its EMPTY
// still-firing lists mean "no verdict", and returning them with a nil error is
// indistinguishable from a genuinely clean re-judge (the caller would falsely credit
// every carried finding as resolved). Any transport error is returned for the engine
// to log + fail open.
func (c *Client) Outcome(req wire.OutcomeRequest) (wire.OutcomeResponse, error) {
	var out wire.OutcomeResponse
	payload, err := json.Marshal(req)
	if err != nil {
		return out, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), outcomeTimeout)
	defer cancel()
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/outcome", bytes.NewReader(payload))
	if err != nil {
		return out, err
	}
	httpReq.Header.Set("content-type", "application/json")
	httpReq.Header.Set(wire.ClientVersionHeader, buildinfo.Version)
	if c.licenseKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.licenseKey)
	}
	resp, err := c.http.Do(httpReq)
	if err != nil {
		return out, fmt.Errorf("apiclient: POST /outcome: %w", err)
	}
	defer resp.Body.Close()
	noteLatest(resp)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return out, fmt.Errorf("apiclient: POST /outcome: status %d: %s", resp.StatusCode, errBodySnippet(resp))
	}
	_ = json.NewDecoder(resp.Body).Decode(&out) // verdict; empty on a 202/skip
	if !out.Scored {
		// No verdict was produced (capacity skip, re-judge failure, garbled body — or
		// an old server that predates the flag). Distinct sentinel so callers can tell
		// "re-judged and clean" from "never judged" via errors.Is.
		return out, fmt.Errorf("apiclient: POST /outcome: %w", outcome.ErrUnscored)
	}
	return out, nil
}

// Telemetry posts the coding agent's turn metadata for a NO-REVIEW turn to
// /telemetry (cloud tier). Like Outcome it is fire-and-forget: the server appends
// one audit record and replies 202, so we only wait for the enqueue, never for any
// processing. The body is discarded; only delivery matters. Any error is returned
// for the engine to log and ignore — telemetry never traps the developer.
func (c *Client) Telemetry(req wire.TelemetryRequest) error {
	payload, err := json.Marshal(req)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), telemetryTimeout)
	defer cancel()
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/telemetry", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	httpReq.Header.Set("content-type", "application/json")
	httpReq.Header.Set(wire.ClientVersionHeader, buildinfo.Version)
	if c.licenseKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.licenseKey)
	}
	resp, err := c.http.Do(httpReq)
	if err != nil {
		return fmt.Errorf("apiclient: POST /telemetry: %w", err)
	}
	defer resp.Body.Close()
	noteLatest(resp)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("apiclient: POST /telemetry: status %d: %s", resp.StatusCode, errBodySnippet(resp))
	}
	return nil
}

// postBackoffs are the waits between transient-failure retries (3 attempts total).
// Short and few by design: every retry holds the developer's Stop hook, so the sum
// must stay a small fraction of the call's deadline. Var, not const, so tests can
// shrink them.
var postBackoffs = []time.Duration{time.Second, 3 * time.Second}

func (c *Client) post(path string, timeout time.Duration, body, out any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// TRANSIENT failures — a network blip, 429, or 5xx — are retried with short
	// backoff inside the SAME deadline. Before this, a single dropped connection
	// meant the whole review silently failed open (an unreviewed turn): the Tasos
	// 20_ run recorded 41 network + 5 rate-limit + 2 server errors, all instant
	// fail-opens a 1s retry would likely have recovered. Non-retryable statuses
	// (401/403/4xx) still return immediately — retrying can't fix a bad license.
	var lastErr error
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(payload))
		if err != nil {
			return err
		}
		req.Header.Set("content-type", "application/json")
		req.Header.Set(wire.ClientVersionHeader, buildinfo.Version)
		if c.licenseKey != "" {
			req.Header.Set("Authorization", "Bearer "+c.licenseKey)
		}

		resp, err := c.http.Do(req)
		switch {
		case err != nil:
			lastErr = fmt.Errorf("apiclient: POST %s: %w", path, err)
			if ctx.Err() != nil {
				return lastErr // deadline spent — a retry can only time out again
			}
		case resp.StatusCode == http.StatusOK:
			defer resp.Body.Close()
			noteLatest(resp)
			if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
				return fmt.Errorf("apiclient: decode %s: %w", path, err)
			}
			return nil
		default:
			// Snapshot the body BEFORE closing — it carries the server's reason.
			lastErr = &StatusError{Path: path, Status: resp.StatusCode, Body: errBodySnippet(resp)}
			resp.Body.Close()
			if resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode < 500 {
				return lastErr
			}
		}

		if attempt >= len(postBackoffs) {
			return lastErr
		}
		select {
		case <-time.After(postBackoffs[attempt]):
		case <-ctx.Done():
			return lastErr
		}
	}
}
