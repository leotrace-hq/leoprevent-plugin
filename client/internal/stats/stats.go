// Package stats reads the developer's own LeoPrevent figures from the customer
// dashboard's agent API (GET /api/agent), for the `mcp` subcommand to serve.
//
// ⚠️ A DIFFERENT HOST FROM THE REVIEW SERVER, AND IT HAS TO BE. `apiclient` talks to the
// Go server, which judges code; the dashboard is a separate Next.js deployment that reads
// MongoDB directly and never calls the Go server (see CLAUDE.md — that separation is what
// let the Fly stack be decommissioned without the dashboards caring). The metric math lives
// in TypeScript there and exists nowhere else, so a stats read has to go to the dashboard;
// there is no Go endpoint that could answer it and adding one would be a second, drifting
// implementation of every number.
//
// SAME CREDENTIAL, THOUGH: the per-user license key the hook already authenticates with,
// sent as a Bearer token. So the developer configures nothing beyond what the review loop
// needed — which is the point of putting the MCP server in this binary at all.
//
// ⚠️ IT NEVER SENDS CODE. The requests carry a view name and a few bounded filters; the
// egress is the license key and nothing else. That keeps agent read access outside the
// tier-dependent egress statement in CLAUDE.md entirely: it adds a read, not a disclosure.
//
// This package returns the dashboard's JSON body VERBATIM as bytes rather than decoding it
// into Go structs. The shapes are defined once, in TypeScript, by the app that computes
// them; mirroring them here would be a second copy that goes stale silently — a new field
// would simply vanish from the tool result with nothing failing. The MCP layer hands the
// body to the agent, which reads JSON perfectly well.
package stats

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/leotrace-hq/leoprevent-plugin/buildinfo"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

// readTimeout bounds one stats call.
//
// The dashboard aggregates a tenant's window in process, which on the production log is
// under a second — but this sits on an agent's tool call, where the developer is watching a
// spinner, so it is generous enough to survive a cold Vercel function and no more.
const readTimeout = 20 * time.Second

// maxBody bounds what we read back. The API clamps its own row counts, so this is a
// backstop against a proxy's error page rather than against the real endpoint: a tool
// result is going into a context window the developer pays for.
const maxBody = 512 << 10

// Client reads one dashboard deployment.
type Client struct {
	baseURL    string
	licenseKey string
	http       *http.Client
}

// New builds a client for a dashboard origin (trailing slash trimmed).
func New(baseURL, licenseKey string) *Client {
	return &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		licenseKey: licenseKey,
		http:       &http.Client{},
	}
}

// Error is a non-2xx from the dashboard, carrying the message it gave.
//
// The message is surfaced to the agent verbatim because every one of them is actionable by
// the developer reading it — "that license key is not recognised", "generate a personal key
// in the dashboard under Plugin setup". A tool that answered "request failed" would leave
// them with a broken feature and nowhere to go, which for a fail-open product is the
// familiar failure worth avoiding.
type Error struct {
	Status  int
	Message string
}

func (e *Error) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("stats: status %d", e.Status)
	}
	return e.Message
}

// Query names one read. Empty fields are omitted from the request.
type Query struct {
	View  string
	Scope string
	Days  int
	Repo  string
	Rule  string
	Limit int
}

// Read fetches one view and returns the dashboard's JSON body.
func (c *Client) Read(q Query) ([]byte, error) {
	if c.baseURL == "" {
		return nil, fmt.Errorf("stats: no dashboard_url configured")
	}

	params := url.Values{}
	params.Set("view", q.View)
	if q.Scope != "" {
		params.Set("scope", q.Scope)
	}
	if q.Days > 0 {
		params.Set("days", fmt.Sprint(q.Days))
	}
	if q.Repo != "" {
		params.Set("repo", q.Repo)
	}
	if q.Rule != "" {
		params.Set("rule", q.Rule)
	}
	if q.Limit > 0 {
		params.Set("limit", fmt.Sprint(q.Limit))
	}

	ctx, cancel := context.WithTimeout(context.Background(), readTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/agent?"+params.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	// The same header the review calls stamp, so a stats read is attributable to a build in
	// the dashboard's own request log without a second convention.
	req.Header.Set(wire.ClientVersionHeader, buildinfo.Version)
	if c.licenseKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.licenseKey)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("stats: GET /api/agent: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, fmt.Errorf("stats: GET /api/agent: read: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &Error{Status: resp.StatusCode, Message: errMessage(body, resp.StatusCode)}
	}
	return body, nil
}

// errMessage pulls the API's `error` field out of a refusal body.
//
// Falls back to a status line when the body is not ours — an edge proxy or a WAF answers in
// HTML, and echoing that into an agent's context helps nobody.
func errMessage(body []byte, status int) string {
	var e struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &e); err == nil && e.Error != "" {
		return e.Error
	}
	return fmt.Sprintf("the dashboard refused the request (HTTP %d)", status)
}
