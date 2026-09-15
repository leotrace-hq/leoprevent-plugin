// Package mcp serves the plugin's READ tools to a coding agent over the Model Context
// Protocol (LEO-88): stdio, JSON-RPC 2.0, newline-delimited.
//
// ⚠️ THIS IS THE PULL SIDE, AND IT IS ADDITIVE — IT IS NOT THE PRODUCT. `docs/design.md`
// explains at length why review is a Stop HOOK and not an MCP tool: MCP is pull, so the
// model chooses whether to call it, and the model that just wrote the bypassable guard is
// exactly the actor you cannot trust to remember. That argument is about ENFORCEMENT and is
// unchanged. What lands here is the case that doc already carved out as the one MCP could
// earn — serving knowledge on demand — narrowed to the developer's OWN figures, which are
// pull by nature: nobody needs to be forced to be told how their week went.
//
// So the rule for anything added here: a tool may REPORT. It may not review, judge, block,
// or be the thing that decides whether code is safe. The moment a tool here could substitute
// for the hook, the product's guarantee becomes "the model usually remembers".
//
// ⚠️ IT SERVES NO RULE CONTENT, and that constraint is the corpus-protection one, not a
// scope decision. The client ships no rules and the endpoints behind these tools return
// none: `rule_detail` answers with a rule's ID, TITLE and SEVERITY — the public CWE-shaped
// half the dashboard already shows — and never `look_for`, `does_not_apply_when` or a
// suggestion. Serving rule bodies to a cloud-tier machine is the one thing the whole tier
// split exists to prevent.
//
// FAIL SOFT, in the same spirit as the hook's fail-open. A tool that cannot answer returns
// an MCP tool ERROR with a readable message, so the agent tells the developer what is wrong
// and carries on; the server itself only exits when its stdin closes. It never writes to
// stdout except protocol messages — stdout IS the transport here, exactly as it is the
// re-wake channel on the hook path.
package mcp

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
)

// ProtocolVersion is what we answer `initialize` with when the client asks for something we
// do not recognise.
//
// The negotiation below echoes a version the client named IF it is one we have checked
// against, and otherwise answers with this. That matters because a client which cannot
// speak the version it is handed simply disconnects, and this server's whole surface —
// `tools/list` plus `tools/call` — is identical across every revision listed, so echoing is
// safe where guessing forward would not be.
const ProtocolVersion = "2025-06-18"

// knownProtocols are the revisions whose tools surface this server has been written
// against. A client asking for one of these gets it back verbatim.
var knownProtocols = map[string]bool{
	"2024-11-05": true,
	"2025-03-26": true,
	"2025-06-18": true,
	"2025-11-25": true,
}

// ServerName is how the server identifies itself. Claude Code namespaces a plugin's MCP
// tools by the key in `.mcp.json`, not by this, so it is descriptive rather than load
// bearing — but keeping the two the same is what makes a log line traceable to a config.
const ServerName = "leoprevent"

// JSON-RPC error codes, from the spec. Only the two this server can produce: everything
// else a caller can get wrong is answered as a tool ERROR instead — see callTool.
const (
	codeParse          = -32700
	codeMethodNotFound = -32601
)

// request is one incoming JSON-RPC message.
//
// `ID` is `json.RawMessage` because the spec permits a string OR a number and a response
// must echo it byte-identically; decoding it into either Go type would rewrite `1` as `1.0`
// for some clients. An ABSENT id means the message is a NOTIFICATION, which must not be
// answered at all — replying to one is the mistake that makes a client log a protocol error
// on every session.
type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Tool is one callable the server advertises.
//
// `Schema` is a JSON Schema object for the arguments. It is written by hand as a Go value
// rather than generated, because it is CONTENT: the descriptions are what an agent reads to
// decide whether to call the tool at all, and they are the difference between a tool that
// gets used and one that sits there.
type Tool struct {
	Name        string
	Description string
	Schema      map[string]any
}

// Handler answers one tool call. It returns the text to hand back, or an error whose
// message is shown to the agent.
type Handler func(name string, args map[string]any) (string, error)

// Server is one stdio session.
type Server struct {
	Tools   []Tool
	Call    Handler
	Version string
}

// Serve reads requests from in and writes responses to out until in closes.
//
// One JSON object per line, in both directions. Line-delimited rather than
// Content-Length-framed because that is what the MCP stdio transport specifies, and it is
// also what makes a session readable in a terminal when something goes wrong.
//
// ⚠️ A MALFORMED LINE DOES NOT END THE SESSION. It is answered with a parse error (when it
// is answerable at all) and the loop continues — an agent that emits one bad message must
// not lose its tools for the rest of the developer's session. Only a closed stdin, or a
// stdout we can no longer write to, stops it.
func (s *Server) Serve(in io.Reader, out io.Writer) error {
	scanner := bufio.NewScanner(in)
	// The default 64 KiB token cap is small for a tool-call message; MCP clients batch
	// nothing here, but an argument object is caller-controlled and a truncated line would
	// surface as a parse error the developer cannot act on.
	scanner.Buffer(make([]byte, 0, 64<<10), 4<<20)

	enc := json.NewEncoder(out)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(trimSpace(line)) == 0 {
			continue
		}

		var req request
		if err := json.Unmarshal(line, &req); err != nil {
			// No id could be recovered, so the spec's null-id parse error is the only honest
			// answer. Some clients ignore it; sending it is still better than silence.
			if werr := enc.Encode(response{
				JSONRPC: "2.0",
				ID:      json.RawMessage("null"),
				Error:   &rpcError{Code: codeParse, Message: "invalid JSON"},
			}); werr != nil {
				return werr
			}
			continue
		}

		// A notification (no id) gets NO response, whatever it asked for. `initialized` and
		// `notifications/cancelled` are the ones seen in practice.
		if len(req.ID) == 0 {
			continue
		}

		resp := s.dispatch(req)
		if err := enc.Encode(resp); err != nil {
			return err
		}
	}
	// A closed stdin is the normal end of a session — the agent exited. Everything else is
	// a real read failure worth surfacing to client.log.
	if err := scanner.Err(); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

func (s *Server) dispatch(req request) response {
	out := response{JSONRPC: "2.0", ID: req.ID}

	switch req.Method {
	case "initialize":
		out.Result = s.initialize(req.Params)
	case "ping":
		// The spec's liveness check. An empty object is the whole answer.
		out.Result = map[string]any{}
	case "tools/list":
		out.Result = map[string]any{"tools": s.toolList()}
	case "tools/call":
		out.Result = s.callTool(req.Params)
	default:
		// Includes `resources/list` and `prompts/list`, which some clients probe for even
		// when the capabilities we advertised say we have neither. Method-not-found is the
		// correct answer and clients treat it as such.
		out.Error = &rpcError{Code: codeMethodNotFound, Message: "unknown method: " + req.Method}
	}
	return out
}

func (s *Server) initialize(params json.RawMessage) map[string]any {
	var p struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	_ = json.Unmarshal(params, &p) // absent or malformed params just means "use our version"

	version := ProtocolVersion
	if knownProtocols[p.ProtocolVersion] {
		version = p.ProtocolVersion
	}

	return map[string]any{
		"protocolVersion": version,
		// Tools only. No resources, no prompts, and no `listChanged` — the tool set is
		// compiled in, so advertising a change notification we can never send would be a
		// claim the server cannot honour.
		"capabilities": map[string]any{"tools": map[string]any{}},
		"serverInfo":   map[string]any{"name": ServerName, "version": s.Version},
	}
}

func (s *Server) toolList() []map[string]any {
	list := make([]map[string]any, 0, len(s.Tools))
	for _, t := range s.Tools {
		list = append(list, map[string]any{
			"name":        t.Name,
			"description": t.Description,
			"inputSchema": t.Schema,
		})
	}
	return list
}

// callTool runs one tool and wraps the outcome in the spec's content shape.
//
// ⚠️ A TOOL FAILURE IS A RESULT WITH `isError`, NOT A JSON-RPC ERROR. The distinction is
// the whole reason the agent can recover: a protocol error is a transport fault the model
// never sees, whereas an `isError` result is handed to it as text — so "that license key is
// not recognised" reaches the developer as an answer instead of vanishing into a client log.
// Only a malformed CALL (bad params, unknown tool) is a protocol error, because that is a
// fault in the client rather than in the request.
func (s *Server) callTool(params json.RawMessage) map[string]any {
	var p struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	}
	if err := json.Unmarshal(params, &p); err != nil || p.Name == "" {
		return errorResult("the call named no tool")
	}
	if !s.known(p.Name) {
		return errorResult(fmt.Sprintf("unknown tool: %s", p.Name))
	}

	text, err := s.Call(p.Name, p.Arguments)
	if err != nil {
		slog.Warn("mcp tool failed", "tool", p.Name, "err", err.Error())
		return errorResult(err.Error())
	}
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": text}},
	}
}

func (s *Server) known(name string) bool {
	for _, t := range s.Tools {
		if t.Name == name {
			return true
		}
	}
	return false
}

func errorResult(message string) map[string]any {
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": message}},
		"isError": true,
	}
}

// trimSpace avoids pulling in strings for one call on a byte slice.
func trimSpace(b []byte) []byte {
	i, j := 0, len(b)
	for i < j && isSpace(b[i]) {
		i++
	}
	for j > i && isSpace(b[j-1]) {
		j--
	}
	return b[i:j]
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n'
}
