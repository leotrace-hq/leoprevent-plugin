package mcp

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// The MCP stdio transport is unforgiving in ways that are invisible until a real client
// connects: a response to a notification, a rewritten request id, or a session that dies on
// the first malformed line all look fine in isolation and present to the developer as "the
// MCP server failed" with nothing in the agent's log worth reading.
//
// So this suite is mostly about the PROTOCOL rather than about the tools. The tool layer has
// its own file.

// serve runs one session over the given lines and returns the responses, in order.
func serve(t *testing.T, s *Server, lines ...string) []map[string]any {
	t.Helper()
	var out bytes.Buffer
	if err := s.Serve(strings.NewReader(strings.Join(lines, "\n")+"\n"), &out); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	var got []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("response is not JSON: %q: %v", line, err)
		}
		got = append(got, m)
	}
	return got
}

func testServer(call Handler) *Server {
	if call == nil {
		call = func(string, map[string]any) (string, error) { return "{}", nil }
	}
	return &Server{Tools: Tools(), Call: call, Version: "9.9.9"}
}

func TestInitializeAdvertisesToolsOnly(t *testing.T) {
	got := serve(t, testServer(nil),
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`)
	if len(got) != 1 {
		t.Fatalf("want 1 response, got %d", len(got))
	}
	result, _ := got[0]["result"].(map[string]any)
	if result["protocolVersion"] != "2025-06-18" {
		t.Errorf("protocolVersion = %v, want the client's own", result["protocolVersion"])
	}
	caps, _ := result["capabilities"].(map[string]any)
	if _, ok := caps["tools"]; !ok {
		t.Error("capabilities must advertise tools")
	}
	// Advertising a capability this server does not implement makes a client probe for
	// resources and prompts it will never get, on every session.
	for _, unwanted := range []string{"resources", "prompts", "logging"} {
		if _, ok := caps[unwanted]; ok {
			t.Errorf("capabilities must not advertise %q", unwanted)
		}
	}
}

func TestInitializeFallsBackForAnUnknownProtocol(t *testing.T) {
	// Echoing a version we have never been written against would claim a surface we cannot
	// promise; answering with our own lets the client decide whether it can speak it.
	got := serve(t, testServer(nil),
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"3000-01-01"}}`)
	result, _ := got[0]["result"].(map[string]any)
	if result["protocolVersion"] != ProtocolVersion {
		t.Errorf("protocolVersion = %v, want %q", result["protocolVersion"], ProtocolVersion)
	}
}

func TestNotificationsAreNeverAnswered(t *testing.T) {
	// ⚠️ A RESPONSE TO A NOTIFICATION IS A PROTOCOL VIOLATION, and `notifications/initialized`
	// arrives on EVERY session — so getting this wrong puts an error in a developer's client
	// log every single time they open an agent, while the tools still appear to work.
	got := serve(t, testServer(nil),
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}`)
	if len(got) != 0 {
		t.Fatalf("notifications must produce no output, got %v", got)
	}
}

func TestRequestIDIsEchoedVerBATIM(t *testing.T) {
	// The spec allows a string OR a number, and a client matches the response to its request
	// by that value. Decoding it into a Go type would rewrite `1` as `1` for some encoders and
	// `1.0` for others, and the client would then wait forever for a reply it already had.
	for _, id := range []string{`1`, `"abc"`, `42`} {
		got := serve(t, testServer(nil),
			`{"jsonrpc":"2.0","id":`+id+`,"method":"ping"}`)
		raw, err := json.Marshal(got[0]["id"])
		if err != nil {
			t.Fatal(err)
		}
		if string(raw) != id {
			t.Errorf("id = %s, want %s", raw, id)
		}
	}
}

func TestAMalformedLineDoesNotEndTheSession(t *testing.T) {
	// One bad message must not cost the developer their tools for the rest of the session.
	got := serve(t, testServer(nil),
		`not json at all`,
		``,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	if len(got) != 2 {
		t.Fatalf("want a parse error then the list, got %d responses", len(got))
	}
	if got[0]["error"] == nil {
		t.Error("the malformed line should be answered with an error")
	}
	if got[1]["result"] == nil {
		t.Error("the session should have continued")
	}
}

func TestToolsListCarriesASchemaAndADescription(t *testing.T) {
	got := serve(t, testServer(nil), `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	result, _ := got[0]["result"].(map[string]any)
	tools, _ := result["tools"].([]any)
	if len(tools) != len(Tools()) {
		t.Fatalf("want %d tools, got %d", len(Tools()), len(tools))
	}
	for _, raw := range tools {
		tool, _ := raw.(map[string]any)
		name, _ := tool["name"].(string)
		if desc, _ := tool["description"].(string); desc == "" {
			t.Errorf("%s: a tool with no description is one an agent never calls", name)
		}
		schema, _ := tool["inputSchema"].(map[string]any)
		if schema["type"] != "object" {
			t.Errorf("%s: inputSchema must be an object schema", name)
		}
	}
}

func TestAToolFailureIsAResultNotAProtocolError(t *testing.T) {
	// ⚠️ THE DISTINCTION IS WHAT LETS THE DEVELOPER RECOVER. A JSON-RPC error is a transport
	// fault the model never sees; an `isError` result is handed to it as text. Every refusal
	// this server can produce is actionable ("generate a personal key…"), so turning them into
	// protocol errors would leave the developer with a broken feature and nowhere to go.
	s := testServer(func(string, map[string]any) (string, error) {
		return "", &stubErr{"that license key is not recognised"}
	})
	got := serve(t, s,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"security_stats","arguments":{}}}`)
	if got[0]["error"] != nil {
		t.Fatal("a tool failure must not be a JSON-RPC error")
	}
	result, _ := got[0]["result"].(map[string]any)
	if result["isError"] != true {
		t.Error("the result must be flagged isError")
	}
	if !strings.Contains(textOf(t, result), "not recognised") {
		t.Error("the message must reach the agent verbatim")
	}
}

func TestAnUnknownToolIsRefusedWithoutCallingTheHandler(t *testing.T) {
	called := false
	s := testServer(func(string, map[string]any) (string, error) {
		called = true
		return "{}", nil
	})
	got := serve(t, s,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_everything","arguments":{}}}`)
	if called {
		t.Fatal("the handler must only ever see a name this server advertised")
	}
	result, _ := got[0]["result"].(map[string]any)
	if result["isError"] != true {
		t.Error("an unknown tool should come back as a tool error")
	}
}

func TestAnUnknownMethodIsMethodNotFound(t *testing.T) {
	// Clients probe `resources/list` even when the capabilities say there are none. -32601 is
	// the answer they expect and handle.
	got := serve(t, testServer(nil), `{"jsonrpc":"2.0","id":1,"method":"resources/list"}`)
	e, _ := got[0]["error"].(map[string]any)
	if e == nil || e["code"].(float64) != -32601 {
		t.Errorf("want method-not-found, got %v", got[0])
	}
}

func TestToolTextIsReturnedUnchanged(t *testing.T) {
	// The dashboard's JSON is the answer. Reformatting it in the client would put a second
	// description of every figure in the one place a dashboard change cannot reach.
	body := `{"view":"stats","turns":120}`
	s := testServer(func(string, map[string]any) (string, error) { return body, nil })
	got := serve(t, s,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"security_stats","arguments":{}}}`)
	result, _ := got[0]["result"].(map[string]any)
	if textOf(t, result) != body {
		t.Errorf("body was rewritten: %q", textOf(t, result))
	}
}

func textOf(t *testing.T, result map[string]any) string {
	t.Helper()
	content, _ := result["content"].([]any)
	if len(content) == 0 {
		t.Fatal("result carried no content")
	}
	first, _ := content[0].(map[string]any)
	text, _ := first["text"].(string)
	return text
}

type stubErr struct{ msg string }

func (e *stubErr) Error() string { return e.msg }
