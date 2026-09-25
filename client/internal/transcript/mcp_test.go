package transcript

import (
	"strings"
	"testing"
)

func TestMCPChangesFollowCurrentTurnAndKeepEveryCall(t *testing.T) {
	p := writeTranscript(t,
		`{"type":"user","message":{"role":"user","content":"old"}}`,
		`{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","name":"mcp__webflow__register_inline_script","input":{"source_code":"old()"}}]}}`,
		`{"type":"user","message":{"role":"user","content":"new"}}`,
		`{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","name":"mcp__webflow__register_inline_script","input":{"source_code":"unsafe()"}},{"type":"tool_use","name":"mcp__webflow__register_hosted_script","input":{"hosted_location":"https://example.com/x.js"}},{"type":"tool_use","name":"mcp__webflow__data_whtml_builder","input":{"html":"<script>x()</script>","css":"a{background:url(x)}"}}]}}`,
		stopFeedback,
		`{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","name":"mcp__webflow__register_inline_script","input":{"source_code":"safe()"}}]}}`,
	)
	got, err := ParseMCPChanges(p, DefaultMCPToolRules())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 5 {
		t.Fatalf("changes = %+v", got)
	}
	var foundHosted, foundHTML, foundCSS, foundUnsafe, foundSafe bool
	for _, c := range got {
		if !c.Virtual || len(c.AddedLines) == 0 {
			t.Fatalf("change lacks virtual provenance: %+v", c)
		}
		switch {
		case strings.Contains(c.FilePath, "hosted_script.html"):
			foundHosted = strings.Contains(c.AddedText, "example.com/x.js") && !strings.Contains(c.AddedText, "integrity=")
		case strings.Contains(c.FilePath, "/html.html"):
			foundHTML = strings.Contains(c.AddedText, "<script>")
		case strings.Contains(c.FilePath, "/css.css"):
			foundCSS = strings.Contains(c.AddedText, "background")
		case strings.Contains(c.FilePath, "/source_code.js"):
			foundUnsafe = foundUnsafe || c.AddedText == "unsafe()"
			foundSafe = foundSafe || c.AddedText == "safe()"
		}
	}
	if !foundHosted || !foundHTML || !foundCSS || !foundUnsafe || !foundSafe {
		t.Fatalf("missing expected connector fields: %+v", got)
	}
}

func TestConfiguredMCPToolAndNestedField(t *testing.T) {
	p := writeTranscript(t,
		userMsg,
		`{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","name":"mcp__custom__publish","input":{"payload":{"code":"eval(user)"}}}]}}`,
	)
	got, err := ParseMCPChanges(p, []MCPToolRule{{Tool: "mcp__custom__*", Fields: map[string]string{"payload.code": ".js"}}})
	if err != nil || len(got) != 1 || got[0].AddedText != "eval(user)" {
		t.Fatalf("changes = %+v, err = %v", got, err)
	}
}

func TestHostedScriptIncludesIntegrityWhenSupplied(t *testing.T) {
	p := writeTranscript(t,
		userMsg,
		`{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","name":"mcp__webflow__register_hosted_script","input":{"hosted_location":"https://cdn.example/x.js","integrity_hash":"sha384-abc"}}]}}`,
	)
	got, err := ParseMCPChanges(p, DefaultMCPToolRules())
	if err != nil || len(got) != 1 || !strings.Contains(got[0].AddedText, `integrity="sha384-abc"`) {
		t.Fatalf("changes = %+v, err = %v", got, err)
	}
}

func TestCodexMCPChanges(t *testing.T) {
	p := writeTranscript(t,
		`{"type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"publish"}]}}`,
		`{"type":"response_item","payload":{"type":"custom_tool_call","name":"mcp__webflow__register_inline_script","input":"{\"source_code\":\"alert(1)\"}"}}`,
	)
	got, err := ParseCodexMCPChanges(p, DefaultMCPToolRules())
	if err != nil || len(got) != 1 || got[0].AddedText != "alert(1)" {
		t.Fatalf("changes = %+v, err = %v", got, err)
	}
}

func TestClaudeMCPRepeatedToolUseIDIsOneCall(t *testing.T) {
	p := writeTranscript(t,
		userMsg,
		`{"type":"assistant","message":{"id":"m1","role":"assistant","content":[{"type":"tool_use","id":"tool-1","name":"mcp__webflow__register_inline_script","input":{"source_code":"alert(1)"}}]}}`,
		`{"type":"assistant","message":{"id":"m1","role":"assistant","content":[{"type":"tool_use","id":"tool-1","name":"mcp__webflow__register_inline_script","input":{"source_code":"alert(1)"}}]}}`,
	)
	got, err := ParseMCPChanges(p, DefaultMCPToolRules())
	if err != nil || len(got) != 1 {
		t.Fatalf("changes = %+v, err = %v", got, err)
	}
}
