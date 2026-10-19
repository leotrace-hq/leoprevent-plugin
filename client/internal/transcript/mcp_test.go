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

// The live Webflow MCP server exposes one tool per area and wraps every
// operation in an actions array. This is the shape it records for a
// register_inline_script call, taken from a real session.
const webflowScriptsCall = `{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","id":"toolu_scripts","name":"mcp__webflow__data_scripts_tool","input":{"session_id":"ses_x","agent_id":"a","context":"c","actions":[{"label":"read","get_registered_scripts":{"site_id":"s"}},{"label":"plant","register_inline_script":{"site_id":"s","display_name":"Fixture","version":"1.0.0","source_code":"banner.innerHTML = location.hash;"}},{"label":"hosted","register_hosted_script":{"site_id":"s","display_name":"Cdn","version":"1.0.0","hosted_location":"https://cdn.example/x.js","integrity_hash":"sha384-abc"}},{"label":"footer","set_site_freeform_code":{"site_id":"s","location":"footer","content":"<script>eval(location.hash)</script>"}},{"label":"page","set_page_freeform_code":{"page_id":"p","location":"head","content":"<script src=\"https://cdn.example/y.js\"></script>"}},{"label":"update","update_registered_script":{"site_id":"s","script_id":"i","source_code":"document.write(location.search)"}}]}}]}}`

func TestWebflowScriptsToolActionsAreReviewed(t *testing.T) {
	p := writeTranscript(t, userMsg, webflowScriptsCall)
	got, err := ParseMCPChanges(p, DefaultMCPToolRules())
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"mcp/mcp__webflow__data_scripts_tool/call-1/actions_1_register_inline_script/source_code.js":     "banner.innerHTML = location.hash;",
		"mcp/mcp__webflow__data_scripts_tool/call-1/actions_2_register_hosted_script/hosted_script.html": `<script src="https://cdn.example/x.js" integrity="sha384-abc"></script>`,
		"mcp/mcp__webflow__data_scripts_tool/call-1/actions_3_set_site_freeform_code/content.html":       "<script>eval(location.hash)</script>",
		"mcp/mcp__webflow__data_scripts_tool/call-1/actions_4_set_page_freeform_code/content.html":       `<script src="https://cdn.example/y.js"></script>`,
		"mcp/mcp__webflow__data_scripts_tool/call-1/actions_5_update_registered_script/source_code.js":   "document.write(location.search)",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d changes, want %d: %+v", len(got), len(want), got)
	}
	for _, c := range got {
		text, ok := want[c.FilePath]
		if !ok || c.AddedText != text || !c.Virtual || len(c.AddedLines) == 0 {
			t.Fatalf("unexpected change %+v", c)
		}
	}
}

func TestWebflowUpdateOfHostedScriptRendersScriptElement(t *testing.T) {
	p := writeTranscript(t, userMsg,
		`{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","name":"mcp__webflow__data_scripts_tool","input":{"actions":[{"label":"u","update_registered_script":{"site_id":"s","script_id":"i","hosted_location":"https://cdn.example/z.js","integrity_hash":""}}]}}]}}`,
	)
	got, err := ParseMCPChanges(p, DefaultMCPToolRules())
	if err != nil || len(got) != 1 || got[0].AddedText != `<script src="https://cdn.example/z.js"></script>` {
		t.Fatalf("changes = %+v, err = %v", got, err)
	}
}

func TestWebflowReadOnlyActionsProduceNothing(t *testing.T) {
	p := writeTranscript(t, userMsg,
		`{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","name":"mcp__webflow__data_scripts_tool","input":{"actions":[{"label":"a","get_site_freeform_code":{"site_id":"s"}},{"label":"b","add_site_script":{"site_id":"s","script_id":"i","location":"footer","version":"1.0.0"}}]}}]}}`,
	)
	got, err := ParseMCPChanges(p, DefaultMCPToolRules())
	if err != nil || len(got) != 0 {
		t.Fatalf("changes = %+v, err = %v", got, err)
	}
}

func TestWebflowWHTMLBuilderActionsAreReviewed(t *testing.T) {
	p := writeTranscript(t, userMsg,
		`{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","name":"mcp__webflow__data_whtml_builder","input":{"siteId":"s","pageId":"p","actions":[{"build_label":"one","creation_position":"append","parent_element_id":{"component":"c","element":"e"},"html":"<div onclick=\"eval(location.hash)\">x</div>","css":".x{color:red}"},{"build_label":"two","creation_position":"append","parent_element_id":{"component":"c","element":"e"},"html":"<a href=\"javascript:alert(1)\">y</a>"}]}}]}}`,
	)
	got, err := ParseMCPChanges(p, DefaultMCPToolRules())
	if err != nil {
		t.Fatal(err)
	}
	paths := map[string]bool{}
	for _, c := range got {
		paths[c.FilePath] = true
	}
	for _, want := range []string{
		"mcp/mcp__webflow__data_whtml_builder/call-1/actions_0/html.html",
		"mcp/mcp__webflow__data_whtml_builder/call-1/actions_0/css.css",
		"mcp/mcp__webflow__data_whtml_builder/call-1/actions_1/html.html",
	} {
		if !paths[want] {
			t.Fatalf("missing %s in %+v", want, got)
		}
	}
	if len(got) != 3 {
		t.Fatalf("changes = %+v", got)
	}
}

func TestScopedRuleWalksArraysAndIsBounded(t *testing.T) {
	var items []string
	for i := 0; i < maxPathMatches+10; i++ {
		items = append(items, `{"code":"x()"}`)
	}
	p := writeTranscript(t, userMsg,
		`{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","name":"mcp__custom__bulk","input":{"batch":{"items":[`+strings.Join(items, ",")+`]}}}]}}`,
	)
	got, err := ParseMCPChanges(p, []MCPToolRule{{Tool: "mcp__custom__*", Scope: "batch.items.*", Fields: map[string]string{"code": ".js"}}})
	if err != nil || len(got) != maxPathMatches {
		t.Fatalf("got %d changes, err = %v", len(got), err)
	}
	if got[0].FilePath != "mcp/mcp__custom__bulk/call-1/batch_items_0/code.js" {
		t.Fatalf("path = %s", got[0].FilePath)
	}
}

func TestClaudeAIConnectorToolNameIsMatchedCaseInsensitively(t *testing.T) {
	call := strings.Replace(webflowScriptsCall, "mcp__webflow__data_scripts_tool", "mcp__claude_ai_Webflow__data_scripts_tool", 1)
	p := writeTranscript(t, userMsg, call)
	got, err := ParseMCPChanges(p, DefaultMCPToolRules())
	if err != nil || len(got) != 5 {
		t.Fatalf("changes = %+v, err = %v", got, err)
	}
}

func TestOpaqueWebflowConnectorToolNameIsReviewed(t *testing.T) {
	call := strings.Replace(webflowScriptsCall, "mcp__webflow__data_scripts_tool", "mcp__668bf9fe-11c1-41dd-9d4c-cba8162162b7__data_scripts_tool", 1)
	p := writeTranscript(t, userMsg, call)
	got, err := ParseMCPChanges(p, DefaultMCPToolRules())
	if err != nil || len(got) != 5 {
		t.Fatalf("changes = %+v, err = %v", got, err)
	}
}
