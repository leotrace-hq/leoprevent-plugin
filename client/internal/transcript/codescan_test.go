package transcript

import (
	"strings"
	"testing"
)

const opaqueWebflow = "mcp__668bf9fe-11c1-41dd-9d4c-cba8162162b7__"

func scanCall(t *testing.T, tool string, input string) []Change {
	t.Helper()
	p := writeTranscript(t, userMsg,
		`{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","name":"`+tool+`","input":`+input+`}]}}`,
	)
	got, err := ParseMCPChanges(p, DefaultMCPToolRules())
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func byPath(got []Change) map[string]string {
	m := map[string]string{}
	for _, c := range got {
		if !c.Virtual || len(c.AddedLines) == 0 {
			panic("change lacks virtual provenance: " + c.FilePath)
		}
		m[c.FilePath] = c.AddedText
	}
	return m
}

func TestWebflowV2WHTMLActionNestedUnderItsNameIsReviewed(t *testing.T) {
	got := byPath(scanCall(t, opaqueWebflow+"data_whtml_builder",
		`{"siteId":"s","pageId":"p","actions":[{"insert_whtml":{"build_label":"card","parent_element_id":{"component":"c","element":"e"},"creation_position":"append","html":"<style>.card:hover{transform:scale(1.05)}</style><div class=\"card\"><img src=x onerror=\"eval(location.hash.slice(1))\"></div>"}}]}`))
	want := "mcp/" + pathSegment(opaqueWebflow+"data_whtml_builder") + "/call-1/actions_0_insert_whtml/html.html"
	if len(got) != 1 || !strings.Contains(got[want], "onerror") {
		t.Fatalf("got %+v, want %s", got, want)
	}
}

func TestWebflowV1WHTMLBuilderIsReviewed(t *testing.T) {
	got := byPath(scanCall(t, "mcp__webflow__whtml_builder",
		`{"siteId":"s","actions":[{"build_label":"one","creation_position":"append","parent_element_id":{"component":"c","element":"e"},"html":"<div onclick=\"eval(location.hash)\">x</div>","css":".x{color:red}"}]}`))
	if len(got) != 2 || got["mcp/mcp__webflow__whtml_builder/call-1/actions_0/css.css"] != ".x{color:red}" || !strings.Contains(got["mcp/mcp__webflow__whtml_builder/call-1/actions_0/html.html"], "onclick") {
		t.Fatalf("got %+v", got)
	}
}

func TestWebflowAttributesAreReviewedUnderBothVersionsNames(t *testing.T) {
	for tool, action := range map[string]string{
		opaqueWebflow + "data_element_tool": "set_attributes",
		"mcp__webflow__element_tool":        "add_or_update_attribute",
	} {
		got := scanCall(t, tool,
			`{"siteId":"s","pageId":"p","actions":[{"`+action+`":{"id":{"component":"c","element":"e"},"attributes":[{"name":"onclick","value":"eval(location.hash.slice(1))"},{"name":"bad name\"><script>","value":"x"},{"name":"data-x","value":"a\"b"}]}},{"get_attributes":{"id":{"component":"c","element":"e"}}}]}`)
		if len(got) != 1 || !strings.HasSuffix(got[0].FilePath, "/actions_0_"+action+"/attributes.html") {
			t.Fatalf("%s: got %+v", tool, got)
		}
		if got[0].AddedText != `<div onclick="eval(location.hash.slice(1))" data-x="a&#34;b"></div>` {
			t.Fatalf("%s: markup = %s", tool, got[0].AddedText)
		}
	}
}

func TestWebflowJavascriptLinkIsReviewedAndPageLinkIsNot(t *testing.T) {
	got := scanCall(t, opaqueWebflow+"data_element_tool",
		`{"siteId":"s","pageId":"p","actions":[{"set_link":{"id":{"component":"c","element":"e"},"linkType":"url","link":"javascript:alert(document.cookie)"}},{"set_link":{"id":{"component":"c","element":"e"},"linkType":"page","link":"page_123"}},{"set_link":{"id":{"component":"c","element":"e"},"linkType":"url","link":"https://example.com"}}]}`)
	if len(got) != 1 || got[0].AddedText != `<a href="javascript:alert(document.cookie)"></a>` {
		t.Fatalf("got %+v", got)
	}
}

func TestEmbedCodeIsFoundWhereverTheSchemaPutsIt(t *testing.T) {
	got := scanCall(t, opaqueWebflow+"data_element_settings_tool",
		`{"siteId":"s","pageId":"p","actions":[{"set_settings":{"element_id":{"component":"c","element":"e"},"operations":[{"setting":"embed","value":{"type":"static","content":"<script>document.write(location.search)</script>"}}]}}]}`)
	if len(got) != 1 || !strings.Contains(got[0].AddedText, "document.write") || !strings.HasSuffix(got[0].FilePath, ".html") {
		t.Fatalf("got %+v", got)
	}
	got = scanCall(t, "mcp__webflow__data_element_builder",
		`{"siteId":"s","pageId":"p","actions":[{"create_element":{"build_label":"b","creation_position":"append","parent_element_id":{"component":"c","element":"e"},"element_schema":{"type":"HtmlEmbed","children":[{"type":"DivBlock","embed_code":"window.addEventListener('message', e => eval(e.data))"}]}}}]}`)
	if len(got) != 1 || !strings.HasSuffix(got[0].FilePath, "/embed_code.html") {
		t.Fatalf("got %+v", got)
	}
}

func TestScanSendsNothingThatIsNotCode(t *testing.T) {
	for tool, input := range map[string]string{
		opaqueWebflow + "data_element_tool":     `{"siteId":"s","pageId":"p","actions":[{"set_text":{"id":{"component":"c","element":"e"},"text":"Welcome to our spring sale"}},{"set_style":{"id":{"component":"c","element":"e"},"style_names":["hero"]}},{"query_elements":{"queries":[{"label":"q","element_filter":{"type":"Heading"}}]}}]}`,
		opaqueWebflow + "data_scripts_tool":     `{"actions":[{"add_site_script":{"site_id":"s","script_id":"i","location":"footer","version":"1.0.0"}},{"get_registered_scripts":{"site_id":"s"}}]}`,
		opaqueWebflow + "data_style_tool":       `{"siteId":"s","pageId":"p","actions":[{"update_style":{"style_name":"card","properties":[{"property_name":"color","property_value":"red"}]}}]}`,
		opaqueWebflow + "data_cms_tool":         `{"siteId":"s","actions":[{"update_collection_items":{"collection_id":"c","request":{"items":[{"fieldData":{"body":"<p>Customer story</p>"}}]}}}]}`,
		"mcp__slack__send_message":              `{"text":"<b>deploy</b> done: window.location.reload()"}`,
		opaqueWebflow + "element_snapshot_tool": `{"actions":[{"html":"<script>x()</script>"}]}`,
	} {
		if got := scanCall(t, tool, input); len(got) != 0 {
			t.Fatalf("%s produced %+v", tool, got)
		}
	}
}

func TestScanIsBounded(t *testing.T) {
	var items []string
	for i := 0; i < maxScanChanges+20; i++ {
		items = append(items, `{"insert_whtml":{"html":"<div>x</div>"}}`)
	}
	got := scanCall(t, "mcp__webflow__data_whtml_builder", `{"actions":[`+strings.Join(items, ",")+`]}`)
	if len(got) != maxScanChanges {
		t.Fatalf("got %d changes", len(got))
	}
}

func TestScanRunsOncePerCallEvenWhenSeveralRulesMatch(t *testing.T) {
	p := writeTranscript(t, userMsg,
		`{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","name":"mcp__webflow__data_whtml_builder","input":{"actions":[{"insert_whtml":{"html":"<div>x</div>"}}]}}]}}`,
	)
	rules := append(DefaultMCPToolRules(), MCPToolRule{Tool: "mcp__webflow__*", Format: FormatCodeScan})
	got, err := ParseMCPChanges(p, rules)
	if err != nil || len(got) != 1 {
		t.Fatalf("got %+v, err = %v", got, err)
	}
}
