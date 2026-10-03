package transcript

import (
	"encoding/json"
	"fmt"
	"html"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
)

type MCPToolRule struct {
	Tool     string            `json:"tool"`
	Scope    string            `json:"scope,omitempty"`
	Fields   map[string]string `json:"fields"`
	Required []string          `json:"required,omitempty"`
	Format   string            `json:"format,omitempty"`
}

func DefaultMCPToolRules() []MCPToolRule {
	rules := []MCPToolRule{
		{Tool: "mcp__*webflow*__register_inline_script", Fields: map[string]string{"source_code": ".js"}},
		{Tool: "mcp__*webflow*__register_hosted_script", Fields: map[string]string{"hosted_location": ".html", "integrity_hash": ".html"}, Format: "html_script"},
		{Tool: "mcp__*__data_scripts_tool", Scope: "actions.*.register_hosted_script", Fields: map[string]string{"hosted_location": ".html", "integrity_hash": ".html"}, Format: "html_script"},
		{Tool: "mcp__*__data_scripts_tool", Scope: "actions.*.update_registered_script", Fields: map[string]string{"hosted_location": ".html", "integrity_hash": ".html"}, Format: "html_script"},
		{Tool: "mcp__*tagmanager*__create_tag", Fields: map[string]string{"html": ".html", "javascript": ".js"}},
		{Tool: "mcp__*tagmanager*__update_tag", Fields: map[string]string{"html": ".html", "javascript": ".js"}},
		{Tool: "mcp__*cloudflare*__workers_upload_script", Fields: map[string]string{"script_content": ".js"}},
	}
	for _, tool := range webflowCodeTools {
		rules = append(rules, MCPToolRule{Tool: "mcp__*__" + tool, Format: FormatCodeScan})
	}
	return rules
}

const FormatCodeScan = "code_scan"

var webflowCodeTools = []string{
	"*whtml_builder",
	"*element_builder",
	"*component_builder",
	"*element_tool",
	"*element_settings_tool",
	"*component_props_tool",
	"*scripts_tool",
}

func ParseMCPChanges(
	transcriptPath string,
	rules []MCPToolRule,
) ([]Change, error) {
	f, err := os.Open(transcriptPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	lines, err := readJSONLLines(f)
	if err != nil {
		return nil, err
	}
	var entries []entry
	for _, line := range lines {
		var e entry
		if json.Unmarshal(line, &e) == nil {
			entries = append(entries, e)
		}
	}
	start := 0
	for i, e := range entries {
		if isGenuineUserMessage(e) {
			start = i
		}
	}
	var out []Change
	seenCalls := map[string]bool{}
	for _, e := range entries[start:] {
		if e.Type != "assistant" {
			continue
		}
		var blocks []contentBlock
		if json.Unmarshal(e.Message.Content, &blocks) != nil {
			continue
		}
		for _, b := range blocks {
			if b.Type != "tool_use" {
				continue
			}
			if b.ID != "" && seenCalls[b.ID] {
				continue
			}
			seenCalls[b.ID] = true
			out = appendMCPChanges(out, len(out)+1, b.Name, b.Input, rules)
		}
	}
	return out, nil
}

func ParseCodexMCPChanges(
	transcriptPath string,
	rules []MCPToolRule,
) ([]Change, error) {
	f, err := os.Open(transcriptPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	lines, err := readJSONLLines(f)
	if err != nil {
		return nil, err
	}
	var entries []codexEntry
	for _, line := range lines {
		var e codexEntry
		if json.Unmarshal(line, &e) == nil {
			entries = append(entries, e)
		}
	}
	start := 0
	for i, e := range entries {
		if e.isGenuineUserMessage() {
			start = i
		}
	}
	var out []Change
	for _, e := range entries[start:] {
		if e.Type == "response_item" && e.Payload.Type == "custom_tool_call" {
			out = appendMCPChanges(out, len(out)+1, e.Payload.Name, json.RawMessage(e.Payload.Input), rules)
		}
	}
	return out, nil
}

func appendMCPChanges(
	out []Change,
	call int,
	tool string,
	input json.RawMessage,
	rules []MCPToolRule,
) []Change {
	if !strings.HasPrefix(tool, "mcp__") {
		return out
	}
	var top map[string]json.RawMessage
	if json.Unmarshal(input, &top) != nil {
		return out
	}
	scanned := false
	for _, rule := range rules {
		matched, err := path.Match(strings.ToLower(rule.Tool), strings.ToLower(tool))
		if err != nil || !matched {
			continue
		}
		prefix := fmt.Sprintf("mcp/%s/call-%d/", pathSegment(tool), call)
		if rule.Format == FormatCodeScan {
			if !scanned {
				out = appendCodeScan(out, prefix, input)
				scanned = true
			}
			continue
		}
		for _, scope := range resolvePath(input, rule.Scope) {
			dir := prefix
			if scope.label != "" {
				dir += pathSegment(scope.label) + "/"
			}
			if rule.Format == "html_script" {
				out = appendHostedScript(out, dir, scope.raw)
				continue
			}
			out = appendFields(out, dir, scope.raw, rule)
		}
	}
	return out
}

func appendHostedScript(
	out []Change,
	dir string,
	raw json.RawMessage,
) []Change {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return out
	}
	var location, integrity string
	if json.Unmarshal(fields["hosted_location"], &location) != nil || location == "" {
		return out
	}
	_ = json.Unmarshal(fields["integrity_hash"], &integrity)
	markup := `<script src="` + html.EscapeString(location) + `"`
	if integrity != "" {
		markup += ` integrity="` + html.EscapeString(integrity) + `"`
	}
	markup += `></script>`
	return append(out, Change{
		FilePath:   dir + "hosted_script.html",
		AddedText:  markup,
		AddedLines: []int{1},
		Virtual:    true,
	})
}

func appendFields(
	out []Change,
	dir string,
	raw json.RawMessage,
	rule MCPToolRule,
) []Change {
	required := map[string]bool{}
	for _, field := range rule.Required {
		required[field] = true
	}
	names := make([]string, 0, len(rule.Fields))
	for field := range rule.Fields {
		names = append(names, field)
	}
	sort.Strings(names)
	for _, field := range names {
		ext := rule.Fields[field]
		matches := resolvePath(raw, field)
		if len(matches) == 0 && required[field] {
			matches = []pathMatch{{label: field, raw: json.RawMessage(`null`)}}
		}
		for _, m := range matches {
			var value string
			if string(m.raw) == "null" {
				value = field + ": missing"
			} else if json.Unmarshal(m.raw, &value) != nil || value == "" {
				continue
			}
			c := Change{FilePath: dir + pathSegment(m.label) + ext, AddedText: value, Virtual: true}
			for i := 1; i <= strings.Count(value, "\n")+1; i++ {
				c.AddedLines = append(c.AddedLines, i)
			}
			out = append(out, c)
		}
	}
	return out
}

const maxPathMatches = 64

type pathMatch struct {
	label string
	raw   json.RawMessage
}

func resolvePath(
	raw json.RawMessage,
	p string,
) []pathMatch {
	matches := []pathMatch{{raw: raw}}
	if p == "" {
		return matches
	}
	for _, part := range strings.Split(p, ".") {
		var next []pathMatch
		for _, m := range matches {
			if part == "*" {
				var items []json.RawMessage
				if json.Unmarshal(m.raw, &items) != nil {
					continue
				}
				for i, item := range items {
					if len(next) >= maxPathMatches {
						break
					}
					next = append(next, pathMatch{label: joinLabel(m.label, strconv.Itoa(i)), raw: item})
				}
				continue
			}
			var object map[string]json.RawMessage
			if json.Unmarshal(m.raw, &object) != nil {
				continue
			}
			if v, ok := object[part]; ok {
				next = append(next, pathMatch{label: joinLabel(m.label, part), raw: v})
			}
		}
		matches = next
	}
	return matches
}

func joinLabel(
	label string,
	part string,
) string {
	if label == "" {
		return part
	}
	return label + "_" + part
}

func pathSegment(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' {
			return r
		}
		return '_'
	}, s)
}
