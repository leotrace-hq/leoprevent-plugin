package transcript

import (
	"encoding/json"
	"fmt"
	"html"
	"os"
	"path"
	"strings"
)

type MCPToolRule struct {
	Tool     string            `json:"tool"`
	Fields   map[string]string `json:"fields"`
	Required []string          `json:"required,omitempty"`
	Format   string            `json:"format,omitempty"`
}

func DefaultMCPToolRules() []MCPToolRule {
	return []MCPToolRule{
		{Tool: "mcp__*webflow*__register_inline_script", Fields: map[string]string{"source_code": ".js"}},
		{Tool: "mcp__*webflow*__register_hosted_script", Fields: map[string]string{"hosted_location": ".html", "integrity_hash": ".html"}, Format: "html_script"},
		{Tool: "mcp__*webflow*__data_whtml_builder", Fields: map[string]string{"html": ".html", "css": ".css"}},
		{Tool: "mcp__*tagmanager*__create_tag", Fields: map[string]string{"html": ".html", "javascript": ".js"}},
		{Tool: "mcp__*tagmanager*__update_tag", Fields: map[string]string{"html": ".html", "javascript": ".js"}},
		{Tool: "mcp__*cloudflare*__workers_upload_script", Fields: map[string]string{"script_content": ".js"}},
	}
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
	var fields map[string]json.RawMessage
	if json.Unmarshal(input, &fields) != nil {
		return out
	}
	for _, rule := range rules {
		matched, err := path.Match(rule.Tool, tool)
		if err != nil || !matched {
			continue
		}
		if rule.Format == "html_script" {
			var location, integrity string
			if json.Unmarshal(fields["hosted_location"], &location) != nil || location == "" {
				continue
			}
			_ = json.Unmarshal(fields["integrity_hash"], &integrity)
			markup := `<script src="` + html.EscapeString(location) + `"`
			if integrity != "" {
				markup += ` integrity="` + html.EscapeString(integrity) + `"`
			}
			markup += `></script>`
			out = append(out, Change{
				FilePath:   fmt.Sprintf("mcp/%s/call-%d/hosted_script.html", pathSegment(tool), call),
				AddedText:  markup,
				AddedLines: []int{1},
				Virtual:    true,
			})
			continue
		}
		for _, field := range rule.Required {
			if _, ok := fields[field]; !ok {
				fields[field] = json.RawMessage(`null`)
			}
		}
		for field, ext := range rule.Fields {
			var value string
			raw := fields[field]
			if strings.Contains(field, ".") {
				parts := strings.Split(field, ".")
				raw = input
				for _, part := range parts {
					var object map[string]json.RawMessage
					if json.Unmarshal(raw, &object) != nil {
						raw = nil
						break
					}
					raw = object[part]
				}
			}
			if string(raw) == "null" {
				value = field + ": missing"
			} else if json.Unmarshal(raw, &value) != nil || value == "" {
				continue
			}
			p := fmt.Sprintf("mcp/%s/call-%d/%s%s", pathSegment(tool), call, pathSegment(field), ext)
			c := Change{FilePath: p, AddedText: value, Virtual: true}
			for i := 1; i <= strings.Count(value, "\n")+1; i++ {
				c.AddedLines = append(c.AddedLines, i)
			}
			out = append(out, c)
		}
	}
	return out
}

func pathSegment(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' {
			return r
		}
		return '_'
	}, s)
}
