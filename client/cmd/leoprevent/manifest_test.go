package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPreToolUseMatcherCoversBash pins the tool that agents actually use to write files
// when they are not handed a write tool.
//
// The matcher shipped as Write|Edit|MultiEdit|NotebookEdit, which reads as the complete
// set of ways to change a file and is not: a heredoc, `sed -i`, `tee` and `git apply`
// are all Bash. Observed live on 2026-08-25, an agent asked six consecutive times to
// write a file chose `cat > path <<'EOF'` EVERY time, so PreToolUse never fired, no
// repository was discovered, and every turn reported itself unreviewed — which is
// indistinguishable from the bug this event was added to fix, and is why it survived a
// first round of live testing.
//
// Excluding a tool from this matcher is therefore an availability decision, not a
// tidy-up: the cost is silent. Anything added here is filtered again in-process, where
// a call naming no path yields no candidates and RecordEditedRepo no-ops.
func TestPreToolUseMatcherCoversBash(t *testing.T) {
	for _, name := range []string{"claude", "codex", "copilot", "vscode"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join("..", "..", "..", "hooks", "hooks."+name+".json")
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			var m struct {
				Hooks map[string][]struct {
					Matcher string `json:"matcher"`
				} `json:"hooks"`
			}
			if err := json.Unmarshal(raw, &m); err != nil {
				t.Fatalf("parse %s: %v", path, err)
			}
			var found bool
			for event, groups := range m.Hooks {
				// Both dialects: Claude/Codex/VS Code say PreToolUse, the Copilot CLI
				// says preToolUse.
				if !strings.EqualFold(event, "PreToolUse") {
					continue
				}
				found = true
				for i, g := range groups {
					// No matcher at all fires on every tool, which covers Bash by
					// construction — that is the copilot/vscode manifests' choice.
					if g.Matcher == "" {
						continue
					}
					if !strings.Contains(g.Matcher, "Bash") {
						t.Errorf("%s: %s group %d matcher %q excludes Bash, so a "+
							"heredoc or sed -i write discovers no repository and the "+
							"turn is silently unreviewed", path, event, i, g.Matcher)
					}
				}
			}
			if !found {
				t.Errorf("%s declares no PreToolUse hook, so a turn in a workspace "+
					"folder discovers no repository", path)
			}
		})
	}
}
