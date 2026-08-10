package transcript

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// ParseCopilotTurnMeta recovers the coding agent's model + token usage for a VS Code
// Copilot turn. Copilot's own transcript (the file the Stop hook points at) does NOT
// record the model — verified by inspection: its records are session.start /
// user.message / assistant.message / turn_* / tool.* with no model field. The model
// Auto actually resolved to (e.g. "claude-haiku-4-5-20251001") and the token counts
// live in a SIBLING file VS Code writes to persist the chat for reload:
//
//	<workspaceStorage>/<wsHash>/chatSessions/<sessionID>.jsonl
//
// as a "details" string ("Raptor mini • N credits" — the label the UI shows; report
// THIS, not the internal resolvedModel codename) + promptTokens/outputTokens. UNDOCUMENTED
// VS Code internal storage, so strictly best-effort: any miss returns a zero Meta + nil
// error — analytics stay blank, review is never affected.
//
// ⚠️ WRITE-ORDER RACE (verified live 2026-07-16): VS Code flushes the turn's model to
// chatSessions AFTER the Stop hook fires (observed ~1 min later), so at hook time the
// current turn's model is frequently NOT on disk yet and this returns empty. The agent
// NAME is always known (the --agent flag, set by the engine); only the MODEL is racy.
// A cross-turn/settled re-read would catch it — not worth the complexity for an analytics
// field. Treat a blank Copilot model as expected, not a bug. Re-verify if the layout changes.
func ParseCopilotTurnMeta(sessionID, transcriptPath string) (Meta, error) {
	path := findCopilotChatSession(sessionID, transcriptPath)
	if path == "" {
		return Meta{}, nil
	}
	data, err := os.ReadFile(path) //nolint:gosec // path derived from our own session id, in the user's config dir
	if err != nil {
		return Meta{}, nil // best-effort: no meta, never an error that touches review
	}
	// The file is an append-order journal. Per request VS Code writes TWO sibling
	// objects: one with a human "details" string ("Raptor mini • 0.3 credits" — the
	// exact model label the chat UI shows) and one with the tokens + a "resolvedModel"
	// (an INTERNAL codename like "oswe-vscode-prime", NOT the user-facing name). We scan
	// the whole file and keep the LAST of each (the turn the Stop hook just ended), then
	// prefer the display name — it's what the developer actually sees and picked.
	var acc copilotAcc
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var rec any
		if json.Unmarshal([]byte(line), &rec) != nil {
			continue
		}
		acc.walk(rec)
	}
	m := Meta{InputTokens: acc.in, OutputTokens: acc.out}
	switch {
	case acc.display != "":
		m.AgentModel = acc.display // "Raptor mini" — matches the chat UI
	case acc.resolved != "":
		m.AgentModel = acc.resolved // fallback: internal codename, better than nothing
	}
	return m, nil
}

// copilotAcc collects, with LAST-wins semantics, the current turn's display model name
// (from a "details" string), the internal resolvedModel, and the token counts.
type copilotAcc struct {
	display  string
	resolved string
	in, out  int
}

func (a *copilotAcc) walk(o any) {
	switch v := o.(type) {
	case map[string]any:
		if d, ok := v["details"].(string); ok {
			if name := modelFromDetails(d); name != "" {
				a.display = name
			}
		}
		if rm, ok := v["resolvedModel"].(string); ok && rm != "" {
			a.resolved = rm
			// tokens are siblings of resolvedModel in the same object
			if in := intField(v, "promptTokens"); in > 0 {
				a.in = in
			}
			if out := intField(v, "outputTokens"); out > 0 {
				a.out = out
			}
		}
		for _, val := range v {
			a.walk(val)
		}
	case []any:
		for _, item := range v {
			a.walk(item)
		}
	}
}

// modelFromDetails extracts the model label from a Copilot chat "details" string of the
// form "Raptor mini • 0.3 credits" → "Raptor mini". Returns "" if the string isn't that
// shape (so non-model details are ignored).
func modelFromDetails(d string) string {
	i := strings.IndexRune(d, '•')
	if i < 0 {
		return ""
	}
	return strings.TrimSpace(d[:i])
}

// intField reads a numeric field decoded as float64 (encoding/json's default for JSON
// numbers), 0 if absent or another type.
func intField(m map[string]any, key string) int {
	if f, ok := m[key].(float64); ok {
		return int(f)
	}
	return 0
}

// findCopilotChatSession locates <wsHash>/chatSessions/<sessionID>.jsonl. It prefers
// deriving the path from the transcript the Stop hook handed us (same <wsHash> parent),
// then falls back to globbing VS Code's workspaceStorage by session id (a UUID, so it's
// unique across workspaces). Returns "" if not found.
func findCopilotChatSession(sessionID, transcriptPath string) string {
	if sessionID == "" {
		return ""
	}
	// Primary: the transcript lives at <wsHash>/GitHub.copilot-chat/transcripts/<sid>.jsonl;
	// the chat session is its sibling at <wsHash>/chatSessions/<sid>.jsonl.
	if i := strings.Index(transcriptPath, string(filepath.Separator)+"GitHub.copilot-chat"+string(filepath.Separator)); i >= 0 {
		cand := filepath.Join(transcriptPath[:i], "chatSessions", sessionID+".jsonl")
		if fileExists(cand) {
			return cand
		}
	}
	// Fallback: glob every workspaceStorage entry for this session id.
	for _, root := range vscodeWorkspaceStorageRoots() {
		matches, _ := filepath.Glob(filepath.Join(root, "*", "chatSessions", sessionID+".jsonl"))
		for _, cand := range matches {
			if fileExists(cand) {
				return cand
			}
		}
	}
	return ""
}

// vscodeWorkspaceStorageRoots returns the candidate VS Code (+ Insiders) workspaceStorage
// dirs for this OS. VS Code's user config dir matches os.UserConfigDir on every platform
// (macOS ~/Library/Application Support, Linux ~/.config, Windows %AppData%).
func vscodeWorkspaceStorageRoots() []string {
	base, err := os.UserConfigDir()
	if err != nil {
		return nil
	}
	var roots []string
	for _, app := range []string{"Code", "Code - Insiders"} {
		roots = append(roots, filepath.Join(base, app, "User", "workspaceStorage"))
	}
	return roots
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}
