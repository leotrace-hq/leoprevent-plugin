package transcript

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
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

// ParseCopilotAgentReply returns the assistant prose a VS Code Copilot turn emitted
// AFTER we delivered a block at `since` — the agent's reaction to leoprevent, for
// /outcome's agent_response.
//
// ⚠️ THE ANCHOR IS A TIMESTAMP, NOT A MARKER, AND IT HAS TO BE. Claude splits on the
// injected "Stop hook feedback:" message, which is the right boundary because it is the
// moment we spoke. Copilot records NO such message: a whole session that blocked and
// remediated carries exactly ONE user.message (the developer's own prompt), verified by
// inspection of a real transcript. So there is nothing in the file to split on, and the
// block-delivery time is the same boundary named from the other side — text after it is a
// response to what we told it, text before it is the agent narrating its own work.
//
// The alternative anchors were both worse. A TIMING GAP between assistant.turn_end and
// the next assistant.turn_start does mark the review (23s on the sample, against
// same-millisecond gaps everywhere else) but a slow tool call looks identical, and the
// failure is a confidently mis-split reply. Shipping the WHOLE turn's prose needs no
// anchor and never misses, at the cost of reporting the agent's pre-block commentary as
// if it were a reply to a finding it had not yet been shown.
//
// ⚠️ THIS IS THE TRANSCRIPT THE HOOK IS HANDED, NOT chatSessions, so the write-order race
// documented on ParseCopilotTurnMeta does NOT apply. The two files are written for
// different reasons: the transcript is an append-order journal (each record's timestamp
// matches the event that produced it), while chatSessions is a persistence snapshot VS Code
// flushes when it gets round to it — which is why the MODEL is racy and the prose is not.
// The records are session.start / user.message / assistant.message / assistant.turn_* /
// tool.*; the prose is assistant.message's data.content.
//
// Best-effort by contract, exactly like the Claude and Codex parsers: a zero `since`, an
// unreadable file, a format change or no post-block message all yield "" so the engine
// falls back to the Stop stdin's last_assistant_message (which Copilot does not populate,
// so the field simply stays empty as it did before this existed). A miss must never cost
// more than the reply.
func ParseCopilotAgentReply(transcriptPath string, since time.Time) (string, error) {
	// No anchor means we cannot tell a reply from the agent's own commentary, and
	// guessing is the one outcome this parser must not produce.
	if since.IsZero() || transcriptPath == "" {
		return "", nil
	}
	// The path comes from the local coding agent's hook stdin, in a process that agent
	// spawned on the developer's own machine as the developer. Anyone able to write that
	// stdin can already run code as this user, so confining the read buys nothing — and
	// the obvious confinement (a prefix check against os.UserConfigDir) would silently
	// return no reply on a portable, Insiders, remote or --user-data-dir VS Code, which is
	// the exact failure this parser exists to remove. Same read, same reasoning, as
	// ParseCopilotTurnMeta above and the Claude and Codex reply parsers.
	data, err := os.ReadFile(transcriptPath) //nolint:gosec // local agent's own hook stdin; see above
	if err != nil {
		return "", err
	}

	var order []string
	text := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var r copilotRecord
		if json.Unmarshal([]byte(line), &r) != nil {
			continue // tolerate a garbled or unknown line, same as every sibling parser
		}
		if r.Type != "assistant.message" {
			continue
		}
		// A record we cannot place in time cannot be attributed to either side of the
		// block, so it is dropped rather than guessed at.
		ts, err := time.Parse(time.RFC3339, r.Timestamp)
		if err != nil || !ts.After(since) {
			continue
		}
		// content only. data.toolRequests are the agent's ACTIONS, already captured as
		// the before/after code, and their arguments carry whole file bodies that would
		// swamp the prose — the same text-only rule assistantTextAfter applies to Claude's
		// tool_use blocks.
		body := strings.TrimSpace(r.Data.Content)
		if body == "" {
			continue
		}
		// Deduped by message id, last-wins, ordered by first appearance — the resolution
		// assistantTextAfter uses, and for its reason: a partial is a PREFIX of the final,
		// so first-wins ships a half-written sentence and keeping every copy ships the
		// reply twice. Copilot was NOT observed to repeat a messageId (10 records, 10 ids),
		// so this is insurance rather than a fix; it costs nothing and keeps the two
		// parsers in the package answering the same question the same way. A record with
		// no id is keyed by position and always kept.
		key := r.Data.MessageID
		if key == "" {
			key = "\x00pos" + strconv.Itoa(len(order))
		}
		if _, seen := text[key]; !seen {
			order = append(order, key)
		}
		text[key] = body
	}

	var out strings.Builder
	for _, k := range order {
		if out.Len() > 0 {
			out.WriteString("\n\n")
		}
		out.WriteString(text[k])
	}
	return capReply(out.String()), nil
}

// copilotRecord is the slice of a Copilot transcript record this parser reads. Declared
// narrowly on purpose: the format is undocumented VS Code internals, so binding only the
// three fields we need means an added or renamed sibling field cannot break the decode.
type copilotRecord struct {
	Type      string `json:"type"`
	Timestamp string `json:"timestamp"`
	Data      struct {
		MessageID string `json:"messageId"`
		Content   string `json:"content"`
	} `json:"data"`
}
