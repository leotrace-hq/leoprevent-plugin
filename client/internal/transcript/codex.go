package transcript

import (
	"encoding/json"
	"os"
	"strings"
	"time"
)

// reWakeMarker is the opening of leoprevent's own review prompt. When Codex
// re-wakes via a Stop {"decision":"block"}, it surfaces the reason as a user
// message; such a message must NOT be treated as a turn start. This is the
// shared prefix of BOTH review.BuildPrompt ("…required —") and
// review.BuildFindingsPrompt ("…— fix before finishing…") — see the
// TestPromptPrefixMatchesCodexMarker regression test, which fails if either
// prompt's first line drifts from this.
const reWakeMarker = "🔒 LeoPrevent: security review"

// ParseCodexChanges extracts the files the agent edited this turn from a Codex
// rollout transcript (JSONL), the analog of ParseChanges for Claude.
//
// Codex encodes file edits as `custom_tool_call` response items named
// "apply_patch" whose `input` is a patch in the "*** Begin Patch /
// *** Update File: <path>" format. We parse those for changed paths + added
// (`+`) lines. A turn starts at the last genuine user message.
//
// KNOWN LIMITATION (same as Claude): files the agent mutates via the
// `exec_command` shell tool (Codex's Bash) are not apply_patch calls, so they
// are not seen; that is the known changed-file provenance gap of the transcript
// fallback, which the primary git-baseline path does not have.
//
// Codex's docs note the rollout format is "not a stable interface"; this parser
// is therefore defensive and the hook fails open if it can't read the file.
func ParseCodexChanges(transcriptPath string) ([]Change, error) {
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
		if json.Unmarshal(line, &e) == nil { // tolerate unknown/garbled lines
			entries = append(entries, e)
		}
	}

	// Turn start = last genuine user message.
	turnStart := 0
	for i, e := range entries {
		if e.isGenuineUserMessage() {
			turnStart = i
		}
	}

	added := map[string]*strings.Builder{}
	var order []string
	record := func(path, text string) {
		if added[path] == nil {
			added[path] = &strings.Builder{}
			order = append(order, path)
		}
		added[path].WriteString(text)
	}

	for _, e := range entries[turnStart:] {
		if e.Type != "response_item" || e.Payload.Type != "custom_tool_call" || e.Payload.Name != "apply_patch" {
			continue
		}
		for path, text := range parseApplyPatch(e.Payload.Input) {
			record(path, text)
		}
	}

	changes := make([]Change, 0, len(order))
	for _, p := range order {
		changes = append(changes, Change{FilePath: p, AddedText: added[p].String()})
	}
	return changes, nil
}

// ParseCodexTurnMeta extracts the coding agent's own turn activity (model, prompt,
// token usage, wall-clock) from a Codex rollout — the analog of ParseTurnMeta for
// Claude. Turn scope is the SAME as ParseCodexChanges (last genuine user message →
// end), so for `codex exec` (one user input per run) it covers the whole run, and
// for the TUI Stop hook it covers just the latest turn — token usage is never
// double-counted across turns.
//
// Token mapping (Codex/OpenAI billing): each request's `last_token_usage` is summed
// over the turn (verified: the per-request sum equals the session's
// `total_token_usage`). `input_tokens` includes the cached portion, so we split it —
// the cached share goes to the cache-read lane (cheaper), the rest to full input.
// OpenAI has no cache-write charge, so CacheCreationTokens stays 0. Codex has no
// Fast tier, so Speed stays "".
func ParseCodexTurnMeta(transcriptPath string) (Meta, error) {
	f, err := os.Open(transcriptPath)
	if err != nil {
		return Meta{}, err
	}
	defer f.Close()

	lines, err := readJSONLLines(f)
	if err != nil {
		return Meta{}, err
	}
	var entries []codexEntry
	for _, line := range lines {
		var e codexEntry
		if json.Unmarshal(line, &e) == nil {
			entries = append(entries, e)
		}
	}

	// Turn start = last genuine user message (same boundary as ParseCodexChanges).
	turnStart := 0
	for i, e := range entries {
		if e.isGenuineUserMessage() {
			turnStart = i
		}
	}

	var m Meta
	// Model: last non-empty turn_context model up to the end of the file — the model
	// that ran the latest turn (it rarely changes within a session).
	for _, e := range entries {
		if e.Payload.Model != "" {
			m.AgentModel = e.Payload.Model
		}
	}

	var promptTime, lastTime time.Time
	if turnStart < len(entries) {
		m.Prompt = entries[turnStart].userText()
		promptTime = parseTime(entries[turnStart].Timestamp)
	}
	var input, cached, output int
	for _, e := range entries[turnStart:] {
		if e.Type == "event_msg" && e.Payload.Type == "token_count" {
			u := e.Payload.Info.LastTokenUsage
			input += u.InputTokens
			cached += u.CachedInputTokens
			output += u.OutputTokens
		}
		if t := parseTime(e.Timestamp); !t.IsZero() {
			lastTime = t
		}
	}
	uncached := input - cached
	if uncached < 0 {
		uncached = 0 // defensive: never negative if the format ever shifts
	}
	m.InputTokens = uncached
	m.CacheReadTokens = cached
	m.OutputTokens = output
	// CacheCreationTokens = 0 (OpenAI has no cache-write charge); Speed = "" (no Fast tier).
	if !promptTime.IsZero() && lastTime.After(promptTime) {
		m.DurationMs = lastTime.Sub(promptTime).Milliseconds()
	}
	// PromptTime is deliberately left zero (unlike Claude's ParseTurnMeta): the Codex
	// rollout is read AFTER the turn has settled, so lastTime is the true final entry —
	// no mid-write flush race — and DurationMs above is already accurate. Leaving PromptTime
	// zero tells engine.turnMeta to trust this DurationMs rather than the hook wall-clock.
	return m, nil
}

// ParseCodexAgentReply returns the assistant text emitted AFTER the last re-wake
// injection — the analog of ParseAgentReply for Claude, and the same fix: the Stop
// stdin's last_assistant_message is one MESSAGE, while an agent that interleaves
// tool calls with prose emits several and leaves the reasoning in an earlier one.
//
// ⚠️ THE MARKER DIFFERS, THE INTENT DOES NOT. Claude prefixes an injected re-wake
// with "Stop hook feedback:"; Codex surfaces the block reason as a plain user
// message carrying our review text, so the boundary here is `reWakeMarker` — the
// same string isGenuineUserMessage already uses to refuse that message as a turn
// start, so the two cannot disagree about what an injection looks like.
//
// Best-effort by contract: no marker, an unreadable file, or the rollout format
// shifting (Codex documents it as unstable) all yield "" and the caller falls back
// to last_assistant_message.
func ParseCodexAgentReply(transcriptPath string) (string, error) {
	f, err := os.Open(transcriptPath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	lines, err := readJSONLLines(f)
	if err != nil {
		return "", err
	}
	var entries []codexEntry
	for _, line := range lines {
		var e codexEntry
		if json.Unmarshal(line, &e) == nil {
			entries = append(entries, e)
		}
	}

	// The LAST injection: one turn can be blocked more than once, and only the most
	// recent re-wake is the one this outcome is scoring.
	rewake := -1
	for i, e := range entries {
		if e.isReWake() {
			rewake = i
		}
	}
	if rewake < 0 {
		return "", nil
	}

	// No id-dedup here, unlike Claude: a Codex rollout records each assistant message
	// once (it is written after the turn settles, with no streamed partials), and there
	// is no message id to key on if it ever did.
	var out strings.Builder
	for _, e := range entries[rewake+1:] {
		if e.Type != "response_item" || e.Payload.Type != "message" || e.Payload.Role != "assistant" {
			continue
		}
		text := strings.TrimSpace(e.userText()) // same concatenation, either role
		if text == "" {
			continue
		}
		if out.Len() > 0 {
			out.WriteString("\n\n")
		}
		out.WriteString(text)
	}
	return capReply(out.String()), nil
}

// isReWake reports whether e is a leoprevent re-wake surfaced as a user message —
// the exact complement of the `reWakeMarker` clause in isGenuineUserMessage.
func (e codexEntry) isReWake() bool {
	if e.Type != "response_item" || e.Payload.Type != "message" || e.Payload.Role != "user" {
		return false
	}
	return strings.HasPrefix(e.userText(), reWakeMarker)
}

// userText concatenates a Codex user message entry's text content.
func (e codexEntry) userText() string {
	var sb strings.Builder
	for _, c := range e.Payload.Content {
		sb.WriteString(c.Text)
	}
	return strings.TrimSpace(sb.String())
}

// codexEntry is the subset of a Codex rollout JSONL line we care about.
type codexEntry struct {
	Timestamp string `json:"timestamp"` // RFC3339 (ms); turn wall-clock for ParseCodexTurnMeta
	Type      string `json:"type"`
	Payload   struct {
		Type    string `json:"type"`
		Role    string `json:"role"`
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		Name  string   `json:"name"`
		Input string   `json:"input"`
		Model string   `json:"model"` // on a "turn_context" entry
		Info  struct { // on an event_msg "token_count" entry
			LastTokenUsage codexTokenUsage `json:"last_token_usage"`
		} `json:"info"`
	} `json:"payload"`
}

// codexTokenUsage is one model request's usage. Note Codex's `input_tokens`
// INCLUDES the cached portion (`cached_input_tokens`), matching OpenAI billing —
// so the uncached input we price at the full rate is input_tokens − cached.
type codexTokenUsage struct {
	InputTokens       int `json:"input_tokens"`
	CachedInputTokens int `json:"cached_input_tokens"`
	OutputTokens      int `json:"output_tokens"`
}

// isGenuineUserMessage reports whether e is a real user prompt — not a synthetic
// wrapper (<environment_context>, <permissions instructions>) and not a leoprevent
// re-wake injection (which Codex surfaces as a user message of our review text).
func (e codexEntry) isGenuineUserMessage() bool {
	if e.Type != "response_item" || e.Payload.Type != "message" || e.Payload.Role != "user" {
		return false
	}
	var sb strings.Builder
	for _, c := range e.Payload.Content {
		sb.WriteString(c.Text)
	}
	text := strings.TrimSpace(sb.String())
	if text == "" {
		return false
	}
	if strings.HasPrefix(text, "<") { // <environment_context>, <permissions instructions>, …
		return false
	}
	if strings.HasPrefix(text, reWakeMarker) {
		return false
	}
	return true
}

// parseApplyPatch extracts changed file paths and their added (`+`) lines from
// an apply_patch input. Update/Add files contribute their added lines; Delete
// files are ignored (no added text to review).
func parseApplyPatch(input string) map[string]string {
	out := map[string]string{}
	bufs := map[string]*strings.Builder{}
	var current string
	for _, line := range strings.Split(input, "\n") {
		switch {
		case strings.HasPrefix(line, "*** Update File: "):
			current = strings.TrimSpace(strings.TrimPrefix(line, "*** Update File: "))
		case strings.HasPrefix(line, "*** Add File: "):
			current = strings.TrimSpace(strings.TrimPrefix(line, "*** Add File: "))
		case strings.HasPrefix(line, "*** Delete File: "):
			current = "" // nothing added
		case strings.HasPrefix(line, "***"), strings.HasPrefix(line, "@@"):
			// patch markers / hunk headers — ignore
		case strings.HasPrefix(line, "+") && current != "":
			if bufs[current] == nil {
				bufs[current] = &strings.Builder{}
			}
			bufs[current].WriteString(strings.TrimPrefix(line, "+"))
			bufs[current].WriteString("\n")
		}
	}
	for path, b := range bufs {
		out[path] = b.String()
	}
	return out
}
