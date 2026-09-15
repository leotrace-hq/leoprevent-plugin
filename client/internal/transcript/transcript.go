// Package transcript extracts the files changed in the current turn from a
// Claude Code session transcript (JSONL), per these verified Claude Code facts:
//
//   - File mutations are Write / Edit / MultiEdit / NotebookEdit tool_use blocks
//     whose input carries file_path / notebook_path.
//   - A turn starts at the last genuine user message. Re-wake injections appear
//     as user messages starting with "Stop hook feedback:" and are NOT turn starts.
//   - Tool results also arrive as type:"user" entries (content = tool_result
//     blocks); those are not turn starts either.
package transcript

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/leotrace-hq/leoprevent-plugin/limits"
)

// Change is one file mutated this turn.
//
//   - AddedText is the text the agent ADDED to the file this turn (new_string /
//     written content for the transcript path; the diff's added lines for the
//     git path). It is what the inert gate and the on-device selector read, and
//     it is what bounds provenance ("only what changed").
//   - FullContent is OPTIONAL surrounding context: the full current file content
//     (capped), populated only by the git-baseline capture path. When present
//     the judge reasons over the whole file (off-screen guards/sinks become
//     visible); when empty the judge falls back to AddedText (the legacy
//     transcript-scoped behaviour). The gate/selector NEVER read it — they stay
//     scoped to AddedText.
type Change struct {
	FilePath    string
	AddedText   string
	FullContent string
	// AddedLines are the 1-based line numbers (in FullContent) the agent added this
	// turn, from the git diff hunks — the positional authority for introduced-vs-
	// pre-existing. Nil on the transcript fallback (no diff line numbers available).
	AddedLines []int
	// RepoDir is the LABEL qualifying FilePath when the turn spans SEVERAL repositories
	// — the repository's basename — and "" when the file came from the repository the
	// session started in, which is every single-repo turn. It is the prefix on
	// FilePath, so stripping it yields the repo-root-relative path.
	//
	// CLIENT-INTERNAL and deliberately NOT on the wire: FilePath already carries the
	// label as a prefix, so the server and the dashboards need nothing new.
	RepoDir string
	// RepoRoot is that repository's absolute root on disk.
	//
	// ⚠️ IT IS CARRIED, NEVER DERIVED FROM RepoDir. A repository discovered at
	// PreToolUse can live ANYWHERE — a sibling checkout, a path typed in full — so it
	// has no cwd-relative name, and RepoDir is only its basename. Rebuilding a root as
	// cwd/RepoDir therefore fails in two ways: it finds nothing for a repo outside cwd
	// (no imported context, silently), and where cwd happens to hold a SAME-NAMED
	// project it resolves the wrong one and egresses that project's code as context —
	// the cross-project leak the resolver's own comment says cannot happen.
	//
	// Empty on the transcript fallback (no git, so no root to name), where callers fall
	// back to cwd exactly as before.
	RepoRoot string
}

// stopHookFeedbackPrefix marks injected re-wake messages.
const stopHookFeedbackPrefix = "Stop hook feedback:"

// entry is the subset of a transcript JSONL line we care about. Timestamp,
// message.model and message.usage are used only by ParseTurnMeta (analytics);
// ParseChanges ignores them.
type entry struct {
	Type      string `json:"type"`
	Timestamp string `json:"timestamp"` // RFC3339; turn wall-clock for ParseTurnMeta
	Message   struct {
		ID      string          `json:"id"` // assistant message id — DEDUP key (Claude logs a message more than once)
		Role    string          `json:"role"`
		Content json.RawMessage `json:"content"`
		Model   string          `json:"model"` // coding-agent model, e.g. "claude-opus-4-8"
		Usage   *usageBlock     `json:"usage"` // per-message token counts
	} `json:"message"`
}

// usageBlock mirrors the token-count block Claude stamps on each assistant
// message. Pointer in entry so its absence (user/tool entries) is distinguishable
// from an all-zero usage.
type usageBlock struct {
	InputTokens         int    `json:"input_tokens"`
	CacheCreationTokens int    `json:"cache_creation_input_tokens"`
	CacheReadTokens     int    `json:"cache_read_input_tokens"`
	OutputTokens        int    `json:"output_tokens"`
	Speed               string `json:"speed"` // "standard" | "fast" (Claude Code /fast) — drives the price tier
}

// Meta is the coding agent's own activity for the current turn, parsed from the
// transcript: the dev's prompt, the model, summed token usage, and the agent's
// wall-clock. It is returned to the agent adapter (which maps it to
// agent.TurnMeta) — defined here, not imported from agent, to keep the dependency
// one-way (agent → transcript, never the reverse).
type Meta struct {
	AgentModel          string
	Prompt              string
	InputTokens         int
	CacheCreationTokens int
	CacheReadTokens     int
	OutputTokens        int
	DurationMs          int64
	Speed               string    // "fast" when Claude Code Fast mode was on (Opus ~2× price)
	PromptTime          time.Time // turn-start timestamp; when set, the engine derives the
	// duration as (hook wall-clock now − PromptTime) instead of trusting DurationMs, because
	// the Stop hook reads the transcript before the final assistant message is flushed, so the
	// transcript END timestamp under-reports. Left zero by adapters whose end IS reliable (Codex
	// reads a settled rollout) — see engine.turnMeta.
}

// contentBlock is one block of an assistant/user message content array.
type contentBlock struct {
	Type  string          `json:"type"`
	Text  string          `json:"text"`
	Name  string          `json:"name"`
	Input json.RawMessage `json:"input"`
}

// mutationInput covers the inputs of all file-mutating tools.
type mutationInput struct {
	FilePath     string `json:"file_path"`
	NotebookPath string `json:"notebook_path"`
	Content      string `json:"content"`
	NewString    string `json:"new_string"`
	NewSource    string `json:"new_source"`
	Edits        []struct {
		NewString string `json:"new_string"`
	} `json:"edits"`
}

var mutatingTools = map[string]bool{
	"Write":        true,
	"Edit":         true,
	"MultiEdit":    true,
	"NotebookEdit": true,
}

// ParseChanges reads the transcript and returns the files changed since the
// last genuine user message, with their added text.
func ParseChanges(transcriptPath string) ([]Change, error) {
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
		if json.Unmarshal(line, &e) == nil { // tolerate unknown/garbled lines
			entries = append(entries, e)
		}
	}

	// Find the last genuine user message = turn start.
	turnStart := 0
	for i, e := range entries {
		if isGenuineUserMessage(e) {
			turnStart = i
		}
	}

	// Collect mutations from assistant tool_use blocks after the turn start.
	added := map[string]*strings.Builder{} // file path -> added text
	var order []string
	for _, e := range entries[turnStart:] {
		if e.Type != "assistant" {
			continue
		}
		var blocks []contentBlock
		if err := json.Unmarshal(e.Message.Content, &blocks); err != nil {
			continue
		}
		for _, b := range blocks {
			if b.Type != "tool_use" || !mutatingTools[b.Name] {
				continue
			}
			var in mutationInput
			if err := json.Unmarshal(b.Input, &in); err != nil {
				continue
			}
			path := in.FilePath
			if path == "" {
				path = in.NotebookPath
			}
			if path == "" {
				continue
			}
			text := in.Content + in.NewString + in.NewSource
			for _, ed := range in.Edits {
				text += "\n" + ed.NewString
			}
			if added[path] == nil {
				added[path] = &strings.Builder{}
				order = append(order, path)
			}
			added[path].WriteString(text)
			added[path].WriteString("\n")
		}
	}

	changes := make([]Change, 0, len(order))
	for _, p := range order {
		changes = append(changes, Change{FilePath: p, AddedText: added[p].String()})
	}
	return changes, nil
}

// ParseTurnMeta extracts the coding agent's own activity for the current turn from
// a Claude transcript: the dev's prompt, the model, token usage summed over the
// turn's assistant messages, and the agent's wall-clock (last-assistant timestamp
// − prompt timestamp). Turn scope is identical to ParseChanges — from the last
// genuine user message to the end — and it is captured at the FIRST Stop, before
// any leoprevent re-wake, so the figures are the agent's own, not the review's.
// Best-effort: malformed/absent fields are skipped; it never errors on content.
func ParseTurnMeta(transcriptPath string) (Meta, error) {
	f, err := os.Open(transcriptPath)
	if err != nil {
		return Meta{}, err
	}
	defer f.Close()

	lines, err := readJSONLLines(f)
	if err != nil {
		return Meta{}, err
	}
	var entries []entry
	for _, line := range lines {
		var e entry
		if json.Unmarshal(line, &e) == nil {
			entries = append(entries, e)
		}
	}

	// Turn start = last genuine user message (same boundary ParseChanges uses).
	turnStart := 0
	for i, e := range entries {
		if isGenuineUserMessage(e) {
			turnStart = i
		}
	}

	var m Meta
	var promptTime time.Time
	if turnStart < len(entries) {
		m.Prompt = userText(entries[turnStart])
		promptTime = parseTime(entries[turnStart].Timestamp) // guard with the same bound (empty entries → no index)
	}
	var lastAssistant time.Time
	// Claude logs the SAME assistant message more than once (identical id + usage:
	// streamed partials + the final, plus re-renders), so summing every occurrence
	// double/triple-counts tokens. Count each unique message id ONCE — this matches
	// Claude Code's own /cost. A message without an id (older formats) is summed as-is.
	seenMsg := map[string]bool{}
	for _, e := range entries[turnStart:] {
		if e.Type != "assistant" {
			continue
		}
		if e.Message.Model != "" {
			m.AgentModel = e.Message.Model // last non-empty wins (the model that ended the turn)
		}
		if id := e.Message.ID; id != "" {
			if seenMsg[id] {
				if t := parseTime(e.Timestamp); !t.IsZero() {
					lastAssistant = t // a duplicate still advances the turn's end timestamp
				}
				continue
			}
			seenMsg[id] = true
		}
		if u := e.Message.Usage; u != nil {
			m.InputTokens += u.InputTokens
			m.CacheCreationTokens += u.CacheCreationTokens
			m.CacheReadTokens += u.CacheReadTokens
			m.OutputTokens += u.OutputTokens
			if u.Speed != "" {
				m.Speed = u.Speed // last non-empty wins; a turn is uniform-speed (Fast is a session toggle)
			}
		}
		if t := parseTime(e.Timestamp); !t.IsZero() {
			lastAssistant = t
		}
	}
	if !promptTime.IsZero() && lastAssistant.After(promptTime) {
		m.DurationMs = lastAssistant.Sub(promptTime).Milliseconds()
	}
	// Hand the turn-start time to the engine so it can derive the duration from the Stop
	// hook's wall-clock end instead of the transcript's last-message timestamp, which the
	// hook reads mid-write (the final assistant message isn't flushed yet) — see Meta.PromptTime.
	m.PromptTime = promptTime
	return m, nil
}

// ParseAgentReply returns the assistant text emitted AFTER the last
// "Stop hook feedback:" re-wake injection — the agent's reaction to leoprevent.
//
// ⚠️ WHY NOT last_assistant_message. The Stop stdin carries the turn's last
// assistant MESSAGE, and a turn is not one message: an agent that interleaves tool
// calls with text emits several, and the substantive reasoning lands in an earlier
// one while the last is a short sign-off ("PR is green — say the word if you'd
// rather I…"). Shipping that one message as `agent_response` therefore captured a
// closing sentence and dropped the actual reasoning — including, on a push-back,
// the false-positive tuning signal the field exists to collect.
//
// The re-wake marker is the RIGHT boundary, not merely a wider one: text before it
// is what the agent was saying about its own work, and only text after it is a
// response to what we told it. The last marker, not the first, because a turn can
// block more than once.
//
// Best-effort by contract — no marker, an unreadable file or a format change all
// yield "" so the caller falls back to last_assistant_message. Never errors on
// content.
func ParseAgentReply(transcriptPath string) (string, error) {
	f, err := os.Open(transcriptPath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	lines, err := readJSONLLines(f)
	if err != nil {
		return "", err
	}
	var entries []entry
	for _, line := range lines {
		var e entry
		if json.Unmarshal(line, &e) == nil { // tolerate unknown/garbled lines
			entries = append(entries, e)
		}
	}

	// The LAST injection: one turn can be blocked more than once, and only the most
	// recent re-wake is the one this outcome is scoring.
	rewake := -1
	for i, e := range entries {
		if isStopHookFeedback(e) {
			rewake = i
		}
	}
	if rewake < 0 {
		return "", nil // no re-wake in this transcript — caller falls back
	}

	return assistantTextAfter(entries[rewake+1:]), nil
}

// assistantTextAfter concatenates the text blocks of the assistant entries in the
// given slice, in order, one blank line apart.
//
// ⚠️ DEDUPED BY MESSAGE ID, KEEPING THE LAST OCCURRENCE. Claude logs the same
// assistant message several times under one id (streamed partials, then the final,
// plus re-renders) — the same duplication ParseTurnMeta skips to avoid triple-counting
// tokens. Text needs the opposite resolution to usage: usage keeps the FIRST because
// every copy carries identical counts, whereas a partial is a PREFIX of the final, so
// keeping the first would ship a half-written sentence and keeping every copy would
// ship the reply three times over. Last-wins, ordered by first appearance.
func assistantTextAfter(entries []entry) string {
	var order []string
	text := map[string]string{}
	for _, e := range entries {
		if e.Type != "assistant" {
			continue
		}
		var blocks []contentBlock
		if err := json.Unmarshal(e.Message.Content, &blocks); err != nil {
			continue
		}
		var b strings.Builder
		for _, blk := range blocks {
			// text only: tool_use blocks are the agent's ACTIONS, already captured as
			// the before/after code, and their inputs would swamp the prose.
			if blk.Type != "text" || strings.TrimSpace(blk.Text) == "" {
				continue
			}
			if b.Len() > 0 {
				b.WriteString("\n")
			}
			b.WriteString(strings.TrimSpace(blk.Text))
		}
		if b.Len() == 0 {
			continue // a tool-call-only message contributes nothing
		}
		// A message with no id (older formats) cannot be deduped, so it is keyed by
		// position and always kept — over-reporting beats dropping the whole reply.
		key := e.Message.ID
		if key == "" {
			key = "\x00pos" + strconv.Itoa(len(order))
		}
		if _, seen := text[key]; !seen {
			order = append(order, key)
		}
		text[key] = b.String()
	}

	var out strings.Builder
	for _, k := range order {
		if out.Len() > 0 {
			out.WriteString("\n\n")
		}
		out.WriteString(text[k])
	}
	return capReply(out.String())
}

// capReply bounds the reply at limits.MaxAgentReplyBytes.
//
// It is a BODY that egresses on /outcome and is persisted, and it now spans a whole
// post-re-wake segment rather than one message, so its size is the agent's to choose.
// Truncation is rune-safe with a visible marker, matching how the server bounds
// model-authored finding fields.
func capReply(s string) string {
	if len(s) <= limits.MaxAgentReplyBytes {
		return s
	}
	cut := limits.MaxAgentReplyBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…[truncated]"
}

// isStopHookFeedback reports whether e is an INJECTED re-wake message — the exact
// complement of the "not a turn start" clause in isGenuineUserMessage, so the two
// can never disagree about what an injection looks like.
func isStopHookFeedback(e entry) bool {
	if e.Type != "user" || e.Message.Role != "user" {
		return false
	}
	var s string
	if err := json.Unmarshal(e.Message.Content, &s); err == nil {
		return strings.HasPrefix(strings.TrimSpace(s), stopHookFeedbackPrefix)
	}
	var blocks []contentBlock
	if err := json.Unmarshal(e.Message.Content, &blocks); err != nil {
		return false
	}
	for _, b := range blocks {
		if b.Type == "text" && strings.HasPrefix(strings.TrimSpace(b.Text), stopHookFeedbackPrefix) {
			return true
		}
	}
	return false
}

// userText returns the plain text of a user message entry (string content, or the
// concatenated text blocks of array content). Used for the turn-start prompt.
func userText(e entry) string {
	var s string
	if err := json.Unmarshal(e.Message.Content, &s); err == nil {
		return strings.TrimSpace(s)
	}
	var blocks []contentBlock
	if err := json.Unmarshal(e.Message.Content, &blocks); err != nil {
		return ""
	}
	var b strings.Builder
	for _, blk := range blocks {
		if blk.Type == "text" {
			if b.Len() > 0 {
				b.WriteByte('\n')
			}
			b.WriteString(blk.Text)
		}
	}
	return strings.TrimSpace(b.String())
}

// parseTime parses an RFC3339 transcript timestamp (fractional seconds tolerated),
// returning the zero time on any error so callers can test with IsZero.
func parseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

// isGenuineUserMessage reports whether e is a real user prompt: a user entry
// whose content is plain text (not tool_result blocks) and is not an injected
// "Stop hook feedback:" re-wake.
func isGenuineUserMessage(e entry) bool {
	if e.Type != "user" || e.Message.Role != "user" {
		return false
	}
	// String content.
	var s string
	if err := json.Unmarshal(e.Message.Content, &s); err == nil {
		return !strings.HasPrefix(strings.TrimSpace(s), stopHookFeedbackPrefix)
	}
	// Array content: genuine only if it has text blocks and no tool_result blocks.
	var blocks []contentBlock
	if err := json.Unmarshal(e.Message.Content, &blocks); err != nil {
		return false
	}
	hasText := false
	for _, b := range blocks {
		switch b.Type {
		case "tool_result":
			return false
		case "text":
			if strings.HasPrefix(strings.TrimSpace(b.Text), stopHookFeedbackPrefix) {
				return false
			}
			hasText = true
		}
	}
	return hasText
}

// readJSONLLines reads newline-delimited JSON and returns each non-blank line's
// bytes. It uses bufio.Reader (NOT Scanner) on purpose: a Scanner halts on a line
// bigger than its buffer, which would drop the rest of the transcript and silently
// skip review. ReadString reads any line length, so one huge tool-output line only
// affects itself. Shared by the Claude and Codex parsers.
func readJSONLLines(r io.Reader) ([][]byte, error) {
	br := bufio.NewReader(r)
	var lines [][]byte
	for {
		line, err := br.ReadString('\n')
		if s := strings.TrimSpace(line); s != "" {
			lines = append(lines, []byte(s))
		}
		if err != nil {
			if err == io.EOF {
				return lines, nil
			}
			return lines, err
		}
	}
}
