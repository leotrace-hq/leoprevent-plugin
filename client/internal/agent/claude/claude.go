// Package claude is the Claude Code adapter.
//
// Stop-hook stdin carries session_id, transcript_path, cwd, hook_event_name,
// stop_hook_active, …; ParseEvent normalizes them (SessionID/Cwd drive the git
// baseline).
//
// Changed-file discovery is PRIMARILY the git-baseline path (engine → vcs;
// agent-agnostic, sees Bash writes, full-file context). ChangedFiles below is the
// FALLBACK used only when there is no git baseline (not a git repo / no commits):
// it parses the transcript JSONL (Write/Edit/MultiEdit/NotebookEdit tool_use
// blocks) since the last genuine user message — the files the agent edited via its
// own tools this turn. That fallback retains the old Bash gap (files mutated via
// Bash aren't tool_use blocks → skipped); the git path does not.
//
// Re-wake is {"decision":"block","reason":…}, injected as a user message
// prefixed "Stop hook feedback:".
package claude

import (
	"encoding/json"
	"os"
	"strings"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/agent"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/review"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

// Adapter implements agent.Agent for Claude Code.
type Adapter struct{}

// New returns a Claude adapter.
func New() *Adapter { return &Adapter{} }

// Name identifies the adapter.
func (*Adapter) Name() string { return "claude" }

// entrypointEnv is the environment variable Claude Code exports naming the surface
// it was launched as. Hooks inherit it: Claude Code builds a hook's environment by
// spreading its own process environment, so a Stop hook sees whatever the app set.
const entrypointEnv = "CLAUDE_CODE_ENTRYPOINT"

// Environment reports which Claude Code surface this turn ran in, from
// $CLAUDE_CODE_ENTRYPOINT. Independent of the transcript and of stdin, so it is
// known even on turns where everything else about the agent fails to parse.
func (*Adapter) Environment(agent.Event) agent.Environment {
	raw := os.Getenv(entrypointEnv)
	return agent.Environment{Name: classifyEntrypoint(raw), Raw: raw}
}

// classifyEntrypoint maps a raw $CLAUDE_CODE_ENTRYPOINT onto the closed wire.Env*
// vocabulary. Pure, so the mapping is tested directly rather than through the
// process environment.
//
// The cases below are the values Claude Code itself recognizes; they are grouped by
// PRODUCT SURFACE, which is the question this field answers ("was this the desktop
// app or the terminal"), not by transport. That is why the remote_* family splits
// rather than collapsing into one "remote" bucket: a remote session driven from the
// desktop app is still the desktop app to the developer who ran it, and folding it
// in with claude.ai would answer a question nobody asked.
//
// An unrecognized value is EnvUnknown ON PURPOSE — it is not guessed at by prefix.
// A wrong bucket is worse than an honest unknown here, because it is invisible: it
// silently inflates a real surface's numbers, whereas an unknown paired with
// TurnMeta.EnvironmentRaw is self-announcing and tells us exactly what to add.
func classifyEntrypoint(raw string) string {
	switch raw {
	case "cli", "ssh-remote", "bench":
		return wire.EnvClaudeTerminal
	case "claude-desktop", "claude-desktop-3p", "remote_desktop":
		return wire.EnvClaudeDesktop
	case "remote", "remote_baku", "remote_trigger":
		return wire.EnvClaudeWeb
	case "remote_mobile":
		return wire.EnvClaudeMobile
	case "claude-vscode":
		return wire.EnvClaudeVSCode
	case "local-agent", "local_agent", "remote_cowork", "claude-coworker", "claude-coworker-terminal":
		return wire.EnvClaudeCowork
	case "sdk-cli", "sdk-ts", "sdk-py", "mcp":
		return wire.EnvClaudeSDK
	default:
		return wire.EnvUnknown
	}
}

// hookPayload is the Claude hook stdin JSON (verified fields). The same shape
// covers both the UserPromptSubmit and Stop events we register for; cwd +
// session_id are present on both.
type hookPayload struct {
	SessionID            string `json:"session_id"`
	TranscriptPath       string `json:"transcript_path"`
	HookEventName        string `json:"hook_event_name"`
	StopHookActive       bool   `json:"stop_hook_active"`
	Cwd                  string `json:"cwd"`
	LastAssistantMessage string `json:"last_assistant_message"`
	// Prompt and PromptID are sent on UserPromptSubmit. Prompt is read only to
	// recognise a task notification and is never stored or sent anywhere.
	Prompt   string `json:"prompt"`
	PromptID string `json:"prompt_id"`
	// ToolInput is the PreToolUse tool argument object. Decoded loosely because the
	// shape differs per tool and we want exactly one field out of it (the path).
	ToolInput       map[string]any  `json:"tool_input"`
	BackgroundTasks json.RawMessage `json:"background_tasks"`
}

type backgroundTask struct {
	ID     string `json:"id"`
	Type   string `json:"type"`
	Status string `json:"status"`
}

func parseBackgroundTasks(
	raw json.RawMessage,
) ([]agent.BackgroundTask, bool) {
	switch strings.TrimSpace(string(raw)) {
	case "", "null", "[]", "{}":
		return nil, false
	}
	var entries []json.RawMessage
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, true
	}
	var tasks []agent.BackgroundTask
	agentWork := false
	for _, entry := range entries {
		var t backgroundTask
		if err := json.Unmarshal(entry, &t); err != nil || t.ID == "" {
			agentWork = true
			continue
		}
		tasks = append(tasks, agent.BackgroundTask{ID: t.ID, Type: t.Type, Status: t.Status})
		switch t.Type {
		case "subagent", "workflow", "teammate":
			agentWork = true
		}
	}
	return tasks, agentWork
}

// ParseEvent decodes Claude's hook stdin (UserPromptSubmit or Stop).
func (*Adapter) ParseEvent(stdin []byte) (agent.Event, error) {
	var p hookPayload
	if err := json.Unmarshal(stdin, &p); err != nil {
		return agent.Event{}, err
	}
	tasks, agentWork := parseBackgroundTasks(p.BackgroundTasks)
	return agent.Event{
		Name:                 p.HookEventName,
		StopHookActive:       p.StopHookActive,
		TranscriptPath:       agent.ConfineTranscript("claude", p.TranscriptPath, agent.ClaudeTranscriptRoots()),
		SessionID:            p.SessionID,
		Cwd:                  p.Cwd,
		LastAssistantMessage: p.LastAssistantMessage,
		PromptID:             p.PromptID,
		TaskNotification:     strings.HasPrefix(strings.TrimSpace(p.Prompt), taskNotificationPrefix),
		EditPaths:            agent.EditPathsFromToolInput(p.ToolInput),
		BackgroundWork:       agentWork,
		BackgroundTasks:      tasks,
	}, nil
}

// taskNotificationPrefix opens the prompt Claude Code submits when a background task
// (Bash run_in_background, Monitor, a background agent) finishes. It is delivered as a
// UserPromptSubmit, mid-turn when the agent is still working.
const taskNotificationPrefix = "<task-notification>"

// ChangedFiles returns ONLY the files the agent edited via its file tools this
// turn (from the transcript). See the package doc for the Bash-write limitation.
func (*Adapter) ChangedFiles(ev agent.Event) ([]transcript.Change, error) {
	if ev.TranscriptPath == "" {
		return nil, nil
	}
	return transcript.ParseChanges(ev.TranscriptPath)
}

// AgentReply returns the agent's prose after our re-wake, from the transcript —
// the reply the Stop stdin's last_assistant_message truncates to its final message.
// Best-effort: no transcript path or no re-wake in it yields "", and the engine
// falls back.
func (*Adapter) AgentReply(ev agent.Event) (string, error) {
	if ev.TranscriptPath == "" {
		return "", nil
	}
	return transcript.ParseAgentReply(ev.TranscriptPath)
}

// TurnMeta extracts the coding agent's own turn activity (model, prompt, token
// usage, wall-clock) from the Claude transcript JSONL. Best-effort: no transcript
// path → zero meta; a read/parse error surfaces for the engine to log and ignore.
func (*Adapter) TurnMeta(ev agent.Event) (agent.TurnMeta, error) {
	if ev.TranscriptPath == "" {
		return agent.TurnMeta{}, nil
	}
	m, err := transcript.ParseTurnMeta(ev.TranscriptPath)
	if err != nil {
		return agent.TurnMeta{}, err
	}
	return agent.TurnMeta{
		AgentModel:          m.AgentModel,
		Prompt:              m.Prompt,
		InputTokens:         m.InputTokens,
		CacheCreationTokens: m.CacheCreationTokens,
		CacheReadTokens:     m.CacheReadTokens,
		OutputTokens:        m.OutputTokens,
		DurationMs:          m.DurationMs,
		Speed:               m.Speed,
		PromptTime:          m.PromptTime, // set → engine derives duration from the wall-clock end
	}, nil
}

func (a *Adapter) DeliverReview(
	prompt, banner string,
	fileCount int,
	findings []wire.Finding,
	summary string,
) ([]byte, error) {
	prompt += askDecisionAsk(findings)
	if a.Environment(agent.Event{}).Name == wire.EnvClaudeTerminal {
		return review.RewakeJSON(prompt, banner)
	}
	ctx := review.ReviewContextMessageWith(summary, fileCount, findings, review.ForceFixedCount(findings))
	return review.RewakeWithContextJSON(prompt, banner, ctx)
}

const askUserQuestionEnv = "CLAUDE_CODE_ENABLE_ASK_USER_QUESTION_TOOL"

// OfferQuestion asks for the session scan's offer (LEO-673) to be put to the developer the
// Claude surface's own way, replacing the offer's "at the end of your reply" rather than adding a
// second way to ask. Its yes says "them", since the question may cover fewer packages than the
// notice lists.
//
//   - With AskUserQuestion switched on (the same switch as askDecisionAsk), the question is asked
//     with it under offerHeader, so the answer can be read back (ScanOfferAnswered): any option is
//     an answer, and "Not now" is the one way to decline that the hook can see.
//   - In the desktop app it has a third option, "Fix in a new session" (decided 23 Oct 2026): a
//     session of its own, forked from this one, so the developer carries on with their task. Its
//     prompt ends with fixSessionMarker, so that session's scan knows it is the fix and quietens
//     what was already there (ScanFixSession, internal/depquiet). A session card alone was tried
//     first: dismissing it, the developer's "Not now", never reaches the transcript.
//   - In the desktop app without AskUserQuestion, the fix session is proposed as a card.
//   - Otherwise nothing is added and the plain one-line question stands.
func (*Adapter) OfferQuestion() string {
	desktop := classifyEntrypoint(os.Getenv(entrypointEnv)) == wire.EnvClaudeDesktop
	asks := os.Getenv(askUserQuestionEnv) == "true"
	session := func(initiation string) string {
		return "call start_session with initiation \"" + initiation + "\", context \"fork\", a title such as \"Fix vulnerable dependencies\", and a prompt that opens with one plain sentence saying what it will fix (the session card shows it), then everything after \"If they say yes:\" above, then \"Fix only these dependencies. Any code findings from LeoPrevent's security review are being fixed in the original session: don't change code for them.\", and ends with the line \"" + fixSessionMarker + "\". Make no dependency changes in this session."
	}
	ask := "\nInstead of writing that question at the end of your reply, ask it with the AskUserQuestion tool, once LeoPrevent's dependency notice is in your reply, with the header \"" + offerHeader + "\" and "
	// The answered line is for a plain-text question, whose answer can't be read otherwise. Where
	// the question is AskUserQuestion's, or there is none, it's noise in the reply.
	noLine := " LeoPrevent reads this answer itself, so leave out the line \"" + wire.OfferAnsweredLine + "\""
	switch {
	case desktop && asks:
		return ask + "three options: \"Fix in a new session\", \"Fix here\" and \"Not now\". " +
			"For \"Fix in a new session\", " + session("user_asked") + " If the session can't be started, propose it instead (initiation \"own_initiative\"). " +
			"For \"Fix here\", follow everything after \"If they say yes:\" above in this session. For \"Not now\", change nothing." + noLine
	case desktop:
		return "\nDon't ask that question. Instead, once LeoPrevent's dependency notice is in your reply, propose the fix as a session of its own: " + session("own_initiative") + noLine
	case asks:
		return ask + "two options: \"Yes, fix them\" and \"Not now\"." + noLine
	}
	return ""
}

// offerHeader heads the scan's AskUserQuestion, so its answer is found in the transcript whatever
// the question's wording (which the server writes) or the options the agent ends up showing.
const offerHeader = "LeoPrevent"

// fixSessionMarker ends the prompt of the session proposed to fix the scan's offer: last, so
// the session card, which shows the prompt's first line, says what the session will do.
const fixSessionMarker = "[LeoPrevent: dependency fix session]"

// ScanOfferAnswered reports whether the developer answered the scan's question in this session,
// however it was asked: an AskUserQuestion answer under offerHeader, where the client has the
// tool, or the agent's reply ending with one of wire.OfferAnsweredLines, which the offer asks for after any
// answer, so a typed "no" counts too. Each quietens what the scan listed (internal/depquiet).
func (*Adapter) ScanOfferAnswered(transcriptPath string) bool {
	if transcript.OfferAnswered(transcriptPath, offerHeader) {
		return true
	}
	for _, line := range wire.OfferAnsweredLines {
		if transcript.AgentSaidLine(transcriptPath, line) {
			return true
		}
	}
	return false
}

// ScanFixSession reports a session started to fix the scan's offer: one whose prompt carries
// fixSessionMarker.
func (*Adapter) ScanFixSession(transcriptPath string) bool {
	return transcript.PromptHas(transcriptPath, fixSessionMarker)
}

func askDecisionAsk(
	findings []wire.Finding,
) string {
	if os.Getenv(askUserQuestionEnv) != "true" {
		return ""
	}
	decide := 0
	for _, f := range findings {
		if f.SuggestOnly && !f.Virtual && !isScannerDispute(f.Rule) {
			decide++
		}
	}
	ask := review.DecisionAsk(decide)
	if ask == "" {
		return ""
	}
	return "\n" + ask + "\n"
}

func isScannerDispute(
	rule string,
) bool {
	for _, d := range wire.ScannerDisputes {
		if strings.HasPrefix(rule, d.Prefix) {
			return true
		}
	}
	return false
}

// DeliverFirstClean delivers the one-time first-clean notice. The terminal renders a
// systemMessage, so it stays a non-blocking notice there; every other Claude surface hides it,
// so there it re-wakes the agent once to say it in its reply (review.FirstCleanRelayPrompt).
func (a *Adapter) DeliverFirstClean(
	message string,
) ([]byte, error) {
	if a.Environment(agent.Event{}).Name == wire.EnvClaudeTerminal {
		return review.NoticeJSON(message)
	}
	return review.RewakeJSON(review.FirstCleanRelayPrompt(), message)
}

const remoteEnv = "CLAUDE_CODE_REMOTE"

func (*Adapter) EphemeralHost() bool {
	return os.Getenv(remoteEnv) == "true" || strings.HasPrefix(os.Getenv(entrypointEnv), "remote")
}

// DeliverNotice wraps a non-blocking developer notice as Claude's Stop-hook
// output: a systemMessage with no decision, so it's shown but the turn yields.
func (*Adapter) DeliverNotice(message string) ([]byte, error) {
	return review.NoticeJSON(message)
}

func (a *Adapter) DeliverPromptNotice(
	message, context string,
) ([]byte, error) {
	if a.Environment(agent.Event{}).Name == wire.EnvClaudeTerminal {
		return review.NoticeJSON(message)
	}
	return review.PromptNoticeJSON(message, context)
}

// WakeForDependencies wakes the agent with the dependency check's instructions (LEO-620): after a
// review's prompt, which stays as it is; in place of the first-clean relay's "nothing else", with
// its notice kept; or on their own. Any systemMessage is kept. Every surface is woken the same
// way, since the agent has to act; the developer's notice is added after this (RelayForDeveloper).
func (a *Adapter) WakeForDependencies(out []byte, prompt string) ([]byte, error) {
	merged, _, err := review.WithDependencyWake(out, prompt)
	return merged, err
}

// RelayForDeveloper adds a notice meant only for the developer to out, the hook output this Stop
// already has (LEO-620, decision D59). It returns the new output and the exact markdown the agent
// was asked to print, or "" when it wasn't asked.
//
//   - Terminal: a systemMessage is shown verbatim, so the notice joins out's (or becomes a
//     plain notice). The agent is never involved.
//   - Desktop app and claude.ai don't show a systemMessage, so the agent prints it:
//   - nothing else to say: a wake whose only job is to print the notice and stop;
//   - the first-clean relay: the notice joins it, so one reply carries both;
//   - a review wake: its instructions are kept as they are, and the agent is also asked to print
//     the notice after LeoPrevent's review block;
//   - a plain notice (a skipped or HEAD-anchored review): kept, plus a wake to print the notice.
//
// The notice is always added to the systemMessage too, so the terminal and the developer's log
// see the same thing. What the agent prints is markdown, the same notice with its advisories
// linked (notice itself when markdown is "").
func (a *Adapter) RelayForDeveloper(out []byte, notice, markdown, before string) ([]byte, string, error) {
	if a.Environment(agent.Event{}).Name == wire.EnvClaudeTerminal {
		hook := map[string]json.RawMessage{}
		if len(strings.TrimSpace(string(out))) > 0 {
			if err := json.Unmarshal(out, &hook); err != nil {
				return out, "", err
			}
		}
		var existing string
		_ = json.Unmarshal(hook["systemMessage"], &existing)
		hook["systemMessage"], _ = json.Marshal(strings.TrimSpace(strings.Join([]string{existing, notice}, "\n\n")))
		merged, err := json.Marshal(hook)
		return merged, "", err
	}
	merged, _, printed, err := review.WithDeveloperRelay(out, notice, markdown, before)
	if err != nil {
		return out, "", err
	}
	return merged, printed, nil
}
