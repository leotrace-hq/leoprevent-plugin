package claude

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/agent"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/review"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

func TestParseEvent(t *testing.T) {
	ev, err := New().ParseEvent([]byte(`{"stop_hook_active":true,"transcript_path":"/t/x.jsonl","cwd":"/work","hook_event_name":"Stop"}`))
	if err != nil {
		t.Fatal(err)
	}
	if !ev.StopHookActive || ev.TranscriptPath != "/t/x.jsonl" {
		t.Errorf("unexpected event: %+v", ev)
	}
}

func TestChangedFilesFromTranscript(t *testing.T) {
	dir := t.TempDir()
	tp := filepath.Join(dir, "t.jsonl")
	lines := []string{
		`{"type":"user","message":{"role":"user","content":"add a route"}}`,
		`{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","name":"Write","input":{"file_path":"/p/app.py","content":"resp = requests.get(url)"}}]}}`,
	}
	if err := os.WriteFile(tp, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	changes, err := New().ChangedFiles(agent.Event{TranscriptPath: tp})
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 1 || changes[0].FilePath != "/p/app.py" {
		t.Fatalf("unexpected changes: %+v", changes)
	}
	if !strings.Contains(changes[0].AddedText, "requests.get(url)") {
		t.Errorf("added text missing: %q", changes[0].AddedText)
	}
}

// ChangedFiles must ignore the working tree entirely: a dirty/untracked file the
// agent did NOT edit via its tools this turn is not reviewed. Regression for the
// "fired on a pasted file during an unrelated turn" surprise.
func TestIgnoresWorkingTree(t *testing.T) {
	repo := t.TempDir()
	// An untracked vulnerable file the "agent" never touched this turn.
	if err := os.WriteFile(filepath.Join(repo, "pasted.py"),
		[]byte("import requests\nrequests.get(request.args['url'])\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Transcript shows the agent edited only an unrelated, neutral file this turn.
	tp := filepath.Join(repo, "t.jsonl")
	lines := []string{
		`{"type":"user","message":{"role":"user","content":"pin the model"}}`,
		`{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","name":"Write","input":{"file_path":"` + repo + `/.claude/settings.json","content":"{\"model\":\"x\"}"}}]}}`,
	}
	if err := os.WriteFile(tp, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	changes, err := New().ChangedFiles(agent.Event{TranscriptPath: tp})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range changes {
		if strings.HasSuffix(c.FilePath, "pasted.py") {
			t.Errorf("must ignore the untracked working-tree file, got %+v", changes)
		}
	}
}

func TestDeliverReviewIsBlockDecision(t *testing.T) {
	banner := "🔒 LeoPrevent: security review (1 file)"
	out, err := New().DeliverReview("review this", banner, 1, []wire.Finding{{Rule: "sql-injection"}})
	if err != nil {
		t.Fatal(err)
	}
	var d struct {
		Decision      string `json:"decision"`
		Reason        string `json:"reason"`
		SystemMessage string `json:"systemMessage"`
	}
	if err := json.Unmarshal(out, &d); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if d.Decision != "block" {
		t.Errorf("decision = %q, want block", d.Decision)
	}
	if !strings.Contains(d.Reason, "review this") {
		t.Errorf("reason missing prompt: %q", d.Reason)
	}
	if d.SystemMessage != banner {
		t.Errorf("systemMessage = %q, want banner %q", d.SystemMessage, banner)
	}
}

// DeliverNotice is the fail-open counterpart: a systemMessage with NO decision,
// so the developer sees it but the turn still yields (never trapped on an outage).
func TestDeliverNoticeIsNonBlocking(t *testing.T) {
	out, err := New().DeliverNotice("⚠️ license invalid")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if _, ok := m["decision"]; ok {
		t.Errorf("notice must NOT block (no decision), got %s", out)
	}
	if m["systemMessage"] != "⚠️ license invalid" {
		t.Errorf("systemMessage = %v, want the message", m["systemMessage"])
	}
}

func TestName(t *testing.T) {
	if New().Name() != "claude" {
		t.Errorf("Name = %q", New().Name())
	}
}

// TestParseEventBaselineFields pins the fields that drive the git baseline +
// routing — SessionID/Cwd (baseline) and Name (UserPromptSubmit vs Stop). These
// are load-bearing for the primary detection path and were previously untested.
func TestParseEventBaselineFields(t *testing.T) {
	ev, err := New().ParseEvent([]byte(`{"hook_event_name":"UserPromptSubmit","session_id":"sess-1","cwd":"/repo","transcript_path":"/t/x.jsonl"}`))
	if err != nil {
		t.Fatal(err)
	}
	if ev.Name != "UserPromptSubmit" || !ev.IsUserPromptSubmit() {
		t.Errorf("UserPromptSubmit routing field not parsed: %+v", ev)
	}
	if ev.SessionID != "sess-1" || ev.Cwd != "/repo" {
		t.Errorf("SessionID/Cwd drive the git baseline but weren't parsed: %+v", ev)
	}
}

// Claude is the ONE adapter that carries the injected-context half of the update
// nag: a systemMessage is not forwarded over stream-json, so without this the notice
// never reaches the desktop app or claude.ai. Counterpart to the codex/copilot guards
// that assert those two stay systemMessage-only.
func TestDeliverPromptNoticeCarriesInjectedContext(t *testing.T) {
	out, err := (&Adapter{}).DeliverPromptNotice("⚠️  update available", "tell the developer")
	if err != nil {
		t.Fatalf("DeliverPromptNotice: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if m["systemMessage"] != "⚠️  update available" {
		t.Errorf("systemMessage = %v, want the verbatim message", m["systemMessage"])
	}
	hso, ok := m["hookSpecificOutput"].(map[string]any)
	if !ok {
		t.Fatalf("claude MUST emit hookSpecificOutput (the only channel the app/web UI sees); got %s", out)
	}
	if hso["hookEventName"] != "UserPromptSubmit" {
		t.Errorf("hookEventName = %v, want UserPromptSubmit", hso["hookEventName"])
	}
	if hso["additionalContext"] != "tell the developer" {
		t.Errorf("additionalContext = %v, want the injected context", hso["additionalContext"])
	}
	if _, ok := m["decision"]; ok {
		t.Errorf("prompt notice must NOT block the prompt; got %s", out)
	}
}

// TestDeliverReviewCarriesContextChannel pins the Stop-path fix: a BLOCK must
// carry hookSpecificOutput.additionalContext as well as the systemMessage banner.
//
// Why it matters: systemMessage is terminal-only (not forwarded over stream-json),
// so on the desktop app and claude.ai a review that fires is otherwise invisible —
// the developer sees code change with no indication a security review caused it.
// The context channel is the only one those surfaces render. Verified against CC
// 2.1.221: a Stop output with BOTH a block decision and additionalContext delivers
// the context to the model, while its systemMessage produces zero wire records.
func TestDeliverReviewCarriesContextChannel(t *testing.T) {
	out, err := New().DeliverReview("FINDINGS", "🔒 LeoPrevent: security review (2 files)", 2, []wire.Finding{{Rule: "sql-injection"}})
	if err != nil {
		t.Fatalf("DeliverReview: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if m["decision"] != "block" {
		t.Errorf("decision = %v, want block (the re-wake must still block)", m["decision"])
	}
	if m["reason"] != "FINDINGS" {
		t.Errorf("reason = %v, want the findings prompt unchanged", m["reason"])
	}
	hso, ok := m["hookSpecificOutput"].(map[string]any)
	if !ok {
		t.Fatalf("claude MUST emit hookSpecificOutput on a block (the only channel the app/web UI sees); got %s", out)
	}
	if hso["hookEventName"] != "Stop" {
		t.Errorf("hookEventName = %v, want Stop", hso["hookEventName"])
	}
	ctx, _ := hso["additionalContext"].(string)
	if !strings.Contains(ctx, "security review") {
		t.Errorf("additionalContext must tell the developer a review ran; got %q", ctx)
	}
	if !strings.Contains(ctx, "2 changed files") {
		t.Errorf("additionalContext should state the reviewed file count; got %q", ctx)
	}
}

// TestReviewContextExcludesGitlessWarning pins a REGRESSION: the context message
// must describe what happened, never the banner's diagnostic suffix.
//
// The first cut passed the whole banner into the context "so the channels can't
// drift". But engine.Run appends review.GitlessWarning to the banner on a
// degraded run, so the developer-facing notice rendered "⚠️ no git repo here" in
// a repo that IS a git repo (the baseline was missing for an unrelated reason) —
// a false-looking claim about their project in the one line they actually see.
func TestReviewContextExcludesGitlessWarning(t *testing.T) {
	banner := "🔒 LeoPrevent: security review (1 file) " + review.GitlessWarning
	out, err := New().DeliverReview("FINDINGS", banner, 1, []wire.Finding{{Rule: "sql-injection"}})
	if err != nil {
		t.Fatalf("DeliverReview: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// The terminal channel KEEPS the warning — it's useful there.
	if sm, _ := m["systemMessage"].(string); !strings.Contains(sm, "no git repo") {
		t.Errorf("systemMessage should keep the gitless warning; got %q", sm)
	}
	hso, _ := m["hookSpecificOutput"].(map[string]any)
	ctx, _ := hso["additionalContext"].(string)
	if strings.Contains(ctx, "no git repo") {
		t.Errorf("additionalContext must NOT restate the gitless warning; got %q", ctx)
	}
}

// TestReviewContextStatesSurfacedNotFixed pins the wording split. The re-wake
// fires on three outcomes and only INTRODUCED findings are force-fixed —
// suggest-only and pre-existing ones are surfaced, with the agent explicitly told
// not to touch them. The first cut said "addressed below" unconditionally, which
// promised a fix that never came. That is the COMMON case on a degraded run (no
// baseline ⇒ nothing anchorable ⇒ everything classified pre-existing), not an edge.
func TestReviewContextStatesSurfacedNotFixed(t *testing.T) {
	ctxOf := func(findings []wire.Finding) string {
		out, err := New().DeliverReview("FINDINGS", "banner", 1, findings)
		if err != nil {
			t.Fatalf("DeliverReview: %v", err)
		}
		var m map[string]any
		if err := json.Unmarshal(out, &m); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		hso, _ := m["hookSpecificOutput"].(map[string]any)
		s, _ := hso["additionalContext"].(string)
		return s
	}

	// All pre-existing → surfaced, nothing fixed. Must NOT promise a fix.
	pre := ctxOf([]wire.Finding{{Rule: "a", Preexisting: true}, {Rule: "b", Preexisting: true}})
	if strings.Contains(pre, "and fixed") {
		t.Errorf("surfaced-only notice must not claim a fix; got %q", pre)
	}
	if !strings.Contains(pre, "2 findings") || !strings.Contains(pre, "your decision") {
		t.Errorf("surfaced-only notice should say what's waiting on the dev; got %q", pre)
	}

	// Suggest-only is surfaced too, even though it is NOT pre-existing.
	sug := ctxOf([]wire.Finding{{Rule: "a", SuggestOnly: true}})
	if strings.Contains(sug, "and fixed") {
		t.Errorf("suggest-only must not be reported as fixed; got %q", sug)
	}

	// All introduced → genuinely fixed in-turn.
	fix := ctxOf([]wire.Finding{{Rule: "a"}, {Rule: "b"}})
	if !strings.Contains(fix, "fixed 2 findings") {
		t.Errorf("introduced findings are force-fixed; got %q", fix)
	}

	// Mixed → both halves stated, so neither is over- nor under-claimed.
	mix := ctxOf([]wire.Finding{{Rule: "a"}, {Rule: "b", Preexisting: true}})
	if !strings.Contains(mix, "fixed 1 finding") || !strings.Contains(mix, "surfaced 1 more") {
		t.Errorf("mixed notice must state both halves; got %q", mix)
	}
}

// The entrypoint mapping. Every input here is a value Claude Code itself ships, so
// this table doubles as the record of which vendor spellings we have accounted for.
func TestClassifyEntrypoint(t *testing.T) {
	for _, tc := range []struct {
		raw, want string
	}{
		{"cli", wire.EnvClaudeTerminal},
		{"ssh-remote", wire.EnvClaudeTerminal},
		{"bench", wire.EnvClaudeTerminal},
		{"claude-desktop", wire.EnvClaudeDesktop},
		{"claude-desktop-3p", wire.EnvClaudeDesktop},
		// A remote session DRIVEN FROM the desktop app is still the desktop app to the
		// developer sitting in front of it — grouped by surface, not by transport.
		{"remote_desktop", wire.EnvClaudeDesktop},
		{"remote", wire.EnvClaudeWeb},
		{"remote_baku", wire.EnvClaudeWeb},
		{"remote_trigger", wire.EnvClaudeWeb},
		{"remote_mobile", wire.EnvClaudeMobile},
		{"claude-vscode", wire.EnvClaudeVSCode},
		{"local-agent", wire.EnvClaudeCowork},
		{"local_agent", wire.EnvClaudeCowork},
		{"remote_cowork", wire.EnvClaudeCowork},
		{"claude-coworker", wire.EnvClaudeCowork},
		{"claude-coworker-terminal", wire.EnvClaudeCowork},
		{"sdk-cli", wire.EnvClaudeSDK},
		{"sdk-ts", wire.EnvClaudeSDK},
		{"sdk-py", wire.EnvClaudeSDK},
		{"mcp", wire.EnvClaudeSDK},
	} {
		if got := classifyEntrypoint(tc.raw); got != tc.want {
			t.Errorf("classifyEntrypoint(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

// An unrecognized entrypoint must NOT be guessed at by prefix. A wrong bucket is
// worse than an honest unknown because it is invisible — it silently inflates a
// real surface — whereas unknown+raw announces itself and names its own fix.
func TestClassifyEntrypointDoesNotGuess(t *testing.T) {
	for _, raw := range []string{
		"",
		"claude-desktop-next", // looks desktop-ish; is not a value we know
		"remote_hologram",     // looks remote-ish; ditto
		"cli-v2",
		"totally-new-surface",
	} {
		if got := classifyEntrypoint(raw); got != wire.EnvUnknown {
			t.Errorf("classifyEntrypoint(%q) = %q, want %q — the mapping must not extrapolate", raw, got, wire.EnvUnknown)
		}
	}
}

// Environment reads the live entrypoint and reports BOTH halves: the bucket, and the
// raw value behind it. The raw half is what makes a surface visible on the very first
// turn it appears, rather than after we ship a client that knows about it.
func TestEnvironmentReportsBucketAndRaw(t *testing.T) {
	t.Setenv(entrypointEnv, "claude-desktop")
	if env := New().Environment(agent.Event{}); env.Name != wire.EnvClaudeDesktop || env.Raw != "claude-desktop" {
		t.Errorf("Environment() = %+v, want {claude-code-desktop claude-desktop}", env)
	}

	// A surface newer than this build: bucket unknown, but the log still records what
	// it actually was.
	t.Setenv(entrypointEnv, "claude-hologram")
	env := New().Environment(agent.Event{})
	if env.Name != wire.EnvUnknown {
		t.Errorf("unrecognized entrypoint should bucket unknown, got %q", env.Name)
	}
	if env.Raw != "claude-hologram" {
		t.Errorf("raw signal must survive an unrecognized bucket, got %q", env.Raw)
	}
}

// No entrypoint at all is unknown with an EMPTY raw. That pairing is what the server
// reads as "a current client looked and found nothing", as distinct from an absent
// Environment field, which means a client too old to look at all.
func TestEnvironmentUnsetIsUnknownWithNoRaw(t *testing.T) {
	t.Setenv(entrypointEnv, "")
	env := New().Environment(agent.Event{})
	if env.Name != wire.EnvUnknown || env.Raw != "" {
		t.Errorf("Environment() with no entrypoint = %+v, want {unknown }", env)
	}
}
