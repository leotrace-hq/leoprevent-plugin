package agent

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// withHome points the home and user-config seams at fresh temp dirs and clears the env
// overrides, so each case states exactly which roots exist.
func withHome(t *testing.T) (home, cfg string) {
	t.Helper()
	home, cfg = t.TempDir(), t.TempDir()
	oldHome, oldCfg := homeDir, userConfigDir
	homeDir = func() (string, error) { return home, nil }
	userConfigDir = func() (string, error) { return cfg, nil }
	t.Cleanup(func() { homeDir, userConfigDir = oldHome, oldCfg })
	for _, k := range []string{"CLAUDE_CONFIG_DIR", "CODEX_HOME", "COPILOT_HOME", "XDG_CONFIG_HOME"} {
		t.Setenv(k, "")
	}
	return home, cfg
}

func writeFile(t *testing.T, p string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestConfineTranscriptAdmitsEachAgentsOwnRoots(t *testing.T) {
	home, cfg := withHome(t)
	claudeDir, codexDir, copilotDir := t.TempDir(), t.TempDir(), t.TempDir()
	t.Setenv("CLAUDE_CONFIG_DIR", claudeDir)
	t.Setenv("CODEX_HOME", codexDir)
	t.Setenv("COPILOT_HOME", copilotDir)
	cases := []struct {
		name  string
		path  string
		roots func() []string
	}{
		{"claude default", filepath.Join(home, ".claude", "projects", "-repo", "s.jsonl"), ClaudeTranscriptRoots},
		{"claude config dir", filepath.Join(claudeDir, "projects", "-repo", "s.jsonl"), ClaudeTranscriptRoots},
		{"claude subagent", filepath.Join(home, ".claude", "projects", "-repo", "s", "subagents", "a.jsonl"), ClaudeTranscriptRoots},
		{"codex default", filepath.Join(home, ".codex", "sessions", "2026", "10", "29", "rollout.jsonl"), CodexTranscriptRoots},
		{"codex home", filepath.Join(codexDir, "sessions", "2026", "rollout.jsonl"), CodexTranscriptRoots},
		{"vscode", filepath.Join(cfg, "Code", "User", "workspaceStorage", "h", "GitHub.copilot-chat", "transcripts", "s.jsonl"), CopilotTranscriptRoots},
		{"vscode insiders", filepath.Join(cfg, "Code - Insiders", "User", "workspaceStorage", "h", "t.jsonl"), CopilotTranscriptRoots},
		{"vscode remote", filepath.Join(home, ".vscode-server", "data", "User", "workspaceStorage", "h", "t.jsonl"), CopilotTranscriptRoots},
		{"copilot cli", filepath.Join(home, ".copilot", "session-state", "s", "events.jsonl"), CopilotTranscriptRoots},
		{"copilot home", filepath.Join(copilotDir, "session-state", "events.jsonl"), CopilotTranscriptRoots},
	}
	for _, c := range cases {
		writeFile(t, c.path)
		if got := ConfineTranscript("test", c.path, c.roots()); got != realPath(t, c.path) {
			t.Errorf("%s: %q was rejected (got %q)", c.name, c.path, got)
		}
	}
}

func TestConfineTranscriptRejectsAPathOutsideTheRoots(t *testing.T) {
	home, _ := withHome(t)
	outside := writeFile(t, filepath.Join(t.TempDir(), "secret.jsonl"))
	projects := filepath.Join(home, ".claude", "projects")
	writeFile(t, filepath.Join(projects, "-repo", "s.jsonl"))
	writeFile(t, filepath.Join(home, ".claude", "projects-evil", "s.jsonl"))
	writeFile(t, filepath.Join(home, ".ssh", "id_ed25519"))
	cases := map[string]string{
		"elsewhere":           outside,
		"climbs out":          filepath.Join(projects, "-repo", "..", "..", "..", ".ssh", "id_ed25519"),
		"sibling with prefix": filepath.Join(home, ".claude", "projects-evil", "s.jsonl"),
		"the root itself":     projects,
		"another agent":       filepath.Join(home, ".codex", "sessions", "r.jsonl"),
		"relative climb":      filepath.Join("..", "..", "..", "..", "etc", "passwd"),
	}
	for name, p := range cases {
		if got := ConfineTranscript("claude", p, ClaudeTranscriptRoots()); got != "" {
			t.Errorf("%s: %q was admitted", name, p)
		}
	}
	if got := ConfineTranscript("claude", "", ClaudeTranscriptRoots()); got != "" {
		t.Errorf("empty path came back as %q", got)
	}
}

func TestConfineTranscriptResolvesSymlinksOnBothSides(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	home, _ := withHome(t)
	// A symlink INSIDE the root that points outside it must not smuggle a file in.
	outside := writeFile(t, filepath.Join(t.TempDir(), "secret.jsonl"))
	projects := filepath.Join(home, ".claude", "projects", "-repo")
	if err := os.MkdirAll(projects, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(projects, "s.jsonl")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if got := ConfineTranscript("claude", link, ClaudeTranscriptRoots()); got != "" {
		t.Errorf("a symlink out of the root was admitted: %q", got)
	}

	// A root that is itself a symlink (a container mount point such as LeoBench's, macOS
	// /var) still admits the paths under it, spelled through the link or through its target,
	// and both come back as the real path.
	real := t.TempDir()
	writeFile(t, filepath.Join(real, "projects", "-repo", "s.jsonl"))
	linkedCfg := filepath.Join(t.TempDir(), "claude-cfg")
	if err := os.Symlink(real, linkedCfg); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CLAUDE_CONFIG_DIR", linkedCfg)
	for _, p := range []string{
		filepath.Join(linkedCfg, "projects", "-repo", "s.jsonl"),
		filepath.Join(real, "projects", "-repo", "s.jsonl"),
	} {
		if got, want := ConfineTranscript("claude", p, ClaudeTranscriptRoots()), realPath(t, p); got != want {
			t.Errorf("%q under a symlinked root: got %q, want %q", p, got, want)
		}
	}
}

func TestConfineTranscriptRejectsAFileThatDoesNotExist(t *testing.T) {
	// A path that does not resolve is rejected, never judged lexically: a lexical check is
	// what a link/.. spelling slips past. Soft as ever: the turn just has no transcript.
	home, _ := withHome(t)
	p := filepath.Join(home, ".claude", "projects", "-repo", "s.jsonl")
	if got := ConfineTranscript("claude", p, ClaudeTranscriptRoots()); got != "" {
		t.Errorf("a missing transcript was admitted as %q", got)
	}
}

func TestConfineTranscriptResolvesALinkBeforeItsDotDot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	// <root>/link/../secret.jsonl cleans lexically to <root>/secret.jsonl, but the OS resolves
	// link first, so opening that spelling reads <outside>/../secret.jsonl. The check must
	// judge the path the OS opens, and hand on that path, not the spelling.
	home, _ := withHome(t)
	root := filepath.Join(home, ".claude", "projects")
	base := t.TempDir()
	outside := filepath.Join(base, "outside")
	writeFile(t, filepath.Join(base, "secret.jsonl"))
	writeFile(t, filepath.Join(outside, "secret.jsonl"))
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	sep := string(filepath.Separator)
	for _, p := range []string{
		// Concatenated, not Joined: Join would Clean the ".." away before the check sees it.
		root + sep + "link" + sep + ".." + sep + "secret.jsonl",
		filepath.Join(root, "link", "secret.jsonl"),
	} {
		if got := ConfineTranscript("claude", p, ClaudeTranscriptRoots()); got != "" {
			t.Errorf("%q was admitted as %q", p, got)
		}
	}
}

func TestConfineTranscriptHandsOnTheResolvedPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	// A link that stays inside the root is admitted, and the reader gets its target.
	home, _ := withHome(t)
	target := writeFile(t, filepath.Join(home, ".claude", "projects", "-repo", "s.jsonl"))
	link := filepath.Join(home, ".claude", "projects", "-other", "l.jsonl")
	if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if got, want := ConfineTranscript("claude", link, ClaudeTranscriptRoots()), realPath(t, target); got != want {
		t.Errorf("got %q, want the resolved %q", got, want)
	}
}

// realPath is p with every symlink resolved (macOS t.TempDir lives under /var -> /private/var).
func realPath(t *testing.T, p string) string {
	t.Helper()
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
