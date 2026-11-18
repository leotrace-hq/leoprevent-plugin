package agent

import (
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// The hook's transcript_path comes from stdin, and every transcript reader (changed-file
// fallback, agent reply, turn meta, MCP connector edits, the scan-offer readers) opens it as
// the developer. The path is the agent's own, so nothing crosses a privilege boundary, but a
// path the plugin will read and then ship parts of (the prompt, the reply) should be one the
// agent could actually have written (LEO-334). Each adapter therefore confines it to that
// agent's own transcript roots in ParseEvent, before any reader sees it.
//
// ⚠️ SOFT CONFINEMENT, NEVER AN ERROR. A path outside the roots is logged and dropped
// (Event.TranscriptPath becomes ""), which every reader already treats as "no transcript":
// the git path still reviews, and only the transcript-derived extras (gitless fallback,
// reply, meta) go missing for that turn. A root list that misses a legitimate location
// therefore costs analytics, never a blocked stop. The roots are documented in
// docs/agents.md § Transcript path confinement.

// homeDir and userConfigDir are seams so the root lists are testable without touching the
// real home directory.
var (
	homeDir       = os.UserHomeDir
	userConfigDir = os.UserConfigDir
)

// extraTranscriptRoots are added to every agent's roots. Test-only (see
// AllowTranscriptRootForTest); nothing in the shipped binary sets it.
var extraTranscriptRoots []string

// AllowTranscriptRootForTest admits dir as a transcript root for every agent and returns a
// restore func. It lets tests in other packages (the engine's, which drive whole hook runs
// through ParseEvent with transcripts under t.TempDir) keep working without pointing HOME at
// the temp dir. Test-only.
func AllowTranscriptRootForTest(dir string) func() {
	old := extraTranscriptRoots
	extraTranscriptRoots = append(append([]string(nil), old...), dir)
	return func() { extraTranscriptRoots = old }
}

// ClaudeTranscriptRoots is where Claude Code writes session transcripts:
// $CLAUDE_CONFIG_DIR/projects when that is set, and ~/.claude/projects (both are admitted, so
// a hook whose environment differs from the CLI's in that one variable still reads).
func ClaudeTranscriptRoots() []string {
	var roots []string
	if d := os.Getenv("CLAUDE_CONFIG_DIR"); d != "" {
		roots = append(roots, filepath.Join(d, "projects"))
	}
	if h := home(); h != "" {
		roots = append(roots, filepath.Join(h, ".claude", "projects"))
	}
	return roots
}

// CodexTranscriptRoots is where Codex writes rollouts: $CODEX_HOME/sessions when set, and
// ~/.codex/sessions.
func CodexTranscriptRoots() []string {
	var roots []string
	if d := os.Getenv("CODEX_HOME"); d != "" {
		roots = append(roots, filepath.Join(d, "sessions"))
	}
	if h := home(); h != "" {
		roots = append(roots, filepath.Join(h, ".codex", "sessions"))
	}
	return roots
}

// CopilotTranscriptRoots covers both Copilot runtimes. VS Code keeps the transcript under its
// per-user data dir (<User>/workspaceStorage/<wsHash>/GitHub.copilot-chat/transcripts/, and
// globalStorage for a window with no workspace), so the whole User dir is admitted for stable
// and Insiders, local and Remote (vscode-server). The Copilot CLI keeps its state under
// ~/.copilot, $COPILOT_HOME or $XDG_CONFIG_HOME/.copilot.
func CopilotTranscriptRoots() []string {
	var roots []string
	if base, err := userConfigDir(); err == nil && base != "" {
		for _, app := range []string{"Code", "Code - Insiders"} {
			roots = append(roots, filepath.Join(base, app, "User"))
		}
	}
	h := home()
	if h != "" {
		for _, server := range []string{".vscode-server", ".vscode-server-insiders"} {
			roots = append(roots, filepath.Join(h, server, "data", "User"))
		}
		roots = append(roots, filepath.Join(h, ".copilot"))
	}
	if d := os.Getenv("COPILOT_HOME"); d != "" {
		roots = append(roots, d)
	}
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" {
		roots = append(roots, filepath.Join(d, ".copilot"))
	}
	return roots
}

func home() string {
	h, err := homeDir()
	if err != nil {
		return ""
	}
	return h
}

// ConfineTranscript returns the symlink-resolved real path of path when that lies strictly
// inside one of roots (each resolved the same way), and "" otherwise. The resolved path, not
// the original spelling, is what the readers then open, so what was checked is exactly what
// is read: a spelling such as <root>/link/../x, where link points outside the root, cannot
// pass a lexical check and then be opened through the link. A path that does not resolve (the
// file is missing) is rejected rather than judged lexically. A rejection is logged to the
// plugin log and is never an error: the caller carries on without a transcript.
func ConfineTranscript(agentName, path string, roots []string) string {
	if path == "" {
		return ""
	}
	if real, ok := confined(path, append(append([]string(nil), roots...), extraTranscriptRoots...)); ok {
		return real
	}
	slog.Info("transcript path outside the agent's transcript roots; transcript reads skipped",
		"agent", agentName, "path", path)
	return ""
}

func confined(path string, roots []string) (string, bool) {
	p, ok := resolve(path)
	if !ok {
		return "", false
	}
	for _, r := range roots {
		if r == "" {
			continue
		}
		if root, ok := resolve(r); ok && within(root, p) {
			return p, true
		}
	}
	return "", false
}

// resolve returns p's real absolute path. ⚠️ p is handed to EvalSymlinks RAW, never
// lexically cleaned first: EvalSymlinks walks the components in order, so in link/.. the
// ".." climbs out of the link's target, as the OS does when it opens the path, whereas
// filepath.Clean (and filepath.Abs, which cleans) would collapse link/.. away unresolved.
// Abs is applied only to the already resolved result. A path that does not exist does not
// resolve, so a root that is missing admits nothing and a missing transcript is rejected.
func resolve(p string) (string, bool) {
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		return "", false
	}
	abs, err := filepath.Abs(r)
	if err != nil {
		return "", false
	}
	if !filepath.IsAbs(r) {
		if abs, err = filepath.EvalSymlinks(abs); err != nil {
			return "", false
		}
	}
	return abs, true
}

// within reports whether p is strictly inside root (root itself is not a transcript).
func within(root, p string) bool {
	if runtime.GOOS == "windows" {
		root, p = strings.ToLower(root), strings.ToLower(p)
	}
	rel, err := filepath.Rel(root, p)
	if err != nil || filepath.IsAbs(rel) {
		return false
	}
	return rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
