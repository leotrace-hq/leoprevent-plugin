package agent

import (
	"os"
	"path/filepath"
	"strings"
)

const (
	// maxBashScan bounds how much of a command string is scanned. A heredoc body
	// arrives inside the command, so this is a whole file's worth of text, not a
	// command line; the paths that matter are in the command itself, which is at the
	// front.
	maxBashScan = 16 << 10
	// maxBashCandidates bounds how many repositories one command can make us stat.
	// Recording is idempotent per repository, so the real cost is the RepoRoot walk.
	maxBashCandidates = 64
)

// bashCommandKeys are the tool-input keys that carry a shell command. Same ordered
// ladder, and the same reasoning, as EditPathFromToolInput's.
var bashCommandKeys = []string{"command", "cmd", "script"}

// BashPathCandidates extracts every plausible filesystem path from a shell command, so
// a file written through Bash still discovers its repository.
//
// ⚠️ THIS IS DELIBERATELY RECALL-ORIENTED, AND THE ASYMMETRY IS THE WHOLE DESIGN. A
// spurious candidate costs one RepoRoot walk that finds nothing, or at worst a baseline
// for a repository the turn never touches — which `ChangedFiles` then diffs to zero. A
// MISSED candidate costs the turn its review, silently, under a notice saying the folder
// is not a repository. So this over-collects on purpose: it is a scavenger, not a parser.
//
// It is explicitly NOT shell parsing. Quoting, expansion, `eval`, `$(...)` and process
// substitution are not modelled, and a command that computes its path at runtime is
// unreachable this way. What it does cover is the shape agents actually reach for when
// they write a file without a write tool: a redirect (`cat > path <<'EOF'`), an in-place
// edit (`sed -i path`), `tee path`, `git apply path`.
//
// Bounds, all of which fail toward collecting nothing rather than toward a wrong repo:
//   - a token must contain a separator, because a bare name resolves against cwd and
//     the case this exists for is a cwd that is NOT a repository, where a bare name
//     therefore names nothing findable
//   - a glob, a URL, an unexpanded variable and a flag are dropped, since none of them
//     name a path we can resolve now
//   - `~` is expanded, because an agent writes it constantly and the shell would have
//   - the scan and the result are both capped (see the constants above)
func BashPathCandidates(command string) []string {
	if len(command) > maxBashScan {
		command = command[:maxBashScan]
	}
	// Shell metacharacters are separators, not path content: `cat >x.ts` and
	// `a;b` must both yield their operands. Replaced with spaces rather than
	// stripped, or `>x.ts` would glue onto the previous token.
	cleaned := strings.Map(func(r rune) rune {
		switch r {
		case '|', '&', ';', '(', ')', '<', '>', '{', '}', '`', '"', '\'', '\n', '\t', '\r', '=':
			return ' '
		}
		return r
	}, command)

	home, _ := os.UserHomeDir()
	var out []string
	seen := map[string]bool{}
	for _, tok := range strings.Fields(cleaned) {
		p := cleanBashToken(tok, home)
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
		if len(out) >= maxBashCandidates {
			break
		}
	}
	return out
}

// cleanBashToken normalises one whitespace-delimited token into a path candidate, or
// returns "" when it cannot be one. Kept separate from the scan so each rejection is
// testable on its own.
func cleanBashToken(tok, home string) string {
	// Trailing punctuation is sentence noise, never part of the name.
	tok = strings.Trim(tok, ",:")
	switch {
	case tok == "":
		return ""
	case strings.HasPrefix(tok, "-"):
		return "" // a flag
	case strings.Contains(tok, "://"):
		return "" // a URL
	case strings.ContainsAny(tok, "*?$"):
		return "" // a glob, or a variable we cannot expand
	}
	if tok == "~" || strings.HasPrefix(tok, "~/") {
		if home == "" {
			return ""
		}
		tok = filepath.Join(home, strings.TrimPrefix(strings.TrimPrefix(tok, "~"), "/"))
	}
	// A separator is what makes a token resolvable: see the bounds on the exported
	// function. Checked AFTER `~` expansion, which introduces one.
	//
	// ⚠️ `/` IS ACCEPTED ON EVERY PLATFORM, NOT filepath.Separator. This reads a SHELL
	// COMMAND, and on Windows the shell running it is Git Bash, which speaks POSIX paths;
	// `filepath.Separator` there is `\`, so every `cat > /c/src/app.py` was rejected and
	// Bash-written files discovered nothing at all on Windows. Caught by the windows-latest
	// job, not by review. The native separator is accepted too, for a command that carries
	// a real Windows path.
	if !strings.ContainsRune(tok, '/') && !strings.ContainsRune(tok, filepath.Separator) {
		return ""
	}
	return tok
}

// EditPathsFromToolInput returns every path a PreToolUse invocation might be about to
// write, newest-intent first, or nil when the tool names none.
//
// A write tool names exactly one file and that answer is authoritative, so it wins
// outright: scavenging its `content` for paths as well would record repositories from
// the text being written rather than the file being written to.
func EditPathsFromToolInput(in map[string]any) []string {
	if p := EditPathFromToolInput(in); p != "" {
		return []string{p}
	}
	for _, k := range bashCommandKeys {
		if s, ok := in[k].(string); ok && strings.TrimSpace(s) != "" {
			return BashPathCandidates(s)
		}
	}
	return nil
}
