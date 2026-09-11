package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestBashPathCandidatesFindsAHeredocTarget is the regression on the shape that made
// this scavenger necessary, taken verbatim from a real session (2026-08-25): asked to
// write a file, the agent reached for a heredoc rather than the Write tool, on every one
// of six consecutive attempts. Before this, such a turn discovered no repository and
// reported itself unreviewed.
func TestBashPathCandidatesFindsAHeredocTarget(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory")
	}
	got := BashPathCandidates("cat > ~/Documents/leoreveal/scratch.ts <<'EOF'\nimport x\nEOF")
	want := filepath.Join(home, "Documents", "leoreveal", "scratch.ts")
	if !contains(got, want) {
		t.Errorf("heredoc target not discovered\n got: %q\nwant to contain: %q", got, want)
	}
}

func TestBashPathCandidatesCoversTheOtherShellWriteShapes(t *testing.T) {
	for _, tc := range []struct{ name, cmd, want string }{
		// No space after the redirect: the operand must not glue onto the operator.
		{"tight redirect", "echo hi >/tmp/x/app.py", "/tmp/x/app.py"},
		{"append", "echo hi >> /tmp/x/app.py", "/tmp/x/app.py"},
		{"sed in place", "sed -i '' 's/a/b/' /tmp/x/app.py", "/tmp/x/app.py"},
		{"tee", "cat f | tee /tmp/x/app.py", "/tmp/x/app.py"},
		{"git apply", "git apply /tmp/x/patch.diff", "/tmp/x/patch.diff"},
		// A second command after a separator is still a write.
		{"after separator", "cd /tmp && cat > /tmp/x/app.py", "/tmp/x/app.py"},
		// Relative paths are resolved against cwd by RecordEditedRepo, not here, so
		// they must survive the scavenge.
		// The raw token, NOT filepath.Join: the scavenger reads a shell command and hands
		// the path back exactly as written, leaving RecordEditedRepo to resolve it.
		{"relative", "cat > sub/dir/app.py", "sub/dir/app.py"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := BashPathCandidates(tc.cmd); !contains(got, tc.want) {
				t.Errorf("got %q, want to contain %q", got, tc.want)
			}
		})
	}
}

// TestBashPathCandidatesDropsWhatItCannotResolve pins the bounds. Each of these would
// cost a pointless RepoRoot walk at best; none can name a repository we could snapshot.
func TestBashPathCandidatesDropsWhatItCannotResolve(t *testing.T) {
	for _, tc := range []struct{ name, cmd string }{
		{"flags", "ls -la --color=auto"},
		{"urls", "curl https://example.com/a/b"},
		{"globs", "rm -rf /tmp/x/*.py"},
		{"unexpanded vars", "cat > $OUT/app.py"},
		{"bare words", "npm run build"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := BashPathCandidates(tc.cmd); len(got) != 0 {
				t.Errorf("expected nothing resolvable, got %q", got)
			}
		})
	}
}

// TestBashPathCandidatesIsBounded keeps one command from making us stat the filesystem
// an unbounded number of times: a heredoc body is a whole file arriving as a string.
func TestBashPathCandidatesIsBounded(t *testing.T) {
	if got := BashPathCandidates(strings.Repeat("/a/b/c"+"x ", 5000)); len(got) > maxBashCandidates {
		t.Errorf("got %d candidates, want at most %d", len(got), maxBashCandidates)
	}
}

// TestEditPathsPrefersTheNamedFile pins that a write tool's own answer wins outright.
// Scavenging `content` as well would record repositories named by the TEXT being
// written rather than the file being written to.
func TestEditPathsPrefersTheNamedFile(t *testing.T) {
	got := EditPathsFromToolInput(map[string]any{
		"file_path": "/tmp/x/app.py",
		"content":   "see /other/repo/thing.py for context",
	})
	if len(got) != 1 || got[0] != "/tmp/x/app.py" {
		t.Errorf("got %q, want exactly [/tmp/x/app.py]", got)
	}
}

func TestEditPathsReadsABashCommand(t *testing.T) {
	got := EditPathsFromToolInput(map[string]any{"command": "cat > /tmp/x/app.py <<'EOF'"})
	if !contains(got, "/tmp/x/app.py") {
		t.Errorf("got %q, want to contain /tmp/x/app.py", got)
	}
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}
