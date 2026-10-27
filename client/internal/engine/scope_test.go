package engine

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/agent"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/agent/claude"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
)

func TestFallbackSendsOnlyFilesInsideTheProjectFolder(t *testing.T) {
	// Arrange
	project := t.TempDir()
	outside := t.TempDir()
	if err := os.MkdirAll(filepath.Join(project, "src"), 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(project, "escape")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(project, "src", "app.py")
	// JSON-quote each path: a raw Windows path's backslashes are invalid JSON escapes.
	q := func(s string) string { b, _ := json.Marshal(s); return string(b) }
	p := writeTranscript(t,
		`{"type":"user","message":{"role":"user","content":"edit"}}`,
		`{"type":"assistant","message":{"role":"assistant","content":[`+
			`{"type":"tool_use","name":"Write","input":{"file_path":`+q(inside)+`,"content":"inside = 1"}},`+
			`{"type":"tool_use","name":"Write","input":{"file_path":`+q(filepath.Join(outside, "notes.py"))+`,"content":"outside = 1"}},`+
			`{"type":"tool_use","name":"Write","input":{"file_path":`+q(filepath.Join(link, "linked.py"))+`,"content":"linked = 1"}},`+
			`{"type":"tool_use","name":"Write","input":{"file_path":`+q(filepath.Join(project, "..", filepath.Base(outside), "dotdot.py"))+`,"content":"dotdot = 1"}},`+
			`{"type":"tool_use","name":"Write","input":{"file_path":"src/relative.py","content":"relative = 1"}},`+
			`{"type":"tool_use","name":"Write","input":{"file_path":"../up.py","content":"up = 1"}},`+
			`{"type":"tool_use","name":"mcp__webflow__register_inline_script","input":{"source_code":"alert(document.cookie)"}}`+
			`]}}`,
	)
	ev := agent.Event{Cwd: project, SessionID: "leo492-scope", TranscriptPath: p, MCPTools: transcript.DefaultMCPToolRules()}

	// Act
	got, usedGit, _, _, err := changedFiles(claude.New(), ev, slog.Default())

	// Assert
	if err != nil || usedGit {
		t.Fatalf("git=%v, err=%v", usedGit, err)
	}
	paths := map[string]bool{}
	for _, c := range got {
		paths[c.FilePath] = true
	}
	if len(got) != 3 || !paths["src/app.py"] || !paths["src/relative.py"] {
		t.Fatalf("changedFiles = %+v", got)
	}
	for path := range paths {
		if filepath.IsAbs(path) {
			t.Errorf("an absolute path reached the wire: %q", path)
		}
	}
}

func TestFallbackWithNoCwdIsLeftUnscoped(t *testing.T) {
	// Arrange
	changes := []transcript.Change{{FilePath: "/p/app.py"}, {FilePath: "src/app.py"}}

	// Act
	got := dropOutsideCwd(changes, "", slog.Default())

	// Assert
	if len(got) != 2 {
		t.Fatalf("got %+v", got)
	}
}
