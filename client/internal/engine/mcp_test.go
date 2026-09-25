package engine

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/agent"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/agent/claude"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/gate"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/selector"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/vcs"
)

func TestMCPInputReachesReviewWithAndWithoutGitChanges(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git unavailable")
	}
	dir := t.TempDir()
	git := func(args ...string) {
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	git("init", "-q")
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte("x = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	git("add", "app.py")
	git("commit", "-q", "-m", "init")
	p := writeTranscript(t,
		`{"type":"user","message":{"role":"user","content":"publish"}}`,
		`{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","name":"mcp__webflow__register_inline_script","input":{"source_code":"alert(document.cookie)"}}]}}`,
	)
	for _, withFile := range []bool{false, true} {
		session := fmt.Sprintf("leo318-mcp-%v", withFile)
		if err := vcs.CaptureBaseline(dir, session); err != nil {
			t.Fatal(err)
		}
		if withFile {
			if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte("x = 2\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		ev := agent.Event{Cwd: dir, SessionID: session, TranscriptPath: p, MCPTools: transcript.DefaultMCPToolRules()}
		got, usedGit, _, _, err := changedFiles(claude.New(), ev, slog.Default())
		if err != nil || !usedGit {
			t.Fatalf("changedFiles = %+v, git=%v, err=%v", got, usedGit, err)
		}
		want := 1
		if withFile {
			want = 2
		}
		if len(got) != want {
			t.Fatalf("changes = %+v, want %d", got, want)
		}
		if !strings.Contains(got[len(got)-1].AddedText, "document.cookie") {
			t.Fatalf("MCP code absent: %+v", got)
		}
		r := &fakeReviewer{}
		var stdout, stderr bytes.Buffer
		Run(claude.New(), r, ev, &stdout, &stderr)
		if !r.called {
			t.Fatalf("reviewer not called: %s", stderr.String())
		}
	}
}

func TestHostedScriptSelectsIntegrityRule(t *testing.T) {
	p := writeTranscript(t,
		`{"type":"user","message":{"role":"user","content":"publish"}}`,
		`{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","name":"mcp__webflow__register_hosted_script","input":{"hosted_location":"https://cdn.example/x.js"}}]}}`,
	)
	changes, err := transcript.ParseMCPChanges(p, transcript.DefaultMCPToolRules())
	if err != nil || len(changes) != 1 {
		t.Fatalf("changes = %+v, err = %v", changes, err)
	}
	for _, id := range selector.SelectIDs(changes) {
		if id == "missing-subresource-integrity" {
			return
		}
	}
	t.Fatal("hosted script did not select missing-subresource-integrity")
}

func TestVirtualCSSIsNotDroppedAsARepositoryAsset(t *testing.T) {
	changes := []transcript.Change{{FilePath: "mcp/server/builder/css.css", AddedText: "a{background:url(x)}", Virtual: true}}
	if got := gate.Run(changes); len(got) != 1 {
		t.Fatalf("virtual CSS was dropped: %+v", got)
	}
}
