package engine

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/agent"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/agent/claude"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/agent/codex"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/outcome"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/vcs"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

func TestRecoveryAfterCancellation(
	t *testing.T,
) {
	for _, a := range []agent.Agent{claude.New(), codex.New()} {
		for _, newEdit := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/new-edit=%v", a.Name(), newEdit), func(t *testing.T) {
				dir := t.TempDir()
				session := "recover-" + filepath.Base(dir)
				t.Cleanup(func() { outcome.Clear(session); outcome.ClearLedger(session) })
				seedRepo(t, dir)
				if err := vcs.CaptureBaseline(dir, session); err != nil {
					t.Fatal(err)
				}
				vulnerable := "import os\nos.system(input())\n"
				path := filepath.Join(dir, "app.py")
				if err := os.WriteFile(path, []byte(vulnerable), 0600); err != nil {
					t.Fatal(err)
				}
				ev := agent.Event{Name: "Stop", SessionID: session, Cwd: dir}
				r := &fakeReviewer{prompt: "Fix the command injection", pending: &outcome.Pending{ReviewID: "original", Before: []wire.ChangedFile{{Path: "app.py", FullContent: vulnerable}}}}
				var out, stderr bytes.Buffer
				Run(a, r, ev, &out, &stderr)
				if !r.called || !strings.Contains(out.String(), "block") {
					t.Fatalf("expected initial block: %s %s", out.String(), stderr.String())
				}
				if err := os.WriteFile(path, []byte("import os\n"), 0600); err != nil {
					t.Fatal(err)
				}
				ev.Name = "UserPromptSubmit"
				CaptureRecovery(a, ev)
				p, ok := outcome.Load(session)
				if !ok || p.Recovery == nil {
					t.Fatal("cancelled turn was not captured")
				}
				if err := vcs.CaptureBaseline(dir, session); err != nil {
					t.Fatal(err)
				}
				if newEdit {
					if err := os.WriteFile(path, []byte(vulnerable), 0600); err != nil {
						t.Fatal(err)
					}
				}
				CaptureRecovery(a, ev)
				r = &fakeReviewer{}
				ev.Name = "Stop"
				ev.LastAssistantMessage = "unrelated new reply"
				out.Reset()
				Run(a, r, ev, &out, &stderr)
				if !r.shipped || r.shippedPending.ReviewID != "original" {
					t.Fatal("original outcome not delivered")
				}
				if len(r.shippedAfter) != 1 || r.shippedAfter[0].FullContent != "import os\n" {
					t.Fatalf("wrong recovery snapshot: %+v", r.shippedAfter)
				}
				if r.shippedResponse != "" || r.shippedMeta.DurationMs != 0 || r.shippedMeta.InputTokens != 0 {
					t.Fatalf("new turn attributed to recovery: %+v", r.shippedMeta)
				}
				if r.called != newEdit {
					t.Fatalf("current turn review=%v, want %v", r.called, newEdit)
				}
				if _, ok := outcome.Load(session); ok {
					t.Fatal("delivered recovery retained")
				}
				r = &fakeReviewer{}
				Run(a, r, ev, &out, &stderr)
				if r.shipped {
					t.Fatal("duplicate recovery")
				}
			})
		}
	}
}

func TestRecoveryRejectsUnavailableSource(
	t *testing.T,
) {
	for _, kind := range []string{"missing", "escape", "directory"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			session := filepath.Base(dir)
			t.Cleanup(func() { outcome.Clear(session) })
			path := filepath.Join(dir, "app.py")
			if kind == "escape" {
				other := filepath.Join(t.TempDir(), "private.py")
				if err := os.WriteFile(other, []byte("private"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(other, path); err != nil {
					t.Skip(err)
				}
			}
			if kind == "directory" {
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			}
			p := outcome.Pending{ReviewID: "r", Sources: []outcome.Source{{Path: "app.py", Root: dir, Relative: "app.py"}}}
			if err := outcome.Remember(session, p); err != nil {
				t.Fatal(err)
			}
			CaptureRecovery(claude.New(), agent.Event{SessionID: session, Cwd: dir})
			got, ok := outcome.Load(session)
			if !ok || got.Recovery != nil {
				t.Fatal("unavailable source must not be scored as fixed")
			}
		})
	}
}

func TestNormalCompletionTakesPrecedenceOverRecovery(
	t *testing.T,
) {
	dir := t.TempDir()
	session := "normal-" + filepath.Base(dir)
	t.Cleanup(func() { outcome.Clear(session); outcome.ClearLedger(session) })
	seedRepo(t, dir)
	if err := vcs.CaptureBaseline(dir, session); err != nil {
		t.Fatal(err)
	}
	fixed := "import os\nprint('final fix')\n"
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte(fixed), 0600); err != nil {
		t.Fatal(err)
	}
	p := outcome.Pending{ReviewID: "r", Recovery: &outcome.Recovery{After: []wire.ChangedFile{{Path: "app.py", FullContent: "stale snapshot"}}}}
	if err := outcome.Remember(session, p); err != nil {
		t.Fatal(err)
	}
	r := &fakeReviewer{}
	var out, stderr bytes.Buffer
	Run(claude.New(), r, agent.Event{Name: "Stop", SessionID: session, Cwd: dir, StopHookActive: true}, &out, &stderr)
	if !r.shipped || len(r.shippedAfter) != 1 || r.shippedAfter[0].FullContent != fixed {
		t.Fatalf("normal outcome replaced by stale snapshot: %+v", r.shippedAfter)
	}
}
