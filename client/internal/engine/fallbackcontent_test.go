package engine

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/agent"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/agent/claude"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/agent/codex"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
	"github.com/leotrace-hq/leoprevent-plugin/limits"
)

// LEO-637: a no-git fallback file reached the judge as an unnumbered extract, so a guard
// appended below the write it guards read as a fix. The file now goes whole, and
// AddedLines stays nil so introduced-vs-pre-existing is decided exactly as before.
func TestFallbackSendsTheFileWholeWithoutPositions(t *testing.T) {
	onDisk := "#!/bin/sh\ncurl \"$1\" > \"$2\"\ncase \"$2\" in *.sh) exit 1;; esac\n"
	for _, a := range []agent.Agent{claude.New(), codex.New()} {
		t.Run(a.Name(), func(t *testing.T) {
			// Arrange
			project := t.TempDir()
			path := filepath.Join(project, "grab.sh")
			if err := os.WriteFile(path, []byte(onDisk), 0o600); err != nil {
				t.Fatal(err)
			}
			var tp string
			if a.Name() == "claude" {
				tp = writeTranscript(t,
					`{"type":"user","message":{"role":"user","content":"guard it"}}`,
					`{"type":"assistant","message":{"role":"assistant","content":[`+
						`{"type":"tool_use","name":"Edit","input":{"file_path":"`+path+`","new_string":"case \"$2\" in *.sh) exit 1;; esac"}}]}}`,
				)
			} else {
				patch, _ := json.Marshal("*** Begin Patch\n*** Add File: " + path + "\n+" +
					strings.ReplaceAll(strings.TrimSuffix(onDisk, "\n"), "\n", "\n+") + "\n*** End Patch")
				tp = writeTranscript(t,
					`{"type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"guard it"}]}}`,
					`{"type":"response_item","payload":{"type":"custom_tool_call","name":"apply_patch","input":`+string(patch)+`}}`,
				)
			}
			ev := agent.Event{Cwd: project, SessionID: "leo572-" + a.Name() + "-" + filepath.Base(project), TranscriptPath: tp}

			// Act
			got, usedGit, _, _, err := changedFiles(a, ev, slog.Default())

			// Assert
			if err != nil || usedGit || len(got) != 1 {
				t.Fatalf("git=%v err=%v changes=%+v", usedGit, err, got)
			}
			if got[0].FullContent != onDisk {
				t.Errorf("FullContent = %q, want the file on disk", got[0].FullContent)
			}
			if got[0].AddedLines != nil {
				t.Errorf("AddedLines = %v, want nil: no diff, no positional authority", got[0].AddedLines)
			}
		})
	}
}

// The fallback reads files the way vcs does, so it can only ever add a body for a
// regular text file reached without a final symlink; anything else keeps its added text.
func TestFallbackContentRefusesWhatVcsRefuses(t *testing.T) {
	// Arrange
	project := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(project, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	write("target.py", "secret = 1\n")
	link := filepath.Join(project, "link.py")
	if err := os.Symlink(filepath.Join(project, "target.py"), link); err != nil {
		t.Fatal(err)
	}
	binary := write("blob.py", "a\x00b\n")
	big := write("big.py", strings.Repeat("x", limits.MaxChangedFileBytes+1))
	write("ok.py", "ok = 1\n")
	changes := []transcript.Change{
		{FilePath: link, AddedText: "secret = 1"},
		{FilePath: binary, AddedText: "a"},
		{FilePath: big, AddedText: "x"},
		{FilePath: filepath.Join(project, "missing.py"), AddedText: "gone = 1"},
		{FilePath: "ok.py", AddedText: "ok = 1"},
		{FilePath: "mcp/inline.js", AddedText: "alert(1)", Virtual: true},
	}

	// Act
	got := withFileContent(changes, project, slog.Default())

	// Assert
	if len(got) != len(changes) {
		t.Fatalf("a change was dropped: %+v", got)
	}
	for _, c := range got {
		want := ""
		if c.FilePath == "ok.py" {
			want = "ok = 1\n"
		}
		if c.FullContent != want {
			t.Errorf("%s: FullContent = %q, want %q", c.FilePath, c.FullContent, want)
		}
	}
}

func TestFallbackContentStaysWithinTheTurnBudget(t *testing.T) {
	// Arrange
	project := t.TempDir()
	body := strings.Repeat("y", limits.MaxChangedFileBytes)
	var changes []transcript.Change
	for _, name := range []string{"a.py", "b.py", "c.py"} {
		if err := os.WriteFile(filepath.Join(project, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		changes = append(changes, transcript.Change{FilePath: name, AddedText: "y"})
	}

	// Act
	got := withFileContent(changes, project, slog.Default())

	// Assert
	total := 0
	for _, c := range got {
		total += len(c.FullContent)
	}
	if total > limits.MaxChangedTotalBytes || got[0].FullContent == "" {
		t.Fatalf("sent %d bytes of file content, budget %d", total, limits.MaxChangedTotalBytes)
	}
}

// Boy's P1 on PR 1093: in a no-git folder, an agent edits `config.py`, a symlink to
// `.env`, by its absolute path. Path normalisation must not rename it to `.env` past the
// secret filter, and the whole-file reader must never send the target's content.
func TestFallbackNeverSendsASecretBehindASymlink(t *testing.T) {
	const token = "API_TOKEN=dummy-0123456789"
	for _, a := range []agent.Agent{claude.New(), codex.New()} {
		for _, target := range []string{".env", "settings.py"} {
			t.Run(a.Name()+"/"+target, func(t *testing.T) {
				// Arrange
				project := t.TempDir()
				if err := os.WriteFile(filepath.Join(project, target), []byte(token+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				alias := filepath.Join(project, "config.py")
				if err := os.Symlink(target, alias); err != nil {
					t.Fatal(err)
				}
				var tp string
				if a.Name() == "claude" {
					tp = writeTranscript(t,
						`{"type":"user","message":{"role":"user","content":"edit"}}`,
						`{"type":"assistant","message":{"role":"assistant","content":[`+
							`{"type":"tool_use","name":"Edit","input":{"file_path":"`+alias+`","new_string":"x = 1"}}]}}`,
					)
				} else {
					patch, _ := json.Marshal("*** Begin Patch\n*** Add File: " + alias + "\n+x = 1\n*** End Patch")
					tp = writeTranscript(t,
						`{"type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"edit"}]}}`,
						`{"type":"response_item","payload":{"type":"custom_tool_call","name":"apply_patch","input":`+string(patch)+`}}`,
					)
				}
				ev := agent.Event{Cwd: project, SessionID: "leo637-secret-" + a.Name() + "-" + filepath.Base(project), TranscriptPath: tp}

				// Act
				got, usedGit, _, _, err := changedFiles(a, ev, slog.Default())

				// Assert
				if err != nil || usedGit {
					t.Fatalf("git=%v err=%v", usedGit, err)
				}
				for _, c := range got {
					if strings.Contains(c.FullContent, token) || strings.Contains(c.AddedText, token) {
						t.Fatalf("the symlink target's content would be sent: %+v", c)
					}
					if c.FilePath != "config.py" {
						t.Errorf("path = %q, want the alias the agent edited, not its target", c.FilePath)
					}
				}
			})
		}
	}
}
