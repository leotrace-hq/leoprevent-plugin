package vcs

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestSessionBaselinesStayInTheirRepositories(
	t *testing.T,
) {
	for _, concurrent := range []bool{false, true} {
		t.Run(map[bool]string{false: "interleaved", true: "concurrent"}[concurrent], func(t *testing.T) {
			isolateSessionScratch(t)
			base := t.TempDir()
			a := seedRepoAt(t, filepath.Join(base, "a"), "app.py", "x = 1\n")
			b := seedRepoAt(t, filepath.Join(base, "b"), "app.py", "x = 1\n")
			const id = "shared"
			if err := CaptureBaseline(a, id); err != nil {
				t.Fatal(err)
			}
			if err := RecordEditedRepo(filepath.Join(a, "app.py"), a, id); err != nil {
				t.Fatal(err)
			}
			appendTo(t, filepath.Join(a, "app.py"), "a = 2\n")
			if concurrent {
				var wg sync.WaitGroup
				for _, repo := range []string{a, b} {
					wg.Add(1)
					go func(repo string) {
						defer wg.Done()
						if err := CaptureBaseline(repo, id); err != nil {
							t.Error(err)
						}
					}(repo)
				}
				wg.Wait()
				appendTo(t, filepath.Join(a, "app.py"), "a = 3\n")
			} else if err := CaptureBaseline(b, id); err != nil {
				t.Fatal(err)
			}
			appendTo(t, filepath.Join(b, "app.py"), "b = 2\n")
			for _, repo := range []string{a, b} {
				changes, ok, skip, err := ChangedFiles(repo, id)
				if err != nil || !ok || len(changes) != 1 {
					t.Fatalf("%s: changes=%d ok=%v skip=%s err=%v", repo, len(changes), ok, skip, err)
				}
				if changes[0].FilePath != "app.py" || !strings.Contains(changes[0].AddedText, filepath.Base(repo)+" =") {
					t.Fatalf("wrong repository: %+v", changes)
				}
			}
		})
	}
}

func TestSessionCaptureDoesNotEraseOrSkipAnotherWorkspaceDiscovery(
	t *testing.T,
) {
	isolateSessionScratch(t)
	workspace := t.TempDir()
	repo := seedRepoAt(t, filepath.Join(t.TempDir(), "repo"), "app.py", "x = 1\n")
	const id = "shared"
	if err := CaptureBaseline(workspace, id); err != nil {
		t.Fatal(err)
	}
	if err := CaptureBaseline(repo, id); err != nil {
		t.Fatal(err)
	}
	if err := RecordEditedRepo(filepath.Join(repo, "app.py"), workspace, id); err != nil {
		t.Fatal(err)
	}
	appendTo(t, filepath.Join(repo, "app.py"), "first = 2\n")
	if err := CaptureBaseline(repo, id); err != nil {
		t.Fatal(err)
	}
	changes, ok, skip, err := ChangedFiles(workspace, id)
	if err != nil || !ok || len(changes) != 1 || !strings.Contains(changes[0].AddedText, "first = 2") {
		t.Fatalf("discovery lost: changes=%+v ok=%v skip=%s err=%v", changes, ok, skip, err)
	}
}

func TestSessionCleanupOnlyRemovesItsScope(
	t *testing.T,
) {
	isolateSessionScratch(t)
	a := t.TempDir()
	b := t.TempDir()
	repo := seedRepoAt(t, filepath.Join(t.TempDir(), "repo"), "app.py", "x = 1\n")
	const id = "shared"
	for _, cwd := range []string{a, b} {
		if err := CaptureBaseline(cwd, id); err != nil {
			t.Fatal(err)
		}
		if err := RecordEditedRepo(filepath.Join(repo, "app.py"), cwd, id); err != nil {
			t.Fatal(err)
		}
	}
	appendTo(t, filepath.Join(repo, "app.py"), "change = 2\n")
	ClearBaseline(a, id)
	for _, path := range []string{scratchPath(scopedSession(a, id)), discoveredDir(scopedSession(a, id)), turnStartPath(scopedSession(a, id))} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("scratch survived: %s: %v", path, err)
		}
	}
	changes, ok, skip, err := ChangedFiles(b, id)
	if err != nil || !ok || len(changes) != 1 {
		t.Fatalf("other workspace lost: %v %v %s %v", changes, ok, skip, err)
	}
	if changes, ok, _, _ := ChangedFiles(a, id); ok || len(changes) != 0 {
		t.Fatalf("cleared workspace borrowed another baseline: %v", changes)
	}
}

func TestSessionLegacyBaselineReadIsRepositoryBound(
	t *testing.T,
) {
	for _, rooted := range []bool{false, true} {
		t.Run(map[bool]string{false: "original", true: "rooted"}[rooted], func(t *testing.T) {
			isolateSessionScratch(t)
			repo := seedRepoAt(t, filepath.Join(t.TempDir(), "repo"), "app.py", "x = 1\n")
			const id = "legacy"
			body := captureRepo(repo)
			if rooted {
				body += repoRootPrefix + repo + "\n"
			}
			if err := os.MkdirAll(filepath.Dir(scratchPath(id)), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(scratchPath(id), []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			appendTo(t, filepath.Join(repo, "app.py"), "change = 2\n")
			changes, ok, skip, err := ChangedFiles(repo, id)
			if err != nil || !ok || len(changes) != 1 {
				t.Fatalf("legacy read: %v %v %s %v", changes, ok, skip, err)
			}
			if rooted {
				other := seedRepoAt(t, filepath.Join(t.TempDir(), "other"), "app.py", "x = 1\n")
				if changes, ok, _, _ := ChangedFiles(other, id); ok || len(changes) != 0 {
					t.Fatalf("borrowed foreign legacy baseline: %v", changes)
				}
			}
			if err := CaptureBaseline(repo, id); err != nil {
				t.Fatal(err)
			}
			ClearBaseline(repo, id)
			raw, err := os.ReadFile(scratchPath(id))
			if err != nil || string(raw) != body {
				t.Fatalf("legacy baseline modified: %v", err)
			}
		})
	}
}

func TestSessionScopeCanonicalizesRepositoryPaths(
	t *testing.T,
) {
	isolateSessionScratch(t)
	repo := seedRepoAt(t, filepath.Join(t.TempDir(), "repo"), "app.py", "x = 1\n")
	sub := filepath.Join(repo, "sub")
	if err := os.Mkdir(sub, 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(repo, alias); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	for _, path := range []string{sub, alias} {
		if scopedSession(path, "id") != scopedSession(repo, "id") {
			t.Fatalf("different scope for %s", path)
		}
	}
}

func TestSessionDoesNotBorrowAnUnrelatedRepositoryBaseline(
	t *testing.T,
) {
	isolateSessionScratch(t)
	a := seedRepoAt(t, filepath.Join(t.TempDir(), "a"), "app.py", "x = 1\n")
	b := seedRepoAt(t, filepath.Join(t.TempDir(), "b"), "app.py", "x = 1\n")
	if err := CaptureBaseline(a, "shared"); err != nil {
		t.Fatal(err)
	}
	appendTo(t, filepath.Join(a, "app.py"), "a = 2\n")
	changes, ok, skip, err := ChangedFiles(b, "shared")
	if err != nil || ok || len(changes) != 0 || skip != SkipNoBaselineFile {
		t.Fatalf("foreign baseline: %v %v %s %v", changes, ok, skip, err)
	}
}

func TestSessionDirectoryChangeUsesOnlyUnambiguousDiscovery(
	t *testing.T,
) {
	isolateSessionScratch(t)
	a, b := t.TempDir(), t.TempDir()
	repo := seedRepoAt(t, filepath.Join(t.TempDir(), "repo"), "app.py", "x = 1\n")
	const id = "shared"
	if err := CaptureBaseline(a, id); err != nil {
		t.Fatal(err)
	}
	if err := RecordEditedRepo(filepath.Join(repo, "app.py"), a, id); err != nil {
		t.Fatal(err)
	}
	appendTo(t, filepath.Join(repo, "app.py"), "change = 2\n")
	if changes, ok, _, err := ChangedFiles(repo, id); err != nil || !ok || len(changes) != 1 {
		t.Fatalf("directory change lost discovery: %v %v %v", changes, ok, err)
	}
	if err := CaptureBaseline(b, id); err != nil {
		t.Fatal(err)
	}
	if err := RecordEditedRepo(filepath.Join(repo, "app.py"), b, id); err != nil {
		t.Fatal(err)
	}
	if changes, ok, skip, err := ChangedFiles(repo, id); err != nil || ok || len(changes) != 0 || skip != SkipNoBaselineFile {
		t.Fatalf("ambiguous scope borrowed: %v %v %s %v", changes, ok, skip, err)
	}
}

func TestSessionLegacyDiscoveryDoesNotOverwriteTheLegacyScratch(
	t *testing.T,
) {
	isolateSessionScratch(t)
	a := seedRepoAt(t, filepath.Join(t.TempDir(), "a"), "app.py", "x = 1\n")
	b := seedRepoAt(t, filepath.Join(t.TempDir(), "b"), "app.py", "x = 1\n")
	const id = "legacy"
	body := captureRepo(a) + repoRootPrefix + a + "\n"
	if err := os.MkdirAll(filepath.Dir(scratchPath(id)), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(scratchPath(id), []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	appendTo(t, filepath.Join(a, "app.py"), "a = 2\n")
	if err := RecordEditedRepo(filepath.Join(a, "app.py"), a, id); err != nil {
		t.Fatal(err)
	}
	if err := RecordEditedRepo(filepath.Join(b, "app.py"), a, id); err != nil {
		t.Fatal(err)
	}
	appendTo(t, filepath.Join(b, "app.py"), "b = 2\n")
	changes, ok, skip, err := ChangedFiles(a, id)
	if err != nil || !ok || len(changes) != 2 {
		t.Fatalf("legacy transition lost changes: %v %v %s %v", changes, ok, skip, err)
	}
	if _, err := os.Stat(discoveredDir(id)); !os.IsNotExist(err) {
		t.Fatalf("legacy discovery directory was written: %v", err)
	}
}

func isolateSessionScratch(
	t *testing.T,
) {
	t.Helper()
	scratch := t.TempDir()
	for _, name := range []string{"TMPDIR", "TMP", "TEMP"} {
		t.Setenv(name, scratch)
	}
}
