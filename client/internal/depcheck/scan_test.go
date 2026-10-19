package depcheck

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

// lister serves fixed repositories and file lists, standing in for git.
func lister(skip string, files map[string][]string) Lister {
	return Lister{
		Projects: func(string) ([]string, string) {
			var roots []string
			for r := range files {
				roots = append(roots, r)
			}
			return roots, skip
		},
		Files: func(root string) ([]string, error) { return files[root], nil },
	}
}

// Only files a reader reads; never under node_modules/ or vendor/, never a symlink.
func TestFindTakesTheReadersFilesOnly(t *testing.T) {
	root, _ := repo(t, map[string]string{
		"package-lock.json": "{}", "web/package-lock.json": "{}", "go.mod": "module x\n", "app.js": "x",
		"node_modules/a/package-lock.json": "{}", "vendor/b/go.mod": "module b\n",
	}, nil)
	if err := os.Symlink(filepath.Join(root, "package-lock.json"), filepath.Join(root, "linked-lock.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "lnk"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "go.mod"), filepath.Join(root, "lnk", "go.mod")); err != nil {
		t.Fatal(err)
	}
	listed := []string{"package-lock.json", "web/package-lock.json", "go.mod", "app.js",
		"node_modules/a/package-lock.json", "vendor/b/go.mod", "lnk/go.mod"}
	w := Find(root, lister("", map[string][]string{root: listed}), quiet)
	var got []string
	for _, f := range w.Files {
		got = append(got, f.Label)
	}
	if strings.Join(got, ",") != "package-lock.json,web/package-lock.json,go.mod" || w.Skip != "" || w.Over != 0 {
		t.Errorf("found %v (%+v)", got, w)
	}
}

// Past maxScanFiles the rest are counted, never checked; with several repositories each file is
// named under its repository.
func TestFindCapsAndNamesByRepository(t *testing.T) {
	files := map[string]string{}
	var listed []string
	for i := 0; i < maxScanFiles+3; i++ {
		rel := fmt.Sprintf("p%02d/go.mod", i)
		files[rel] = "module x\n"
		listed = append(listed, rel)
	}
	root, _ := repo(t, files, nil)
	w := Find(root, lister("", map[string][]string{root: listed}), quiet)
	if len(w.Files) != maxScanFiles || w.Over != 3 {
		t.Errorf("%d files, %d over", len(w.Files), w.Over)
	}

	a, _ := repo(t, map[string]string{"go.mod": "module a\n"}, nil)
	b, _ := repo(t, map[string]string{"go.mod": "module b\n"}, nil)
	w = Find("", lister("", map[string][]string{a: {"go.mod"}, b: {"go.mod"}}), quiet)
	for _, f := range w.Files {
		if f.Label != filepath.Base(f.Root)+"/go.mod" {
			t.Errorf("label %q under %s", f.Label, f.Root)
		}
	}
	if w = Find("", lister("several projects", nil), quiet); w.Skip != "several projects" || len(w.Files) != 0 {
		t.Errorf("skipped: %+v", w)
	}
}

// The whole file is sent, with the turn's changes still marked, once: the turn's own copy of it
// isn't sent again. A changed file the scan doesn't cover is sent as at any other Stop.
func TestScanSendsEachFileWholeAndOnce(t *testing.T) {
	root, ts := repo(t,
		map[string]string{"package-lock.json": lock(map[string]string{"lodash": "4.17.15", "axios": "1.6.0"}),
			"other/package-lock.json": lock(map[string]string{"ws": "8.17.0", "left-pad": "1.3.0"})},
		map[string]string{"package-lock.json": lock(map[string]string{"lodash": "4.17.10", "axios": "1.6.0"}),
			"other/package-lock.json": lock(map[string]string{"ws": "8.17.1", "left-pad": "1.3.0"})})
	w := Workspace{Files: []ScanFile{{Label: "package-lock.json", Path: filepath.Join(root, "package-lock.json"), Root: root}}}
	changes := []transcript.Change{{FilePath: "package-lock.json", RepoRoot: root}, {FilePath: "other/package-lock.json", RepoRoot: root}}
	srv := &fakeServer{}
	text, _ := Scan(w, changes, root, ts, srv, quiet)
	if len(srv.got) != 2 {
		t.Fatalf("one request per file, the scanned one only once: %d", len(srv.got))
	}
	sent := func(i int) string {
		var s []string
		for _, p := range srv.got[i].Packages {
			s = append(s, p.Name+":"+p.Change)
		}
		return strings.Join(s, ",")
	}
	if got := sent(0); got != "lodash:changed,axios:unchanged" {
		t.Errorf("the scanned file, whole: %s", got)
	}
	if got := sent(1); got != "ws:changed" {
		t.Errorf("a changed file the scan doesn't cover, changes only: %s", got)
	}
	if !strings.HasPrefix(text, "🛡️ LeoPrevent · dependency scan of this project, for your information: something to look at in 2 dependency files\n\npackage-lock.json:\nflagged ") {
		t.Errorf("notice:\n%s", text)
	}
}

// flaggingServer answers with the server's issue counts and a notice for each package it's told to flag.
type flaggingServer struct{ flag map[string]bool }

func (c flaggingServer) CheckDependencies(req wire.DependenciesRequest) (wire.DependenciesResponse, error) {
	resp := wire.DependenciesResponse{Ecosystem: req.Ecosystem}
	for _, p := range req.Packages {
		if c.flag[p.Name] {
			resp.Issues++
			msg := "🛡️ LeoPrevent · dependency check (1 package)\n" + p.Name + " has 1 high vulnerability."
			resp.Messages.Developer = &msg
		}
	}
	return resp, nil
}

// Nothing serious and everything checked: nothing to say. Something serious: a summary line
// above each file's notice. A partial scan says so even when nothing was found.
func TestScanSpeaksOnlyWhenThereIsSomethingToSay(t *testing.T) {
	root, _ := repo(t, map[string]string{"a/go.mod": "module a\n\nrequire golang.org/x/text v0.3.7\n",
		"b/go.mod": "module b\n\nrequire golang.org/x/net v0.1.0\n"}, nil)
	files := []ScanFile{{Label: "a/go.mod", Path: filepath.Join(root, "a/go.mod"), Root: root},
		{Label: "b/go.mod", Path: filepath.Join(root, "b/go.mod"), Root: root}}
	if text, md := Scan(Workspace{Files: files}, nil, root, nil, flaggingServer{}, quiet); text != "" || md != "" {
		t.Errorf("clean and complete: %q", text)
	}
	text, _ := Scan(Workspace{Files: files}, nil, root, nil, flaggingServer{flag: map[string]bool{"golang.org/x/text": true}}, quiet)
	want := "🛡️ LeoPrevent · dependency scan of this project, for your information: 1 high or critical issue in 1 of 2 dependency files\n\n" +
		"🛡️ LeoPrevent · dependency check (1 package) · a/go.mod\ngolang.org/x/text has 1 high vulnerability."
	if text != want {
		t.Errorf("one issue:\n%s\nwant\n%s", text, want)
	}
	text, _ = Scan(Workspace{Files: files, Over: 4}, nil, root, nil, &fakeServer{err: fmt.Errorf("503")}, quiet)
	if text != "🛡️ LeoPrevent · dependency scan of this project, for your information: nothing high or critical in the 0 dependency files checked (2 files couldn't be checked; 4 more files over the limit of 50)" {
		t.Errorf("partial: %q", text)
	}
}

// A folder that isn't a project gets its one line, and the turn's own files are still checked.
func TestASkippedScanSaysSo(t *testing.T) {
	root, ts := repo(t, map[string]string{"package-lock.json": lock(map[string]string{"lodash": "4.17.15"})},
		map[string]string{"package-lock.json": lock(map[string]string{"lodash": "4.17.10"})})
	srv := &fakeServer{}
	text, md := Scan(Workspace{Skip: "several projects"}, []transcript.Change{{FilePath: "package-lock.json", RepoRoot: root}}, root, ts, srv, quiet)
	if !strings.HasPrefix(text, "🛡️ LeoPrevent · dependency scan skipped: this folder holds several projects. Open one of them to scan it.\n\npackage-lock.json:\nflagged lodash@4.17.15:changed") ||
		!strings.HasPrefix(md, "🛡️ LeoPrevent · dependency scan skipped") {
		t.Errorf("skipped, with the turn's file:\n%s", text)
	}
	if text, _ := Scan(Workspace{Skip: "home folder"}, nil, root, nil, srv, quiet); text != "🛡️ LeoPrevent · dependency scan skipped: this is your home folder. Open a project folder to scan it." {
		t.Errorf("skipped alone: %q", text)
	}
	for _, reason := range []string{"home folder", "filesystem root", "several projects", "no repository"} {
		if line := skipLine(reason); !strings.HasPrefix(line, "🛡️ LeoPrevent · dependency scan skipped: ") || strings.Contains(line, "—") {
			t.Errorf("%s: %q", reason, line)
		}
	}
}
