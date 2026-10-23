package depcheck

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/vcs"
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
	text, _, _, _ := Scan(w, changes, root, ts, srv, quiet)
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
	if srv.got[0].Path != "package-lock.json" || srv.got[1].Path != "other/package-lock.json" {
		t.Errorf("each request names its file relatively: %q, %q", srv.got[0].Path, srv.got[1].Path)
	}
	if !strings.HasPrefix(text, "🛡️ LeoPrevent · dependency scan of this project: something to look at in 2 dependency files\n\npackage-lock.json:\nflagged ") {
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
	if text, md, _, _ := Scan(Workspace{Files: files}, nil, root, nil, flaggingServer{}, quiet); text != "" || md != "" {
		t.Errorf("clean and complete: %q", text)
	}
	text, _, _, _ := Scan(Workspace{Files: files}, nil, root, nil, flaggingServer{flag: map[string]bool{"golang.org/x/text": true}}, quiet)
	want := "🛡️ LeoPrevent · dependency scan of this project: 1 high or critical issue to fix in 1 of 2 dependency files\n\n" +
		"🛡️ LeoPrevent · dependency check (1 package) · a/go.mod\ngolang.org/x/text has 1 high vulnerability."
	if text != want {
		t.Errorf("one issue:\n%s\nwant\n%s", text, want)
	}
	text, _, _, _ = Scan(Workspace{Files: files, Over: 4}, nil, root, nil, &fakeServer{err: fmt.Errorf("503")}, quiet)
	if text != "🛡️ LeoPrevent · dependency scan of this project: nothing high or critical in the 0 dependency files checked (2 files couldn't be checked; 4 more files over the limit of 50)" {
		t.Errorf("partial: %q", text)
	}
}

// A folder with no repository is walked, not skipped (LEO-658): what a reader reads, test folders
// included, never inside node_modules/, vendor/, a hidden folder or a symlink, or more than
// maxWalkDepth folders down. Nothing is marked as changed, since there's no start-of-turn copy.
func TestFindWalksAFolderWithNoRepository(t *testing.T) {
	root, _ := repo(t, map[string]string{
		"package-lock.json": "{}", "web/package-lock.json": "{}", "test/fixtures/package-lock.json": "{}",
		"a/b/c/d/package-lock.json": "{}", "a/b/c/d/e/package-lock.json": "{}", "app.js": "x",
		"node_modules/x/package-lock.json": "{}", "vendor/y/go.mod": "module y\n", ".venv/z/package-lock.json": "{}",
	}, nil)
	if err := os.Symlink(filepath.Join(root, "web"), filepath.Join(root, "linked")); err != nil {
		t.Fatal(err)
	}
	w := Find(root, lister(vcs.SkipNoRepository, nil), quiet)
	var got []string
	for _, f := range w.Files {
		got = append(got, f.Label)
		if f.Root != "" {
			t.Errorf("%s: a walked file has no repository, so no start-of-turn copy: %q", f.Label, f.Root)
		}
	}
	if strings.Join(got, ",") != "package-lock.json,web/package-lock.json,test/fixtures/package-lock.json,a/b/c/d/package-lock.json" ||
		!w.Walked || w.Cut || w.Skip != "" {
		t.Errorf("found %v (%+v)", got, w)
	}
	if w := Find("", lister(vcs.SkipNoRepository, nil), quiet); w.Skip != vcs.SkipNoRepository || w.Walked {
		t.Errorf("no folder at all is still skipped: %+v", w)
	}
	if w := Find(root, lister(vcs.SkipHomeFolder, nil), quiet); w.Skip != vcs.SkipHomeFolder || w.Walked {
		t.Errorf("the home folder is still skipped: %+v", w)
	}
}

// The walk stops after maxWalkEntries entries, and the summary says the folder wasn't looked
// through in full rather than reading as complete.
func TestTheWalkStopsAtItsCap(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < maxWalkEntries+5; i++ {
		if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("f%05d.txt", i)), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if files, cut := walkFolder(root); !cut || len(files) != maxWalkEntries {
		t.Fatalf("walked %d files, cut %v", len(files), cut)
	}
	text, _, _, _ := Scan(Workspace{Walked: true, Cut: true}, nil, root, nil, flaggingServer{}, quiet)
	if text != "🛡️ LeoPrevent · dependency scan of this project: nothing high or critical in the 0 dependency files checked (the folder was too large to look through in full) "+gitlessWarning {
		t.Errorf("cut: %q", text)
	}
}

// A walked folder always says so, once, even with nothing serious: the review's own no-git
// warning shows only when there's code to review. A folder with no dependency files says nothing.
func TestAWalkedScanAlwaysWarns(t *testing.T) {
	root, _ := repo(t, map[string]string{"go.mod": "module a\n\nrequire golang.org/x/text v0.3.7\n"}, nil)
	w := Workspace{Walked: true, Files: []ScanFile{{Label: "go.mod", Path: filepath.Join(root, "go.mod")}}}
	text, md, _, _ := Scan(w, nil, root, nil, flaggingServer{}, quiet)
	want := "🛡️ LeoPrevent · dependency scan of this project: nothing high or critical in the 1 dependency file checked " +
		"⚠️ no git repo here, so the dependency scan reaches less of your project (run git init for full coverage)"
	if text != want || md != want {
		t.Errorf("nothing serious:\n%s\nwant\n%s", text, want)
	}
	text, _, _, _ = Scan(w, nil, root, nil, flaggingServer{flag: map[string]bool{"golang.org/x/text": true}}, quiet)
	if !strings.HasPrefix(text, "🛡️ LeoPrevent · dependency scan of this project: 1 high or critical issue to fix in 1 dependency file "+gitlessWarning+"\n\n") {
		t.Errorf("with a finding:\n%s", text)
	}
	if text, _, _, _ := Scan(Workspace{Walked: true}, nil, root, nil, flaggingServer{}, quiet); text != "" {
		t.Errorf("no dependency files: %q", text)
	}
	if text, _, _, _ := Scan(Workspace{Files: w.Files}, nil, root, nil, flaggingServer{}, quiet); text != "" {
		t.Errorf("a repository with nothing serious stays silent: %q", text)
	}
}

// Fingerprint reads only inside its folder: a ".." path or a symlink out of it reads nothing.
func TestFingerprintStaysInItsFolder(t *testing.T) {
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir, _ := repo(t, map[string]string{"package-lock.json": "{}"}, nil)
	if err := os.Symlink(filepath.Join(outside, "secret"), filepath.Join(dir, "linked")); err != nil {
		t.Fatal(err)
	}
	if Fingerprint(dir, "package-lock.json") == "" {
		t.Error("a file in the folder is read")
	}
	rel, _ := filepath.Rel(dir, filepath.Join(outside, "secret"))
	for _, p := range []string{filepath.ToSlash(rel), "linked"} {
		if got := Fingerprint(dir, p); got != "" {
			t.Errorf("%s read from outside the folder", p)
		}
	}
}

// A server with no dependency check (ErrUnavailable, a 404) is never mentioned to the developer:
// no "couldn't be checked", no scan line, no no-git warning, nothing for the agent. Any other
// failure is still said.
func TestAnUnavailableCheckSaysNothing(t *testing.T) {
	root, _ := repo(t, map[string]string{"package-lock.json": lock(map[string]string{"lodash": "4.17.15"})}, nil)
	files := []ScanFile{{Label: "package-lock.json", Path: filepath.Join(root, "package-lock.json")}}
	unavailable := &fakeServer{err: fmt.Errorf("POST /dependencies: status 404: %w", ErrUnavailable)}
	for name, w := range map[string]Workspace{"repository": {Files: files}, "no git": {Files: files, Walked: true}} {
		if text, md, agent, offer := Scan(w, nil, root, nil, unavailable, quiet); text+md+agent+offer != "" {
			t.Errorf("%s: scan said %q", name, text+md+agent+offer)
		}
	}
	changes := []transcript.Change{{FilePath: "package-lock.json"}}
	if text, md, agent := Run(changes, root, nil, unavailable, quiet); text+md+agent != "" {
		t.Errorf("turn check said %q", text)
	}
	if text, md, agent := RunWhole(files, files, nil, root, unavailable, quiet); text+md+agent != "" {
		t.Errorf("no-git check said %q", text)
	}
	if text, _, _, _ := Scan(Workspace{Files: files}, nil, root, nil, &fakeServer{err: fmt.Errorf("503")}, quiet); !strings.Contains(text, "couldn't be checked") {
		t.Errorf("any other failure is still said: %q", text)
	}
}

// A folder that isn't a project gets its one line, and the turn's own files are still checked.
func TestASkippedScanSaysSo(t *testing.T) {
	root, ts := repo(t, map[string]string{"package-lock.json": lock(map[string]string{"lodash": "4.17.15"})},
		map[string]string{"package-lock.json": lock(map[string]string{"lodash": "4.17.10"})})
	srv := &fakeServer{}
	text, md, _, _ := Scan(Workspace{Skip: "several projects"}, []transcript.Change{{FilePath: "package-lock.json", RepoRoot: root}}, root, ts, srv, quiet)
	if !strings.HasPrefix(text, "🛡️ LeoPrevent · dependency scan skipped: this folder holds several projects. Open one of them to scan it.\n\npackage-lock.json:\nflagged lodash@4.17.15:changed") ||
		!strings.HasPrefix(md, "🛡️ LeoPrevent · dependency scan skipped") {
		t.Errorf("skipped, with the turn's file:\n%s", text)
	}
	if text, _, _, _ := Scan(Workspace{Skip: "home folder"}, nil, root, nil, srv, quiet); text != "🛡️ LeoPrevent · dependency scan skipped: this is your home folder. Open a project folder to scan it." {
		t.Errorf("skipped alone: %q", text)
	}
	for _, reason := range []string{"home folder", "filesystem root", "several projects", "no repository"} {
		if line := skipLine(reason); !strings.HasPrefix(line, "🛡️ LeoPrevent · dependency scan skipped: ") || strings.Contains(line, "—") {
			t.Errorf("%s: %q", reason, line)
		}
	}
}

// quietingServer quietens the packages it's told to, as the server does for a developer's answer:
// left out of the notice and counted in quieted, and flags the rest.
type quietingServer struct{ quiet, flag map[string]bool }

func (c quietingServer) CheckDependencies(req wire.DependenciesRequest) (wire.DependenciesResponse, error) {
	resp := wire.DependenciesResponse{Ecosystem: req.Ecosystem}
	for _, p := range req.Packages {
		switch {
		case c.quiet[p.Name]:
			resp.Issues++
			resp.QuietIssues++
			resp.Quieted = append(resp.Quieted, wire.QuietDependency{Name: p.Name, Version: p.Version})
		case c.flag[p.Name]:
			resp.Issues++
			msg := "🛡️ LeoPrevent · dependency scan (1 package)\n" + p.Name + " has 1 high vulnerability."
			resp.Messages.Developer = &msg
		}
	}
	return resp, nil
}

// A scan the developer has answered is never silent: one reminder line says what's quiet and
// until when, beside anything new, which is counted and listed as usual.
func TestAQuietenedScanLeavesAReminder(t *testing.T) {
	root, _ := repo(t, map[string]string{"go.mod": "module a\n\nrequire (\n\tgolang.org/x/text v0.3.7\n\tgolang.org/x/net v0.1.0\n)\n"}, nil)
	files := []ScanFile{{Label: "go.mod", Path: filepath.Join(root, "go.mod"), Root: root}}
	until := time.Now().Add(time.Hour)
	w := Workspace{Files: files, QuietUntil: until}
	stamp := until.Local().Format("15:04")
	if until.Local().YearDay() != time.Now().Local().YearDay() {
		stamp += " tomorrow"
	}

	text, _, _, _ := Scan(w, nil, root, nil, quietingServer{quiet: map[string]bool{"golang.org/x/text": true, "golang.org/x/net": true}}, quiet)
	if want := "🛡️ LeoPrevent · dependency scan of this project: 2 packages with high or critical issues, answered earlier (quiet until " + stamp + ")"; text != want {
		t.Errorf("all quiet:\n%s\nwant\n%s", text, want)
	}
	text, _, _, _ = Scan(w, nil, root, nil, quietingServer{quiet: map[string]bool{"golang.org/x/text": true}, flag: map[string]bool{"golang.org/x/net": true}}, quiet)
	if want := "🛡️ LeoPrevent · dependency scan of this project: 1 high or critical issue to fix in 1 dependency file; 1 more package answered earlier (quiet until " + stamp + ")\n\n"; !strings.HasPrefix(text, want) || !strings.Contains(text, "golang.org/x/net has 1 high") {
		t.Errorf("one new beside one quiet:\n%s", text)
	}
}

func TestQuietUntilSaysTomorrow(t *testing.T) {
	now := time.Date(2026, 10, 23, 15, 0, 0, 0, time.Local)
	if got := quietUntil(time.Date(2026, 10, 23, 18, 30, 0, 0, time.Local), now); got != "18:30" {
		t.Errorf("today = %q", got)
	}
	if got := quietUntil(time.Date(2026, 10, 24, 10, 0, 0, 0, time.Local), now); got != "10:00 tomorrow" {
		t.Errorf("tomorrow = %q", got)
	}
	if got := quietUntil(time.Time{}, now); got != "" {
		t.Errorf("nothing quiet = %q", got)
	}
}
