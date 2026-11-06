package depcheck

import (
	"errors"
	"slices"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
)

// The covering file is the nearest of the code's own ecosystem, up to the repository's root: an
// npm workspace member with no lockfile of its own reports the root's, Go code its go.mod, and
// code in a language with no reader, a vendored file or a dependency file the turn changed
// itself has none. Two changes under one lockfile report it once.
func TestCoveringFindsTheNearestFileOfTheCodesEcosystem(t *testing.T) {
	gomod := "module example.com/svc\n\ngo 1.22\n"
	root, _ := repo(t, map[string]string{
		"package-lock.json":              lock(map[string]string{"lodash": "4.17.15"}),
		"packages/web/package.json":      `{"name":"web"}`,
		"packages/web/src/app.ts":        "export {}\n",
		"packages/web/src/util.js":       "export {}\n",
		"apps/api/package-lock.json":     lock(map[string]string{"axios": "0.21.1"}),
		"apps/api/index.js":              "export {}\n",
		"svc/go.mod":                     gomod,
		"svc/internal/x/x.go":            "package x\n",
		"tools/run.py":                   "print(1)\n",
		"node_modules/left-pad/index.js": "module.exports = 1\n",
		"go.mod":                         "module example.com/root\n",
	}, nil)
	ch := func(p string) transcript.Change { return transcript.Change{FilePath: p, RepoRoot: root} }
	got := Covering([]transcript.Change{
		ch("packages/web/src/app.ts"), ch("packages/web/src/util.js"), ch("apps/api/index.js"),
		ch("svc/internal/x/x.go"), ch("tools/run.py"), ch("node_modules/left-pad/index.js"),
		{FilePath: "README.md", RepoRoot: root, Virtual: true},
	}, root, quiet)
	var labels []string
	for _, f := range got {
		labels = append(labels, f.Label)
	}
	if want := []string{"package-lock.json", "apps/api/package-lock.json", "svc/go.mod"}; !slices.Equal(labels, want) {
		t.Errorf("covering = %v, want %v", labels, want)
	}

	// A lockfile the turn changed is the turn's own check's, never this one's too.
	got = Covering([]transcript.Change{ch("apps/api/index.js"), ch("apps/api/package-lock.json")}, root, quiet)
	if len(got) != 0 {
		t.Errorf("a changed lockfile is the turn check's: %v", got)
	}
	// Without a repository there's nothing to walk up to.
	if got := Covering([]transcript.Change{{FilePath: "apps/api/index.js"}}, root, quiet); len(got) != 0 {
		t.Errorf("no repository, no covering file: %v", got)
	}
	// A turn spanning several repositories labels the file under its repository's folder.
	multi := transcript.Change{FilePath: "api/apps/api/index.js", RepoRoot: root, RepoDir: "api"}
	if got := Covering([]transcript.Change{multi}, root, quiet); len(got) != 1 || got[0].Label != "api/apps/api/package-lock.json" {
		t.Errorf("multi-repository label: %v", got)
	}
}

// Without leaves out the files another check sends.
func TestWorkspaceWithout(t *testing.T) {
	root, _ := repo(t, map[string]string{"a/go.mod": "module a\n", "b/go.mod": "module b\n"}, nil)
	w := Workspace{Files: []ScanFile{{Label: "a/go.mod", Path: root + "/a/go.mod"}, {Label: "b/go.mod", Path: root + "/b/go.mod"}}}
	got := w.Without(map[string]bool{w.Files[0].Key(): true})
	if len(got.Files) != 1 || got.Files[0].Label != "b/go.mod" || len(w.Files) != 2 {
		t.Errorf("without = %v (original %v)", got.Files, w.Files)
	}
}

// ScanLockfiles sends each file whole, shows its notice under its own heading with no summary
// line, and reports as checked only the files the server answered, so a failed one is tried
// again on a later turn.
func TestScanLockfiles(t *testing.T) {
	root, _ := repo(t, map[string]string{"package-lock.json": lock(map[string]string{"lodash": "4.17.15"})}, nil)
	f := ScanFile{Label: "package-lock.json", Path: root + "/package-lock.json", Root: root}
	srv := &fakeServer{}
	text, _, _, _, checked := ScanLockfiles([]ScanFile{f}, nil, srv, quiet)
	if len(srv.got) != 1 || !srv.got[0].Whole || srv.got[0].Path != "package-lock.json" {
		t.Fatalf("requests = %+v", srv.got)
	}
	if text != labelled("package-lock.json", "flagged lodash@4.17.15:") {
		t.Errorf("notice = %q", text)
	}
	if len(checked) != 1 || checked[0] != f.Key() {
		t.Errorf("checked = %v", checked)
	}

	failing := &fakeServer{err: errors.New("503")}
	if _, _, _, _, checked := ScanLockfiles([]ScanFile{f}, nil, failing, quiet); len(checked) != 0 {
		t.Errorf("a failed file isn't checked: %v", checked)
	}
	none := &fakeServer{err: ErrUnavailable}
	if text, _, _, _, checked := ScanLockfiles([]ScanFile{f}, nil, none, quiet); text != "" || len(checked) != 0 {
		t.Errorf("no dependency check, nothing said: %q %v", text, checked)
	}
}
