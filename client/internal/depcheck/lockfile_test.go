package depcheck

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
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
	text, _, _, _, _, checked := ScanLockfiles([]ScanFile{f}, nil, srv, quiet)
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
	if _, _, _, _, _, checked := ScanLockfiles([]ScanFile{f}, nil, failing, quiet); len(checked) != 0 {
		t.Errorf("a failed file isn't checked: %v", checked)
	}
	none := &fakeServer{err: ErrUnavailable}
	if text, _, _, _, _, checked := ScanLockfiles([]ScanFile{f}, nil, none, quiet); text != "" || len(checked) != 0 {
		t.Errorf("no dependency check, nothing said: %q %v", text, checked)
	}
}

// sessionServer answers with a session offer (LEO-831), as the server does for a mid-session file
// with nothing fixable on its major.
type sessionServer struct{}

func (sessionServer) CheckDependencies(req wire.DependenciesRequest) (wire.DependenciesResponse, error) {
	notice, offer := "🛡️ LeoPrevent · 1 vulnerable dependency has no fix on its current major version\n- express 3.21.2 → 4", "SESSION OFFER"
	return wire.DependenciesResponse{Ecosystem: req.Ecosystem, Messages: wire.DependencyMessages{Developer: &notice, AgentOffer: &offer,
		AgentOfferPackages: []string{"express@3.21.2"}, AgentOfferSession: "Upgrade in a new session"}}, nil
}

// A session offer is returned apart from the fix offers, with its label, so it's asked on its own.
func TestScanLockfilesKeepsASessionOfferApart(t *testing.T) {
	root, _ := repo(t, map[string]string{"package-lock.json": lock(map[string]string{"express": "3.21.2"})}, nil)
	f := ScanFile{Label: "package-lock.json", Path: root + "/package-lock.json", Root: root}
	_, _, _, offer, sessions, _ := ScanLockfiles([]ScanFile{f}, nil, sessionServer{}, quiet)
	if offer != "" || len(sessions) != 1 || sessions[0].Text != "SESSION OFFER" || sessions[0].Label != "Upgrade in a new session" {
		t.Errorf("offer %q, sessions %+v", offer, sessions)
	}
}

// partsServer answers each file with a fix offer in parts (LEO-832), as the server does for a
// client that sends combined_offers, and a session offer for express, which is never combined.
type partsServer struct{}

func (partsServer) CheckDependencies(req wire.DependenciesRequest) (wire.DependenciesResponse, error) {
	notice := "🛡️ LeoPrevent · 1 vulnerable dependency has a fix\n- lodash 4.17.15"
	offer := "WHOLE OFFER " + req.Path
	m := wire.DependencyMessages{Developer: &notice, AgentOffer: &offer, AgentOfferPackages: []string{"lodash@4.17.15"},
		AgentOfferChanges: "Make each change in " + req.Path, AgentOfferRules: []string{"RULE", "PRIORITY"}}
	if strings.Contains(req.Path, "worker") {
		session := "SESSION OFFER"
		m = wire.DependencyMessages{Developer: &notice, AgentOffer: &session, AgentOfferPackages: []string{"express@3.21.2"}, AgentOfferSession: "Upgrade in a new session"}
	}
	return wire.DependenciesResponse{Ecosystem: req.Ecosystem, Messages: m}, nil
}

// Two covering files' fix offers come back as one, from their parts; a session offer stays apart.
func TestScanLockfilesMakesSeveralFixOffersOne(t *testing.T) {
	l := lock(map[string]string{"lodash": "4.17.15"})
	root, _ := repo(t, map[string]string{"api/package-lock.json": l, "web/package-lock.json": l, "worker/package-lock.json": l}, nil)
	var files []ScanFile
	for _, d := range []string{"web", "api", "worker"} {
		files = append(files, ScanFile{Label: d + "/package-lock.json", Path: root + "/" + d + "/package-lock.json", Root: root})
	}
	_, _, _, offer, sessions, _ := ScanLockfiles(files, nil, partsServer{}, quiet)
	if strings.Contains(offer, "WHOLE OFFER") || strings.Count(offer, "RULE") != 1 || strings.Count(offer, wire.OfferAnsweredLine) != 1 ||
		!strings.Contains(offer, "\"Fix the 2 dependencies in these 2 files") || !strings.Contains(offer, "RULE\nPRIORITY\n\napi/package-lock.json:\n") {
		t.Errorf("one offer expected:\n%s", offer)
	}
	if len(sessions) != 1 || sessions[0].Text != "SESSION OFFER" {
		t.Errorf("the session offer stays apart: %+v", sessions)
	}
}
