package depcheck

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/deps"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// fakeServer records each request and answers with a notice naming what it was sent.
type fakeServer struct {
	got []wire.DependenciesRequest
	err error
}

func (f *fakeServer) CheckDependencies(req wire.DependenciesRequest) (wire.DependenciesResponse, error) {
	f.got = append(f.got, req)
	if f.err != nil {
		return wire.DependenciesResponse{}, f.err
	}
	var names []string
	for _, p := range req.Packages {
		names = append(names, p.Name+"@"+p.Version+":"+p.Change)
	}
	msg := "flagged " + strings.Join(names, ",")
	return wire.DependenciesResponse{Ecosystem: req.Ecosystem, Messages: wire.DependencyMessages{Developer: &msg}}, nil
}

func lock(pkgs map[string]string) string {
	var b strings.Builder
	b.WriteString(`{"lockfileVersion": 3, "packages": {"": {"dependencies": {`)
	first := true
	for name := range pkgs {
		if !first {
			b.WriteString(",")
		}
		first = false
		b.WriteString(`"` + name + `": "*"`)
	}
	b.WriteString(`}}`)
	for name, v := range pkgs {
		resolved := "https://registry.npmjs.org/" + name + "/-/" + name + "-" + v + ".tgz"
		if strings.HasPrefix(name, "@acme/") {
			resolved = "https://npm.acme.internal/" + name + "-" + v + ".tgz"
		}
		b.WriteString(`, "node_modules/` + name + `": {"version": "` + v + `", "resolved": "` + resolved + `"}`)
	}
	b.WriteString(`}}`)
	return b.String()
}

// repo writes files under a temp root and returns it with a TurnStart serving the given
// start-of-turn copies (a missing name is a file that didn't exist then).
func repo(t *testing.T, now map[string]string, before map[string]string) (string, TurnStart) {
	t.Helper()
	root := t.TempDir()
	for rel, body := range now {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	ts := func(r string) deps.Opener {
		return func(path string) ([]byte, error) {
			rel, _ := filepath.Rel(r, path)
			if b, ok := before[filepath.ToSlash(rel)]; ok {
				return []byte(b), nil
			}
			return nil, &fs.PathError{Op: "open", Path: path, Err: fs.ErrNotExist}
		}
	}
	return root, ts
}

// Only the turn's changes are sent, each with its context; a private package never leaves the
// machine; files no reader reads are ignored.
func TestSendsTheTurnsChangesOnly(t *testing.T) {
	root, ts := repo(t,
		map[string]string{
			"web/package-lock.json": lock(map[string]string{"lodash": "4.17.15", "axios": "1.6.2", "left-pad": "1.3.0", "@acme/ui": "2.0.0"}),
			"web/app.js":            "console.log(1)",
		},
		map[string]string{"web/package-lock.json": lock(map[string]string{"lodash": "4.17.15", "axios": "1.6.0"})})
	srv := &fakeServer{}
	changes := []transcript.Change{
		{FilePath: "web/package-lock.json", RepoRoot: root},
		{FilePath: "web/app.js", RepoRoot: root},
	}
	notice, _, _ := Run(changes, root, ts, srv, quiet)
	if len(srv.got) != 1 || srv.got[0].Ecosystem != "npm" {
		t.Fatalf("one npm request: %+v", srv.got)
	}
	sent := map[string]wire.DependencyVersion{}
	for _, p := range srv.got[0].Packages {
		sent[p.Name] = p
	}
	if len(sent) != 2 || sent["axios"].Change != wire.DependencyChanged || sent["axios"].Previous != "1.6.0" ||
		sent["left-pad"].Change != wire.DependencyAdded {
		t.Errorf("sent %+v, want axios changed from 1.6.0 and left-pad added; unchanged lodash and private @acme/ui not sent", sent)
	}
	if !strings.HasPrefix(notice, "web/package-lock.json:\nflagged ") {
		t.Errorf("one file's notice is the server's, named by its file: %q", notice)
	}
}

// A file created this turn sends everything as added; with no start-of-turn copy, everything is
// sent with no change known.
func TestNewFilesAndNoBaseline(t *testing.T) {
	root, ts := repo(t, map[string]string{"package-lock.json": lock(map[string]string{"a": "1.0.0"})}, nil)
	srv := &fakeServer{}
	Run([]transcript.Change{{FilePath: "package-lock.json", RepoRoot: root}}, root, ts, srv, quiet)
	if p := srv.got[0].Packages[0]; p.Change != wire.DependencyAdded {
		t.Errorf("created this turn: %+v", p)
	}
	srv = &fakeServer{}
	Run([]transcript.Change{{FilePath: "package-lock.json", RepoRoot: root}}, root, nil, srv, quiet)
	if p := srv.got[0].Packages[0]; p.Change != "" || p.Previous != "" {
		t.Errorf("no baseline: %+v", p)
	}
	srv = &fakeServer{}
	noCopy := func(string) deps.Opener {
		return func(string) ([]byte, error) { return nil, errors.New("no start-of-turn copy kept") }
	}
	Run([]transcript.Change{{FilePath: "package-lock.json", RepoRoot: root}}, root, noCopy, srv, quiet)
	if p := srv.got[0].Packages[0]; p.Change != "" {
		t.Errorf("an unreadable start-of-turn copy is unknown, never added: %+v", p)
	}
}

// It fails open: an unreadable lockfile, a deleted one or a failed call is no notice, never an
// error, and nothing unchanged is sent.
func TestFailsOpen(t *testing.T) {
	root, ts := repo(t, map[string]string{"package-lock.json": `{"lockfileVersion": 1}`, "go.mod": "module m\n\ngo 1.21\n\nrequire a.com/x v1.0.0\n"},
		map[string]string{"go.mod": "module m\n\ngo 1.21\n\nrequire a.com/x v1.0.0\n"})
	srv := &fakeServer{}
	if n, _, _ := Run([]transcript.Change{
		{FilePath: "package-lock.json", RepoRoot: root},
		{FilePath: "go.mod", RepoRoot: root},
		{FilePath: "gone/package-lock.json", RepoRoot: root, Deleted: true},
	}, root, ts, srv, quiet); n != "" || len(srv.got) != 0 {
		t.Errorf("nothing to send: notice %q, requests %+v", n, srv.got)
	}
	root, ts = repo(t, map[string]string{"package-lock.json": lock(map[string]string{"a": "1.0.0"})}, nil)
	srv = &fakeServer{err: errors.New("503 no advisory copy")}
	if n, _, _ := Run([]transcript.Change{{FilePath: "package-lock.json", RepoRoot: root}}, root, ts, srv, quiet); n != "" || len(srv.got) != 1 {
		t.Errorf("a failed call: notice %q", n)
	}
}

// A list over the server's cap is split; several files' notices are each labelled.
func TestSplitsAndLabels(t *testing.T) {
	prev := maxPerRequest
	maxPerRequest = 2
	t.Cleanup(func() { maxPerRequest = prev })
	root, ts := repo(t, map[string]string{
		"a/package-lock.json": lock(map[string]string{"x": "1.0.0", "y": "1.0.0", "z": "1.0.0"}),
		"b/go.mod":            "module b\n\ngo 1.21\n\nrequire q.com/q v1.0.0\n",
	}, nil)
	srv := &fakeServer{}
	notice, _, _ := Run([]transcript.Change{
		{FilePath: "a/package-lock.json", RepoRoot: root},
		{FilePath: "b/go.mod", RepoRoot: root},
	}, root, ts, srv, quiet)
	if len(srv.got) != 3 || len(srv.got[0].Packages) != 2 || len(srv.got[1].Packages) != 1 || srv.got[2].Ecosystem != "Go" {
		t.Errorf("requests: %+v", srv.got)
	}
	if !strings.Contains(notice, "a/package-lock.json:\nflagged") || !strings.Contains(notice, "b/go.mod:\nflagged q.com/q@v1.0.0:added") {
		t.Errorf("notice:\n%s", notice)
	}
}

// A repository's label is stripped to find the file on disk; the transcript path is used as is.
func TestOnDisk(t *testing.T) {
	if got, ok := onDisk(transcript.Change{FilePath: "api/go.mod", RepoDir: "api", RepoRoot: "/r/api"}, "/cwd"); !ok || got != filepath.Join("/r/api", "go.mod") {
		t.Errorf("labelled: %s, %v", got, ok)
	}
	if got, ok := onDisk(transcript.Change{FilePath: "web/go.mod"}, "/cwd"); !ok || got != filepath.Join("/cwd", "web", "go.mod") {
		t.Errorf("transcript, relative: %s, %v", got, ok)
	}
}

// A path that leads outside the repository or the project folder is never read: "../" in the
// path, an absolute path elsewhere, or a folder that is a symlink out.
func TestOnDiskStaysInsideTheProject(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "package-lock.json"), []byte(lock(map[string]string{"a": "1.0.0"})), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, ch := range map[string]transcript.Change{
		"../ under the root":         {FilePath: "../../etc/package-lock.json", RepoRoot: root},
		"../ under a label":          {FilePath: "api/../../package-lock.json", RepoDir: "api", RepoRoot: root},
		"../ on the transcript path": {FilePath: "../package-lock.json"},
		"an absolute path elsewhere": {FilePath: filepath.Join(outside, "package-lock.json")},
	} {
		if _, ok := onDisk(ch, root); ok {
			t.Errorf("%s: read as inside", name)
		}
	}
	if err := os.Symlink(outside, filepath.Join(root, "linked")); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	ch := transcript.Change{FilePath: "linked/package-lock.json", RepoRoot: root}
	if _, ok := onDisk(ch, root); ok {
		t.Error("a symlinked folder out of the repository is read as inside")
	}
	srv := &fakeServer{}
	if n, _, _ := Run([]transcript.Change{ch, {FilePath: "../package-lock.json"}}, root, nil, srv, quiet); n != "" || len(srv.got) != 0 {
		t.Errorf("nothing outside is read or sent: %q, %+v", n, srv.got)
	}
}

// The answer is the server's verdict, worked out the same way when an older server sends none;
// a partial check is logged as partial, so a clean verdict isn't mistaken for a full one.
func TestReadsTheVerdictAndReportsAPartialCheck(t *testing.T) {
	if got := answer(wire.DependenciesResponse{Verdict: wire.VerdictClean}, 3); got != wire.VerdictClean {
		t.Errorf("the server's verdict is the answer: %s", got)
	}
	if answer(wire.DependenciesResponse{}, 1) != wire.VerdictTriggered || answer(wire.DependenciesResponse{}, 0) != wire.VerdictClean {
		t.Error("an older server's answer is worked out from needs_fix")
	}
	root, ts := repo(t, map[string]string{"package-lock.json": lock(map[string]string{"next": "13.4.2"})}, nil)
	var logged strings.Builder
	log := slog.New(slog.NewTextHandler(&logged, nil))
	srv := partialServer{}
	if n, _, _ := Run([]transcript.Change{{FilePath: "package-lock.json", RepoRoot: root}}, root, ts, srv, log); n != "" {
		t.Errorf("clean and partial: no notice, got %q", n)
	}
	if !strings.Contains(logged.String(), "PARTIAL") || !strings.Contains(logged.String(), "unchecked=1") || !strings.Contains(logged.String(), "verdict=clean") {
		t.Errorf("log:\n%s", logged.String())
	}
}

// partialServer answers clean, with one package not fully checked.
type partialServer struct{}

func (partialServer) CheckDependencies(req wire.DependenciesRequest) (wire.DependenciesResponse, error) {
	return wire.DependenciesResponse{Ecosystem: req.Ecosystem, Verdict: wire.VerdictClean, Unchecked: 1}, nil
}

// countingServer answers each file with the issue counts it's given, by ecosystem, and a notice.
// countingServer answers each ecosystem with its issue counts and, as the server does, a package
// needing a fix for each issue counted, the first malicious ones malicious. countsOnly answers
// with the counts alone, as a server that lists no packages would.
type countingServer struct {
	issues, malicious map[string]int
	fail              map[string]bool
	countsOnly        bool
}

func (c countingServer) CheckDependencies(req wire.DependenciesRequest) (wire.DependenciesResponse, error) {
	if c.fail[req.Ecosystem] {
		return wire.DependenciesResponse{}, errors.New("503 no advisory copy")
	}
	msg := "notice for " + req.Ecosystem
	resp := wire.DependenciesResponse{Ecosystem: req.Ecosystem, Issues: c.issues[req.Ecosystem], Malicious: c.malicious[req.Ecosystem],
		Messages: wire.DependencyMessages{Developer: &msg}}
	resp.Verdict = wire.VerdictClean
	if resp.Issues > 0 {
		resp.Verdict = wire.VerdictTriggered
	}
	for i := 0; i < resp.Issues && !c.countsOnly; i++ {
		resp.Packages = append(resp.Packages, wire.DependencyCheck{Name: fmt.Sprintf("p%d", i), Version: "1.0.0",
			Security: &wire.DependencySecurity{NeedsFix: true, Advisories: []wire.DependencyAdvisory{{Malicious: i < resp.Malicious}}}})
	}
	return resp, nil
}

// Across several dependency files, a summary line counts the packages that need fixing above the
// per-file notices; one file needs none; a file that couldn't be checked is counted. A server that
// lists no packages is summarised by its issue counts.
func TestASummaryAcrossDependencyFiles(t *testing.T) {
	root, ts := repo(t, map[string]string{
		"web/package-lock.json": lock(map[string]string{"a": "1.0.0"}),
		"api/go.mod":            "module api\n\ngo 1.21\n\nrequire q.com/q v1.0.0\n",
	}, nil)
	both := []transcript.Change{{FilePath: "web/package-lock.json", RepoRoot: root}, {FilePath: "api/go.mod", RepoRoot: root}}

	n, _, _ := Run(both, root, ts, countingServer{issues: map[string]int{"npm": 2, "Go": 1}}, quiet)
	if !strings.HasPrefix(n, "🛡️ LeoPrevent · dependency check: 3 packages with high or critical issues across 2 dependency files\n\n") ||
		!strings.Contains(n, "web/package-lock.json:\nnotice for npm") || !strings.Contains(n, "api/go.mod:\nnotice for Go") {
		t.Errorf("two files:\n%s", n)
	}
	n, _, _ = Run(both, root, ts, countingServer{issues: map[string]int{"npm": 2, "Go": 1}, malicious: map[string]int{"npm": 1}}, quiet)
	if !strings.HasPrefix(n, "🛡️ LeoPrevent · dependency check: 3 packages to fix across 2 dependency files, 1 of them malicious") {
		t.Errorf("with malware:\n%s", n)
	}
	// One file with an issue and one clean: still a summary over both files checked.
	n, _, _ = Run(both, root, ts, countingServer{issues: map[string]int{"npm": 1}}, quiet)
	if !strings.HasPrefix(n, "🛡️ LeoPrevent · dependency check: 1 package with high or critical issues across 2 dependency files") {
		t.Errorf("one file with an issue:\n%s", n)
	}
	n, _, _ = Run(both, root, ts, countingServer{issues: map[string]int{"npm": 2, "Go": 1}, countsOnly: true}, quiet)
	if !strings.HasPrefix(n, "🛡️ LeoPrevent · dependency check: 3 high or critical issues to fix across 2 dependency files\n\n") {
		t.Errorf("a server that lists no packages:\n%s", n)
	}
	// One file: no summary, just the file's name above the server's notice.
	if n, _, _ := Run(both[:1], root, ts, countingServer{issues: map[string]int{"npm": 2}}, quiet); n != "web/package-lock.json:\nnotice for npm" {
		t.Errorf("one file: %q", n)
	}
	// Three files, one of which couldn't be checked.
	root3, ts3 := repo(t, map[string]string{
		"web/package-lock.json":   lock(map[string]string{"a": "1.0.0"}),
		"admin/package-lock.json": lock(map[string]string{"b": "1.0.0"}),
		"api/go.mod":              "module api\n\ngo 1.21\n\nrequire q.com/q v1.0.0\n",
	}, nil)
	three := []transcript.Change{{FilePath: "web/package-lock.json", RepoRoot: root3}, {FilePath: "admin/package-lock.json", RepoRoot: root3}, {FilePath: "api/go.mod", RepoRoot: root3}}
	n, _, _ = Run(three, root3, ts3, countingServer{issues: map[string]int{"npm": 1}, fail: map[string]bool{"Go": true}}, quiet)
	if !strings.HasPrefix(n, "🛡️ LeoPrevent · dependency check: 2 packages with high or critical issues across 2 dependency files (1 file couldn't be checked)") {
		t.Errorf("one file not checked:\n%s", n)
	}
	// Nothing needs fixing anywhere: no summary, no notice.
	if n, _, _ := Run(both, root, ts, partialServer{}, quiet); n != "" {
		t.Errorf("nothing to fix: %q", n)
	}
}

// A server older than the issue counts is summarised like any other, by the packages it says need
// fixing.
func TestASummaryFromAnOlderServer(t *testing.T) {
	tl := tally{checked: map[string]bool{"a": true, "b": true}, missed: map[string]bool{}, needsFix: 2}
	if got := tl.summary(); got != "🛡️ LeoPrevent · dependency check: 2 packages with high or critical issues across 2 dependency files" {
		t.Errorf("older server: %q", got)
	}
}

// The file is named on the server's heading line; a notice without one gets the name above it.
func TestTheFileIsNamedOnTheHeading(t *testing.T) {
	for notice, want := range map[string]string{
		"🛡️ LeoPrevent · dependency check (1 package)\nlodash 4.17.15 has 1 high vulnerability.": "🛡️ LeoPrevent · dependency check (1 package) · web/package-lock.json\nlodash 4.17.15 has 1 high vulnerability.",
		"🛡️ LeoPrevent · dependency check (2 packages)":                                          "🛡️ LeoPrevent · dependency check (2 packages) · web/package-lock.json",
		"notice for npm": "web/package-lock.json:\nnotice for npm",
	} {
		if got := labelled("web/package-lock.json", notice); got != want {
			t.Errorf("labelled(%q) = %q, want %q", notice, got, want)
		}
	}
}

// markdownServer answers with a notice as text and as markdown, the way the server words it.
type markdownServer struct{}

func (markdownServer) CheckDependencies(req wire.DependenciesRequest) (wire.DependenciesResponse, error) {
	text := "🛡️ LeoPrevent · dependency check (1 package)\nlodash has 1 high vulnerability (GHSA-35jh-r3h4-6jhm)."
	md := "🛡️ LeoPrevent · dependency check (1 package)\nlodash has 1 high vulnerability ([GHSA-35jh-r3h4-6jhm](https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm))."
	return wire.DependenciesResponse{Ecosystem: req.Ecosystem, Messages: wire.DependencyMessages{Developer: &text, DeveloperMarkdown: &md}}, nil
}

// The markdown is the server's, named by its file like the text (escaped, so a path can't become
// markup); a server that sends no markdown gets its text in both.
func TestTheMarkdownNoticeIsTheServers(t *testing.T) {
	root, ts := repo(t,
		map[string]string{"my_app/package-lock.json": lock(map[string]string{"lodash": "4.17.15"})},
		map[string]string{"my_app/package-lock.json": lock(map[string]string{"lodash": "4.17.10"})})
	changes := []transcript.Change{{FilePath: "my_app/package-lock.json", RepoRoot: root}}
	text, md, _ := Run(changes, root, ts, markdownServer{}, quiet)
	if text != "🛡️ LeoPrevent · dependency check (1 package) · my_app/package-lock.json\nlodash has 1 high vulnerability (GHSA-35jh-r3h4-6jhm)." {
		t.Errorf("text = %q", text)
	}
	if md != `🛡️ LeoPrevent · dependency check (1 package) · my\_app/package-lock.json`+"\nlodash has 1 high vulnerability ([GHSA-35jh-r3h4-6jhm](https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm))." {
		t.Errorf("markdown = %q", md)
	}
	text, md, _ = Run(changes, root, ts, &fakeServer{}, quiet)
	if !strings.HasPrefix(md, `my\_app/package-lock.json:`+"\nflagged ") || strings.TrimPrefix(md, `my\_app`) != strings.TrimPrefix(text, "my_app") {
		t.Errorf("an older server: text %q, markdown %q", text, md)
	}
}

// Each request names its file relative to the repository, the form /review's paths take; a path
// the agent recorded as absolute is made relative to the project folder, and one that can't be
// is never sent.
func TestTheRequestNamesItsFileRelatively(t *testing.T) {
	root, ts := repo(t,
		map[string]string{"web/package-lock.json": lock(map[string]string{"lodash": "4.17.15"})},
		map[string]string{"web/package-lock.json": lock(map[string]string{"lodash": "4.17.10"})})
	srv := &fakeServer{}
	Run([]transcript.Change{{FilePath: "web/package-lock.json", RepoRoot: root}}, root, ts, srv, quiet)
	Run([]transcript.Change{{FilePath: filepath.Join(root, "web", "package-lock.json")}}, root, nil, srv, quiet)
	if len(srv.got) != 2 || srv.got[0].Path != "web/package-lock.json" || srv.got[1].Path != "web/package-lock.json" {
		t.Fatalf("paths sent: %+v", srv.got)
	}
	for in, want := range map[string]string{
		"web/package-lock.json":                       "web/package-lock.json",
		filepath.Join(root, "go.mod"):                 "go.mod",
		filepath.Join(filepath.Dir(root), "x", "a"):   "",
		"../outside/go.mod":                           "",
		filepath.Join("a", "..", "..", "b", "go.mod"): "",
	} {
		if got := wirePath(in, root); got != want {
			t.Errorf("wirePath(%q) = %q, want %q", in, got, want)
		}
	}
	if got := wirePath(filepath.Join(root, "go.mod"), ""); got != "" {
		t.Errorf("an absolute path with no project folder to be relative to is never sent: %q", got)
	}
}

// One version installed in several folders is sent once, with every folder it's in; another
// version is its own entry. Past maxLocations the rest are counted.
func TestEachVersionIsSentOnceWithItsLocations(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"lockfileVersion": 3, "packages": {"": {"dependencies": {"lodash": "*", "old-lib": "*"}},
		"node_modules/lodash": {"version": "4.17.15", "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz"},
		"node_modules/old-lib": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/old-lib/-/old-lib-1.0.0.tgz"},
		"node_modules/old-lib/node_modules/lodash": {"version": "4.17.15", "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz"},
		"node_modules/other/node_modules/lodash": {"version": "4.17.10", "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.10.tgz"}`)
	for i := 0; i < maxLocations+2; i++ {
		fmt.Fprintf(&b, `, "node_modules/p%02d/node_modules/ws": {"version": "8.17.0", "resolved": "https://registry.npmjs.org/ws/-/ws-8.17.0.tgz"}`, i)
	}
	b.WriteString(`}}`)
	root, _ := repo(t, map[string]string{"package-lock.json": b.String()}, nil)
	srv := &fakeServer{}
	Run([]transcript.Change{{FilePath: "package-lock.json"}}, root, nil, srv, quiet)
	if len(srv.got) != 1 {
		t.Fatalf("requests: %d", len(srv.got))
	}
	byVersion := map[string]wire.DependencyVersion{}
	for _, p := range srv.got[0].Packages {
		byVersion[p.Name+"@"+p.Version] = p
	}
	if got := byVersion["lodash@4.17.15"].Locations; strings.Join(got, ",") != "node_modules/lodash,node_modules/old-lib/node_modules/lodash" {
		t.Errorf("one version, both folders: %v", got)
	}
	if got := byVersion["lodash@4.17.10"].Locations; strings.Join(got, ",") != "node_modules/other/node_modules/lodash" {
		t.Errorf("another version is its own entry: %v", got)
	}
	if ws := byVersion["ws@8.17.0"]; len(ws.Locations) != maxLocations || ws.MoreLocations != 2 {
		t.Errorf("capped: %d locations, %d more", len(ws.Locations), ws.MoreLocations)
	}
}

// A dependency file in a test area (fixtures, or what the review counts as test code) is sent as it
// is, and its answer is used only for malware (decided 22 Oct 2026): with none, no notice, no count
// and nothing for the agent; with malware, its notice is shown, still with nothing for the agent.
// The project's own lockfile, and a folder merely named like a test one, are reported as ever.
func TestATestAreaIsReportedOnlyForMalware(t *testing.T) {
	files := map[string]string{}
	paths := []string{"package-lock.json", "plugin/deps/testdata/workspace/package-lock.json", "e2e/package-lock.json",
		"tests/app/package-lock.json", "web/fixtures/package-lock.json", "contest/package-lock.json"}
	for _, p := range paths {
		files[p] = lock(map[string]string{"lodash": "4.17.15"})
	}
	root, _ := repo(t, files, nil)
	var changes []transcript.Change
	for _, p := range paths {
		changes = append(changes, transcript.Change{FilePath: p, RepoRoot: root})
	}
	srv := &areaServer{malware: map[string]bool{"e2e/package-lock.json": true}}
	text, _, agent := Run(changes, root, nil, srv, quiet)
	for _, p := range paths {
		if !srv.sent[p] {
			t.Errorf("%s: every file is still sent as it is", p)
		}
	}
	for path, shown := range map[string]bool{
		"package-lock.json": true, "contest/package-lock.json": true, // the project's own
		"e2e/package-lock.json":                            true, // a test area, with malware
		"plugin/deps/testdata/workspace/package-lock.json": false, "tests/app/package-lock.json": false, "web/fixtures/package-lock.json": false,
	} {
		if got := strings.Contains(text, path+":"); got != shown {
			t.Errorf("%s: notice shown %v, want %v\n%s", path, got, shown, text)
		}
	}
	if strings.Count(agent, "FIX ") != 2 || strings.Contains(agent, "FIX e2e/") || strings.Contains(agent, "FIX tests/") {
		t.Errorf("only the project's own files are put to the agent:\n%s", agent)
	}
}

// areaServer answers every file with a notice and something for the agent, plus malware for the
// files named in malware, recording which files it was sent.
type areaServer struct {
	malware map[string]bool
	sent    map[string]bool
}

func (a *areaServer) CheckDependencies(req wire.DependenciesRequest) (wire.DependenciesResponse, error) {
	if a.sent == nil {
		a.sent = map[string]bool{}
	}
	a.sent[req.Path] = true
	notice, ask := "notice", "FIX "+req.Path
	resp := wire.DependenciesResponse{Ecosystem: req.Ecosystem, Verdict: wire.VerdictTriggered, Issues: 1,
		Messages: wire.DependencyMessages{Developer: &notice, Agent: &ask}}
	if a.malware[req.Path] {
		resp.Malicious = 1
	}
	return resp, nil
}

// An npm lockfile's request carries its lockfileVersion, so the server can say which npm to run
// (LEO-694); a go.mod's carries none.
func TestTheRequestCarriesTheLockfileVersion(t *testing.T) {
	v2 := strings.Replace(lock(map[string]string{"lodash": "4.17.15"}), `"lockfileVersion": 3`, `"lockfileVersion": 2`, 1)
	root, ts := repo(t,
		map[string]string{"package-lock.json": v2, "go.mod": "module m\n\ngo 1.21\n\nrequire a.com/x v1.0.1\n"},
		map[string]string{"package-lock.json": lock(map[string]string{"lodash": "4.17.10"}), "go.mod": "module m\n\ngo 1.21\n\nrequire a.com/x v1.0.0\n"})
	srv := &fakeServer{}
	Run([]transcript.Change{{FilePath: "package-lock.json", RepoRoot: root}, {FilePath: "go.mod", RepoRoot: root}}, root, ts, srv, quiet)
	got := map[string]int{}
	for _, r := range srv.got {
		got[r.Path] = r.LockfileVersion
	}
	if len(srv.got) != 2 || got["package-lock.json"] != 2 || got["go.mod"] != 0 {
		t.Errorf("lockfile versions sent: %v", got)
	}
}
