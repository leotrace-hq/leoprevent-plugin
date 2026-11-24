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

// installed is an npm lockfile with each package at its install folder ("node_modules/a/node_modules/x").
func installed(folders map[string]string) string {
	var b strings.Builder
	b.WriteString(`{"lockfileVersion": 3, "packages": {"": {}`)
	for folder, v := range folders {
		name := folder[strings.LastIndex(folder, "node_modules/")+len("node_modules/"):]
		resolved := "https://registry.npmjs.org/" + name + "/-/" + name + "-" + v + ".tgz"
		if strings.HasPrefix(name, "@acme/") {
			resolved = "https://npm.acme.internal/" + name + "-" + v + ".tgz"
		}
		fmt.Fprintf(&b, `, %q: {"version": %q, "resolved": %q}`, folder, v, resolved)
	}
	b.WriteString(`}}`)
	return b.String()
}

func removedNames(rs []wire.RemovedDependency) string {
	var s []string
	for _, r := range rs {
		s = append(s, r.Name+"@"+r.Version)
	}
	return strings.Join(s, ",")
}

// What the turn took out of the file goes on its request (LEO-513): not a version still installed
// in another folder, never a private one, and once per file when it's split.
func TestTheTurnsRemovalsAreSent(t *testing.T) {
	prev := maxPerRequest
	maxPerRequest = 1
	t.Cleanup(func() { maxPerRequest = prev })
	root, ts := repo(t,
		map[string]string{"package-lock.json": installed(map[string]string{
			"node_modules/x": "2.0.0", "node_modules/y": "1.0.0", "node_modules/lodash": "4.17.15"})},
		map[string]string{"package-lock.json": installed(map[string]string{
			"node_modules/x": "1.0.0", "node_modules/lodash": "4.17.15", "node_modules/old/node_modules/lodash": "4.17.15",
			"node_modules/left-pad": "1.3.0", "node_modules/@acme/ui": "2.0.0"})})
	srv := &fakeServer{}
	Run([]transcript.Change{{FilePath: "package-lock.json", RepoRoot: root}}, root, ts, srv, quiet)
	if len(srv.got) != 2 {
		t.Fatalf("x and y, one per request: %+v", srv.got)
	}
	removed := map[string]bool{}
	for _, r := range srv.got[0].Removed {
		removed[r.Name+"@"+r.Version] = true
	}
	if len(removed) != 1 || !removed["left-pad@1.3.0"] {
		t.Errorf("removed %v: want left-pad only (x moved to a new version but is still listed under its own key, "+
			"lodash 4.17.15 is still in another folder, @acme/ui is private)", removed)
	}
	if len(srv.got[1].Removed) != 0 {
		t.Errorf("removals go on the first request only: %+v", srv.got[1].Removed)
	}
	if srv.got[0].Whole || srv.got[0].Deleted {
		t.Errorf("a changes-only turn is neither whole nor deleted: %+v", srv.got[0])
	}
}

// A turn that only removed dependencies still sends one request, with no packages, and it has no
// notice of its own.
func TestARemovalsOnlyTurnIsSent(t *testing.T) {
	root, ts := repo(t,
		map[string]string{"package-lock.json": installed(map[string]string{"node_modules/a": "1.0.0"})},
		map[string]string{"package-lock.json": installed(map[string]string{"node_modules/a": "1.0.0", "node_modules/b": "2.0.0"})})
	srv := &fakeServer{}
	notice, _, agent := Run([]transcript.Change{{FilePath: "package-lock.json", RepoRoot: root}}, root, ts, srv, quiet)
	if len(srv.got) != 1 {
		t.Fatalf("requests: %+v", srv.got)
	}
	req := srv.got[0]
	if req.Packages == nil || len(req.Packages) != 0 || removedNames(req.Removed) != "b@2.0.0" || req.Deleted || req.Path != "package-lock.json" {
		t.Errorf("removals only: %+v", req)
	}
	if notice != "" || agent != "" {
		t.Errorf("nothing was looked up, so nothing is said: %q, %q", notice, agent)
	}
}

// Whole is sent when every dependency in the file is: the scan, a file with no start-of-turn copy.
// Never on a changes-only turn, nor on part of a file split across requests.
func TestWholeIsSentForEveryDependency(t *testing.T) {
	root, ts := repo(t,
		map[string]string{"package-lock.json": lock(map[string]string{"a": "1.0.1", "b": "1.0.0"})},
		map[string]string{"package-lock.json": lock(map[string]string{"a": "1.0.0", "b": "1.0.0"})})
	changes := []transcript.Change{{FilePath: "package-lock.json", RepoRoot: root}}
	srv := &fakeServer{}
	Run(changes, root, ts, srv, quiet)
	if len(srv.got) != 1 || srv.got[0].Whole {
		t.Errorf("a turn's changes only: %+v", srv.got)
	}
	srv = &fakeServer{}
	Run(changes, root, nil, srv, quiet)
	if len(srv.got) != 1 || !srv.got[0].Whole || len(srv.got[0].Packages) != 2 {
		t.Errorf("no start-of-turn copy: %+v", srv.got)
	}
	srv = &fakeServer{}
	w := Workspace{Files: []ScanFile{{Label: "package-lock.json", Path: filepath.Join(root, "package-lock.json"), Root: root}}}
	Scan(w, nil, root, ts, srv, quiet)
	if len(srv.got) != 1 || !srv.got[0].Whole {
		t.Errorf("the scan: %+v", srv.got)
	}
	srv = &fakeServer{}
	RunWhole(w.Files, w.Files, nil, root, srv, quiet)
	if len(srv.got) != 1 || !srv.got[0].Whole {
		t.Errorf("no repository: %+v", srv.got)
	}
	prev := maxPerRequest
	maxPerRequest = 1
	t.Cleanup(func() { maxPerRequest = prev })
	srv = &fakeServer{}
	Scan(w, nil, root, ts, srv, quiet)
	if len(srv.got) != 2 || srv.got[0].Whole || srv.got[1].Whole {
		t.Errorf("a split file is never whole: %+v", srv.got)
	}
}

// A dependency file the turn deleted sends everything it held at the start of the turn (but a
// private package) as removed, marked deleted, with no packages and no notice. With no
// start-of-turn copy there's nothing to send, and it isn't counted as unchecked.
func TestADeletedFileSendsWhatItHeld(t *testing.T) {
	root, ts := repo(t, nil, map[string]string{"web/package-lock.json": lock(map[string]string{"a": "1.0.0", "b": "2.0.0", "@acme/ui": "1.0.0"})})
	changes := []transcript.Change{{FilePath: "web/package-lock.json", RepoRoot: root, Deleted: true}}
	srv := &fakeServer{}
	notice, _, agent := Run(changes, root, ts, srv, quiet)
	if len(srv.got) != 1 {
		t.Fatalf("requests: %+v", srv.got)
	}
	req := srv.got[0]
	got := map[string]bool{}
	for _, r := range req.Removed {
		got[r.Name+"@"+r.Version] = true
	}
	if !req.Deleted || req.Packages == nil || len(req.Packages) != 0 || len(got) != 2 || !got["a@1.0.0"] || !got["b@2.0.0"] ||
		req.Ecosystem != "npm" || req.Path != "web/package-lock.json" || req.Whole {
		t.Errorf("deleted: %+v", req)
	}
	if notice != "" || agent != "" {
		t.Errorf("a deleted file has no notice of its own: %q, %q", notice, agent)
	}

	for name, ts := range map[string]TurnStart{"no turn start": nil, "not in the turn start": func(string) deps.Opener {
		return func(p string) ([]byte, error) { return nil, &fs.PathError{Op: "open", Path: p, Err: fs.ErrNotExist} }
	}} {
		srv := &fakeServer{}
		if n, _, _ := Run(changes, root, ts, srv, quiet); n != "" || len(srv.got) != 0 {
			t.Errorf("%s: nothing to send: notice %q, requests %+v", name, n, srv.got)
		}
	}

	// A failed send counts the file as not checked; a successful one doesn't count it as checked.
	srv = &fakeServer{err: errors.New("503")}
	r := check(turnItems(changes, root, nil, quiet), ts, srv, quiet)
	if !r.t.missed["web/package-lock.json"] || len(r.notices) != 0 {
		t.Errorf("a failure is missed: %+v", r.t)
	}
	r = check(turnItems(changes, root, nil, quiet), ts, &fakeServer{}, quiet)
	if len(r.t.checked) != 0 || len(r.t.missed) != 0 {
		t.Errorf("a deleted file is neither checked nor missed: %+v", r.t)
	}
}

// A move is never a fix (LEO-513): when the turn deleted a dependency file and added one of the same
// name elsewhere (a lockfile moved and regenerated, which git doesn't pair as a rename), the deleted
// one isn't sent, so none of its packages are recorded as removed. The new file is checked as usual.
// A deletion with no file of that name added or changed is still sent.
func TestAMovedLockfileIsNeverSentAsRemoved(t *testing.T) {
	root, ts := repo(t,
		map[string]string{"apps/web/package-lock.json": lock(map[string]string{"a": "1.0.0", "b": "2.1.0"}),
			"api/package-lock.json": lock(map[string]string{"c": "1.0.1"})},
		map[string]string{"web/package-lock.json": lock(map[string]string{"a": "1.0.0", "b": "2.0.0"}),
			"api/package-lock.json": lock(map[string]string{"c": "1.0.0"})})
	changes := []transcript.Change{
		{FilePath: "web/package-lock.json", RepoRoot: root, Deleted: true},
		{FilePath: "apps/web/package-lock.json", RepoRoot: root},
	}
	srv := &fakeServer{}
	Run(changes, root, ts, srv, quiet)
	for _, req := range srv.got {
		if req.Path == "web/package-lock.json" || req.Deleted || len(req.Removed) != 0 {
			t.Errorf("a moved file's packages must never be sent as removed: %+v", req)
		}
	}
	if len(srv.got) != 1 || srv.got[0].Path != "apps/web/package-lock.json" {
		t.Errorf("the new file is still checked: %+v", srv.got)
	}

	// The same deletion beside a file of another name, or beside a change to a lockfile of the same
	// name that was already there (another project in a monorepo), is a real deletion.
	for name, beside := range map[string]transcript.Change{
		"another name":           {FilePath: "apps/web/go.mod", RepoRoot: root},
		"an existing same-named": {FilePath: "api/package-lock.json", RepoRoot: root},
	} {
		srv := &fakeServer{}
		Run([]transcript.Change{changes[0], beside}, root, ts, srv, quiet)
		sent := false
		for _, req := range srv.got {
			sent = sent || (req.Path == "web/package-lock.json" && req.Deleted && len(req.Removed) == 2)
		}
		if !sent {
			t.Errorf("%s: a deletion with no new file of its name is still sent: %+v", name, srv.got)
		}
	}
}

// The scan's count of files leaves out a deleted one.
func TestTheScanDoesNotCountADeletedFile(t *testing.T) {
	root, ts := repo(t,
		map[string]string{"package-lock.json": lock(map[string]string{"a": "1.0.0"})},
		map[string]string{"package-lock.json": lock(map[string]string{"a": "1.0.0"}), "old/package-lock.json": lock(map[string]string{"b": "1.0.0"})})
	w := Workspace{Files: []ScanFile{{Label: "package-lock.json", Path: filepath.Join(root, "package-lock.json"), Root: root}}}
	srv := &fakeServer{}
	text, _, _, _ := Scan(w, []transcript.Change{{FilePath: "old/package-lock.json", RepoRoot: root, Deleted: true}}, root, ts, srv, quiet)
	if len(srv.got) != 2 || !srv.got[1].Deleted {
		t.Fatalf("the scanned file and the deleted one: %+v", srv.got)
	}
	if !strings.Contains(text, "in 1 dependency file\n") {
		t.Errorf("one file noticed, of one checked:\n%s", text)
	}
}

// branchServer is a fakeServer that is also a BranchTeller, answering by folder and counting
// how often each was asked.
type branchServer struct {
	fakeServer
	on    map[string]*bool
	asked map[string]int
}

func (b *branchServer) DefaultBranch(dir string) *bool {
	b.asked[dir]++
	return b.on[dir]
}

func flag(v bool) *bool { return &v }

// Every request says whether its file's repository is on its default branch (LEO-513), asked
// once per repository however many files and requests it has: a turn spanning two repositories
// sends each its own answer, and one that can't tell sends nil. A checker that can't tell at all
// sends nil everywhere.
func TestEveryRequestSaysWhetherItsRepositoryIsOnTheDefaultBranch(t *testing.T) {
	mainRoot, ts := repo(t, map[string]string{
		"package-lock.json":     lock(map[string]string{"a": "1.0.1"}),
		"web/package-lock.json": lock(map[string]string{"b": "1.0.0"}),
	}, map[string]string{
		"package-lock.json":     lock(map[string]string{"a": "1.0.0"}),
		"web/package-lock.json": lock(map[string]string{"b": "1.0.0", "c": "2.0.0"}),
		"old/package-lock.json": lock(map[string]string{"d": "1.0.0"}),
	})
	featureRoot, _ := repo(t, map[string]string{"package-lock.json": lock(map[string]string{"e": "1.0.0"})}, nil)
	unknownRoot, _ := repo(t, map[string]string{"package-lock.json": lock(map[string]string{"f": "1.0.0"})}, nil)
	changes := []transcript.Change{
		{FilePath: "package-lock.json", RepoRoot: mainRoot},
		{FilePath: "web/package-lock.json", RepoRoot: mainRoot}, // removals only
		{FilePath: "old/package-lock.json", RepoRoot: mainRoot, Deleted: true},
		{FilePath: "feature/package-lock.json", RepoDir: "feature", RepoRoot: featureRoot},
		{FilePath: "unknown/package-lock.json", RepoDir: "unknown", RepoRoot: unknownRoot},
	}
	srv := &branchServer{on: map[string]*bool{mainRoot: flag(true), featureRoot: flag(false)}, asked: map[string]int{}}
	Run(changes, mainRoot, func(r string) deps.Opener { return ts(mainRoot) }, srv, quiet)
	if len(srv.got) != 5 {
		t.Fatalf("one request per file: %+v", srv.got)
	}
	want := []string{"true", "true", "true", "false", "nil"}
	for i, req := range srv.got {
		if got := describe(req.DefaultBranch); got != want[i] {
			t.Errorf("request %d (%s, removed %d, deleted %v): default_branch %s, want %s", i, req.Path, len(req.Removed), req.Deleted, got, want[i])
		}
	}
	if srv.asked[mainRoot] != 1 || srv.asked[featureRoot] != 1 || srv.asked[unknownRoot] != 1 || len(srv.asked) != 3 {
		t.Errorf("each repository is asked once: %v", srv.asked)
	}

	// The scan carries it too; a file with no root (the transcript fallback) is asked by its folder.
	srv = &branchServer{on: map[string]*bool{mainRoot: flag(false), filepath.Join(mainRoot, "web"): flag(true)}, asked: map[string]int{}}
	w := Workspace{Files: []ScanFile{{Label: "package-lock.json", Path: filepath.Join(mainRoot, "package-lock.json"), Root: mainRoot}}}
	Scan(w, []transcript.Change{{FilePath: filepath.Join(mainRoot, "web", "package-lock.json")}}, mainRoot, nil, srv, quiet)
	if len(srv.got) != 2 || describe(srv.got[0].DefaultBranch) != "false" || describe(srv.got[1].DefaultBranch) != "true" {
		t.Errorf("the scan: %+v", srv.got)
	}

	// A walked folder's files have no repository: nil, and nothing is asked.
	srv = &branchServer{on: map[string]*bool{}, asked: map[string]int{}}
	walked := []ScanFile{{Label: "package-lock.json", Path: filepath.Join(featureRoot, "package-lock.json")}}
	RunWhole(walked, walked, nil, featureRoot, srv, quiet)
	if len(srv.got) != 1 || srv.got[0].DefaultBranch != nil {
		t.Errorf("no repository: %+v", srv.got)
	}

	plain := &fakeServer{}
	Run(changes, mainRoot, func(r string) deps.Opener { return ts(mainRoot) }, plain, quiet)
	for _, req := range plain.got {
		if req.DefaultBranch != nil {
			t.Errorf("a checker that can't tell sends nil: %+v", req)
		}
	}
}

func describe(b *bool) string {
	switch {
	case b == nil:
		return "nil"
	case *b:
		return "true"
	}
	return "false"
}
