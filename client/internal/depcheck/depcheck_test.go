package depcheck

import (
	"errors"
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
	notice := Run(changes, root, ts, srv, quiet)
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
	if !strings.HasPrefix(notice, "flagged ") || strings.Contains(notice, "web/package-lock.json:") {
		t.Errorf("one file's notice is the server's, unprefixed: %q", notice)
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
	if n := Run([]transcript.Change{
		{FilePath: "package-lock.json", RepoRoot: root},
		{FilePath: "go.mod", RepoRoot: root},
		{FilePath: "gone/package-lock.json", RepoRoot: root, Deleted: true},
	}, root, ts, srv, quiet); n != "" || len(srv.got) != 0 {
		t.Errorf("nothing to send: notice %q, requests %+v", n, srv.got)
	}
	root, ts = repo(t, map[string]string{"package-lock.json": lock(map[string]string{"a": "1.0.0"})}, nil)
	srv = &fakeServer{err: errors.New("503 no advisory copy")}
	if n := Run([]transcript.Change{{FilePath: "package-lock.json", RepoRoot: root}}, root, ts, srv, quiet); n != "" || len(srv.got) != 1 {
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
	notice := Run([]transcript.Change{
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
	if n := Run([]transcript.Change{ch, {FilePath: "../package-lock.json"}}, root, nil, srv, quiet); n != "" || len(srv.got) != 0 {
		t.Errorf("nothing outside is read or sent: %q, %+v", n, srv.got)
	}
}

func TestSwitch(t *testing.T) {
	t.Setenv(switchEnv, "")
	if Enabled() {
		t.Error("off unless set")
	}
	t.Setenv(switchEnv, " ON ")
	if !Enabled() {
		t.Error("on")
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
	if n := Run([]transcript.Change{{FilePath: "package-lock.json", RepoRoot: root}}, root, ts, srv, log); n != "" {
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
