package imports

import (
	"fmt"
	"strings"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
	"github.com/leotrace-hq/leoprevent-plugin/limits"
)

// checkLines asserts the invariant every consumer depends on: Lines is
// index-aligned with the excerpt's lines, strictly increasing, and each number
// names the line's REAL position in the original file. A violation is silent
// downstream (the server renders a plausible wrong file:line), so it is asserted
// directly rather than through behaviour.
func checkLines(t *testing.T, orig, excerpt string, nums []int) {
	t.Helper()
	origLines := strings.Split(strings.TrimRight(orig, "\n"), "\n")
	exLines := strings.Split(excerpt, "\n")
	if len(exLines) != len(nums) {
		t.Fatalf("excerpt has %d lines but %d line numbers", len(exLines), len(nums))
	}
	prev := 0
	for i, n := range nums {
		if n <= prev {
			t.Fatalf("line numbers not strictly increasing at %d: %v", i, nums)
		}
		prev = n
		if n < 1 || n > len(origLines) {
			t.Fatalf("line number %d out of range 1..%d", n, len(origLines))
		}
		if origLines[n-1] != exLines[i] {
			t.Fatalf("line %d: excerpt has %q, file has %q", n, exLines[i], origLines[n-1])
		}
	}
}

const pyHelper = `import requests
from urllib.parse import urlparse

ALLOWED_HOSTS = ["api.internal", "cdn.internal"]
TIMEOUT = 5


def _resolve(host):
    """Resolve a host to an address."""
    import socket
    return socket.gethostbyname(host)


def safe_fetch(url):
    host = urlparse(url).hostname
    if host not in ALLOWED_HOSTS:
        raise ValueError("blocked")
    _resolve(host)
    return requests.get(url, timeout=TIMEOUT).text


def render_template(name, ctx):
    with open(name) as fh:
        body = fh.read()
    for k, v in ctx.items():
        body = body.replace("{{%s}}" % k, v)
    return body


def send_mail(to, subject, body):
    import smtplib
    conn = smtplib.SMTP("localhost")
    conn.sendmail("noreply@example.com", to, body)
    conn.quit()
`

func TestSliceKeepsTheReachedFunctionAndDropsTheRest(t *testing.T) {
	refs := map[string]bool{"safe_fetch": true, "netutil": true}
	excerpt, nums, ok := sliceFile("netutil.py", pyHelper, refs, limits.MaxContextFileBytes, true)
	if !ok {
		t.Fatal("expected the helper to slice")
	}
	checkLines(t, pyHelper, excerpt, nums)

	// The reached function's body is the whole point of pulling this file.
	for _, want := range []string{"ALLOWED_HOSTS", "raise ValueError", "requests.get(url, timeout=TIMEOUT)"} {
		if !strings.Contains(excerpt, want) {
			t.Errorf("excerpt lost %q:\n%s", want, excerpt)
		}
	}
	// An unreached body is what we are here to drop — its signature stays, so the
	// judge can see the function exists and was elided.
	if strings.Contains(excerpt, "smtplib.SMTP") || strings.Contains(excerpt, "body.replace") {
		t.Errorf("excerpt kept an unreached body:\n%s", excerpt)
	}
	for _, want := range []string{"def send_mail(", "def render_template("} {
		if !strings.Contains(excerpt, want) {
			t.Errorf("excerpt dropped the signature %q:\n%s", want, excerpt)
		}
	}
	if len(excerpt) >= len(pyHelper) {
		t.Errorf("excerpt (%d B) did not shrink the file (%d B)", len(excerpt), len(pyHelper))
	}
}

func TestSliceFollowsCallsWithinTheFile(t *testing.T) {
	// _resolve is never named in the diff — only safe_fetch is. Its body still has
	// to travel: it is one call away from the code being judged, and a guard or a
	// sink hiding there is exactly the blind spot imported context exists to close.
	excerpt, _, ok := sliceFile("netutil.py", pyHelper, map[string]bool{"safe_fetch": true}, limits.MaxContextFileBytes, true)
	if !ok {
		t.Fatal("expected the helper to slice")
	}
	if !strings.Contains(excerpt, "socket.gethostbyname") {
		t.Errorf("dropped a transitively reached body:\n%s", excerpt)
	}
}

func TestSliceKeepsModuleLevelCodeWhateverIsReached(t *testing.T) {
	// Imports and module constants are judged alongside the function (an allowlist
	// defined at module level IS the guard), and they are never a "span", so they
	// must survive by construction.
	excerpt, _, ok := sliceFile("netutil.py", pyHelper, map[string]bool{"send_mail": true}, limits.MaxContextFileBytes, true)
	if !ok {
		t.Fatal("expected the helper to slice")
	}
	for _, want := range []string{"import requests", `ALLOWED_HOSTS = ["api.internal", "cdn.internal"]`, "TIMEOUT = 5"} {
		if !strings.Contains(excerpt, want) {
			t.Errorf("excerpt lost module-level %q:\n%s", want, excerpt)
		}
	}
}

func TestSliceFallsBackToTheWholeFileWhenNothingIsReached(t *testing.T) {
	// The import gate already decided this file is referenced. If the slicer cannot
	// see HOW, the answer is to send everything: guessing "nothing is reachable"
	// would turn a parser gap into a missing sink and a clean verdict.
	if _, _, ok := sliceFile("netutil.py", pyHelper, map[string]bool{"netutil": true}, limits.MaxContextFileBytes, true); ok {
		t.Error("expected a fall back to the whole file when no span matched")
	}
}

func TestSliceFallsBackOnAFileItCannotParse(t *testing.T) {
	cases := map[string]string{
		"unknown language": "helper.rb",
		"no functions":     "config.py",
	}
	bodies := map[string]string{
		"helper.rb": "def safe_fetch(u)\n  Net::HTTP.get(u)\nend\n",
		"config.py": "TIMEOUT = 5\nALLOWED = ['a', 'b']\n",
	}
	for name, path := range cases {
		if _, _, ok := sliceFile(path, bodies[path], map[string]bool{"safe_fetch": true}, limits.MaxContextFileBytes, true); ok {
			t.Errorf("%s: expected a fall back to the whole file", name)
		}
	}
}

func TestSliceLeavesASmallFileAlone(t *testing.T) {
	// Below the saving threshold the gaps cost the judge more than the bytes buy.
	small := "def a():\n    return 1\n\ndef b():\n    return 2\n    # a couple of lines, but only a couple\n"
	if _, _, ok := sliceFile("small.py", small, map[string]bool{"a": true}, limits.MaxContextFileBytes, true); ok {
		t.Error("expected no slice when there is nothing worth saving")
	}
}

const goHelper = `package netutil

import (
	"io"
	"net/http"
	"os/exec"
)

// Timeout bounds every outbound call.
var Timeout = 5

func Fetch(url string) (string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b), nil
}

func RunShell(cmd string) error {
	// A brace in a string must not close the span: "}" }
	return exec.Command("sh", "-c", cmd).Run()
}

func Archive(dir string) error {
	/* a brace in a block comment: { */
	return exec.Command("tar", "-czf", dir+".tgz", dir).Run()
}
`

func TestSliceGoKeepsOnlyTheCalledFunction(t *testing.T) {
	excerpt, nums, ok := sliceFile("netutil/net.go", goHelper, map[string]bool{"netutil": true, "Fetch": true}, limits.MaxContextFileBytes, true)
	if !ok {
		t.Fatal("expected the helper to slice")
	}
	checkLines(t, goHelper, excerpt, nums)
	if !strings.Contains(excerpt, "http.Get(url)") {
		t.Errorf("dropped the reached body:\n%s", excerpt)
	}
	if strings.Contains(excerpt, `exec.Command("sh"`) || strings.Contains(excerpt, `"tar"`) {
		t.Errorf("kept an unreached body:\n%s", excerpt)
	}
	// Braces inside a string and inside a block comment must not be read as span
	// boundaries — that would slice the file at the wrong line and drop real code.
	if !strings.Contains(excerpt, "func RunShell(cmd string) error {") || !strings.Contains(excerpt, "func Archive(dir string) error {") {
		t.Errorf("lost a signature, so a brace in a literal moved a span boundary:\n%s", excerpt)
	}
	if !strings.Contains(excerpt, "var Timeout = 5") {
		t.Errorf("lost a package-level declaration:\n%s", excerpt)
	}
}

const jsHelper = `import fetch from 'node-fetch';

const ALLOWED = ['api.internal'];

export async function safeFetch(url) {
  const u = new URL(url);
  if (!ALLOWED.includes(u.hostname)) {
    throw new Error('blocked');
  }
  return (await fetch(url)).text();
}

export const renderRow = (row) => {
  const el = document.createElement('div');
  el.innerHTML = row.name;
  return el;
};

export class Mailer {
  constructor(host) {
    this.host = host;
  }

  send(to, body) {
    return fetch(this.host, { method: 'POST', body });
  }
}
`

func TestSliceJSKeepsOnlyTheCalledExport(t *testing.T) {
	excerpt, nums, ok := sliceFile("lib/net.ts", jsHelper, map[string]bool{"safeFetch": true}, limits.MaxContextFileBytes, true)
	if !ok {
		t.Fatal("expected the helper to slice")
	}
	checkLines(t, jsHelper, excerpt, nums)
	if !strings.Contains(excerpt, "ALLOWED.includes(u.hostname)") {
		t.Errorf("dropped the reached body:\n%s", excerpt)
	}
	if strings.Contains(excerpt, "innerHTML") {
		t.Errorf("kept an unreached arrow body:\n%s", excerpt)
	}
	// The class declaration is not a function, so it survives whatever is reached;
	// its unreached method body does not.
	if !strings.Contains(excerpt, "export class Mailer {") {
		t.Errorf("lost the class declaration:\n%s", excerpt)
	}
	if strings.Contains(excerpt, "method: 'POST'") {
		t.Errorf("kept an unreached method body:\n%s", excerpt)
	}
}

const javaHelper = `package com.example;

import java.sql.Connection;
import java.sql.Statement;

public class UserDao {
    private final Connection conn;

    public UserDao(Connection conn) {
        this.conn = conn;
    }

    public String findByName(String name) throws Exception {
        Statement st = conn.createStatement();
        return st.executeQuery("SELECT * FROM users WHERE name = '" + name + "'").toString();
    }

    public void deleteAll() throws Exception {
        conn.createStatement().execute("DELETE FROM users");
        conn.createStatement().execute("DELETE FROM sessions");
        conn.createStatement().execute("DELETE FROM audit_log");
    }

    public void export(String path) throws Exception {
        Statement st = conn.createStatement();
        java.io.Writer out = new java.io.FileWriter(path);
        out.write(st.executeQuery("SELECT * FROM users").toString());
        out.write(st.executeQuery("SELECT * FROM sessions").toString());
        out.write(st.executeQuery("SELECT * FROM audit_log").toString());
        out.close();
    }
}
`

func TestSliceJavaKeepsOnlyTheCalledMethod(t *testing.T) {
	excerpt, nums, ok := sliceFile("src/UserDao.java", javaHelper, map[string]bool{"UserDao": true, "findByName": true}, limits.MaxContextFileBytes, true)
	if !ok {
		t.Fatal("expected the helper to slice")
	}
	checkLines(t, javaHelper, excerpt, nums)
	if !strings.Contains(excerpt, "SELECT * FROM users") {
		t.Errorf("dropped the reached body:\n%s", excerpt)
	}
	if strings.Contains(excerpt, "DELETE FROM users") {
		t.Errorf("kept an unreached body:\n%s", excerpt)
	}
	if !strings.Contains(excerpt, "private final Connection conn;") {
		t.Errorf("lost a field declaration:\n%s", excerpt)
	}
}

// Resolve-level: the slice must be gated on the WHOLE turn's identifiers, not on
// the one changed file that resolved the helper first. `seen` resolves a helper
// once, so gating per-file would drop the body the second file calls.
func TestResolveSlicesAgainstEveryChangedFile(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"a.py":       "from netutil import safe_fetch\n",
		"b.py":       "from netutil import send_mail\n",
		"netutil.py": pyHelper,
	})
	got := Resolve(root, []transcript.Change{
		{FilePath: "a.py", AddedText: "from netutil import safe_fetch\nsafe_fetch(u)\n", FullContent: "from netutil import safe_fetch\n"},
		{FilePath: "b.py", AddedText: "from netutil import send_mail\nsend_mail(a, b, c)\n", FullContent: "from netutil import send_mail\n"},
	})
	if len(got) != 1 {
		t.Fatalf("expected one context file, got %d", len(got))
	}
	if !strings.Contains(got[0].Content, "requests.get(url") {
		t.Errorf("dropped the body the first changed file calls:\n%s", got[0].Content)
	}
	if !strings.Contains(got[0].Content, "smtplib.SMTP") {
		t.Errorf("dropped the body the second changed file calls:\n%s", got[0].Content)
	}
}

func TestResolveSendsLineNumbersOnlyForASlicedFile(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"app.py":     "from netutil import safe_fetch\n",
		"netutil.py": pyHelper,
		"tiny.py":    "def one():\n    return 1\n",
	})
	got := Resolve(root, []transcript.Change{{
		FilePath:    "app.py",
		AddedText:   "from netutil import safe_fetch\nfrom tiny import one\nsafe_fetch(u)\none()\n",
		FullContent: "from netutil import safe_fetch\nfrom tiny import one\n",
	}})
	if len(got) != 2 {
		t.Fatalf("expected two context files, got %d", len(got))
	}
	for _, cf := range got {
		switch cf.Path {
		case "netutil.py":
			if len(cf.Lines) == 0 {
				t.Error("a sliced file must carry its real line numbers")
			}
			checkLines(t, pyHelper, cf.Content, cf.Lines)
		case "tiny.py":
			if len(cf.Lines) != 0 {
				t.Error("a whole file must carry no line numbers (it starts at line 1)")
			}
		}
	}
}

// bigModule builds a helper too large for a per-file cap, with the function the
// change calls at the END — the shape of a real dashboard/UI module, where the
// entry point and the export block sit after thousands of lines of components.
func bigModule(fillers int) string { return bigModuleN(fillers, 3) }

func bigModuleN(fillers, entryLines int) string {
	var b strings.Builder
	b.WriteString("import { db } from './db';\n\nexport const ALLOWED = ['api.internal'];\n\n")
	for i := 0; i < fillers; i++ {
		fmt.Fprintf(&b, "/**\n * Widget%d renders a row.\n * A long maintainer note that costs bytes and answers nothing about the change.\n */\nfunction Widget%d(props) {\n", i, i)
		for j := 0; j < 20; j++ {
			fmt.Fprintf(&b, "  const v%d = props.values[%d] + '%s';\n", j, j, strings.Repeat("x", 60))
		}
		b.WriteString("  return v0;\n}\n\n")
	}
	b.WriteString("/** entry point. */\nfunction renderApp(cfg) {\n  const url = cfg.target;\n")
	for j := 0; j < entryLines; j++ {
		fmt.Fprintf(&b, "  const pad%d = '%s';\n", j, strings.Repeat("y", 60))
	}
	b.WriteString("  return db.query('SELECT * FROM t WHERE u = ' + url);\n}\n\nexport { renderApp };\n")
	return b.String()
}

// A helper too big for the cap must spend that budget on what the change can REACH,
// not on whatever the file happens to start with. Before this, an over-cap helper
// fell back to the whole file, which means its first maxBytes: on the real 614 KB
// dashboard module that was lines 1-1854 of 9,925, holding neither the component
// the change imported nor the export block naming it. The excerpt is reach-ordered
// instead, so the called function is in it and so is every signature.
func TestOverCapHelperSpendsItsBudgetOnWhatTheChangeReaches(t *testing.T) {
	src := bigModule(60)
	cap := len(src) / 3
	if strings.Contains(src[:cap], "function renderApp(") {
		t.Fatal("fixture is not representative: the called function must sit past the cap")
	}
	excerpt, nums, ok := sliceFile("lib/ui.js", src, map[string]bool{"renderApp": true}, cap, true)
	if !ok {
		t.Fatal("expected an over-cap helper to slice rather than fall back to its first bytes")
	}
	checkLines(t, src, excerpt, nums)
	if len(excerpt) > cap {
		t.Fatalf("excerpt %d B exceeds the cap %d B", len(excerpt), cap)
	}
	for _, want := range []string{"function renderApp(cfg) {", "db.query('SELECT * FROM t WHERE u = ' + url)", "export { renderApp }", "export const ALLOWED"} {
		if !strings.Contains(excerpt, want) {
			t.Errorf("excerpt lost %q — the reason the file was resolved at all", want)
		}
	}
	// Structure survives across the WHOLE file: every signature travels, so the judge
	// can see what was elided rather than being handed a file that appears to end.
	if !strings.Contains(excerpt, "function Widget59(props) {") {
		t.Error("excerpt dropped a signature, so the file reads as shorter than it is")
	}
}

// A doc comment describes the code it sits above, so it shares that code's fate.
// This is the larger half on a documented codebase: the real dashboard module is
// 614 KB, of which 192 KB is comment blocks ABOVE functions rather than inside them,
// and keeping every one to accompany an elided body pays for prose about code the
// change cannot call.
func TestDocCommentTravelsWithItsBody(t *testing.T) {
	src := bigModule(20)
	excerpt, _, ok := sliceFile("lib/ui.js", src, map[string]bool{"renderApp": true}, 1<<20, true)
	if !ok {
		t.Fatal("expected the helper to slice")
	}
	if strings.Contains(excerpt, "A long maintainer note") {
		t.Errorf("kept the doc of an unreachable function:\n%s", excerpt[:400])
	}
	if !strings.Contains(excerpt, "/** entry point. */") {
		t.Error("dropped the doc of the function the change calls")
	}
	if !strings.Contains(excerpt, "function Widget3(props) {") {
		t.Error("dropped a signature along with its doc — the signature always travels")
	}
}

// `#` opens a comment in Python and a PRIVATE CLASS FIELD in JS/TS. Reading the
// latter as a doc would elide a class's private state along with the next method's
// body, which is state a guard may depend on.
func TestPrivateFieldIsNotReadAsADocComment(t *testing.T) {
	src := `class Vault {
  #secretKey = process.env.VAULT_KEY;
  unlock(token) {
    return token === this.#secretKey;
  }

  audit(evt) {
    console.log(evt);
    console.log(evt);
    console.log(evt);
    console.log(evt);
    console.log(evt);
    console.log(evt);
    console.log(evt);
    console.log(evt);
  }
}
`
	excerpt, _, ok := sliceFile("lib/vault.ts", src, map[string]bool{"unlock": true}, 1<<20, true)
	if !ok {
		t.Skip("nothing to slice in this fixture")
	}
	if !strings.Contains(excerpt, "#secretKey = process.env.VAULT_KEY;") {
		t.Errorf("elided a private field as if it were a comment:\n%s", excerpt)
	}
}

// The last resort, and the case that made this worth building. When the file's
// module-level content plus the called function's own body still overflow the cap,
// the excerpt gives up the body too — and that is STILL the better rendering than
// falling back to the file's first maxBytes, because it carries the module-level
// code and every signature from across the whole file rather than a prefix of it.
// The real 614 KB dashboard module lands exactly here.
func TestOverCapFallsBackToStructureNotToAPrefix(t *testing.T) {
	src := bigModuleN(40, 400) // a large entry point

	// Size the cap from the excerpt itself: just under what the called function's own
	// body needs, so the last resort is the only way to fit. Deriving it beats
	// guessing a constant, which is how the sibling test above ended up never
	// reaching this path.
	withBody, _, ok := sliceFile("lib/ui.js", src, map[string]bool{"renderApp": true}, 1<<20, true)
	if !ok {
		t.Fatal("expected the helper to slice at an unlimited cap")
	}
	cap := len(withBody) - 5000
	excerpt, nums, ok := sliceFile("lib/ui.js", src, map[string]bool{"renderApp": true}, cap, true)
	if !ok {
		t.Fatal("expected an excerpt rather than a fall back to the file's first bytes")
	}
	checkLines(t, src, excerpt, nums)
	if len(excerpt) > cap {
		t.Fatalf("excerpt %d B exceeds the cap %d B", len(excerpt), cap)
	}
	if strings.Contains(excerpt, "return db.query(") {
		t.Fatal("fixture did not force the last resort: the entry body still fits")
	}
	// What a first-bytes fall back cannot give you, and what makes the excerpt the
	// better rendering: the structure of everything AFTER the cap.
	for _, want := range []string{"function renderApp(cfg) {", "export { renderApp }", "function Widget39(props) {", "export const ALLOWED"} {
		if !strings.Contains(excerpt, want) {
			t.Errorf("excerpt lost %q, which is what a first-bytes fall back also loses", want)
		}
	}
}

// The whole-file fallback on "nothing looks reachable" is a benefit of the doubt,
// and it is owed only to a NAMED pull. A named import says a symbol defined in this
// file was written in the added code, so failing to find it means the slicer is
// wrong and the file should travel whole. A Go package import, a Python
// `import pkg.mod` and a JS `export * from` say no such thing — they pull files
// nothing ever claimed a symbol in — so those travel as their skeleton.
//
// Measured on this repo, three quarters of the whole-file fallback was the unnamed
// kind: 188 KB of Go package siblings and 173 KB of re-export targets, all sent
// whole on the strength of a claim no import had made.
func TestOnlyANamedPullEarnsTheWholeFileFallback(t *testing.T) {
	// A package sibling: nothing in it is named by the change.
	refs := map[string]bool{"netutil": true}

	if _, _, ok := sliceFile("netutil/net.go", goHelper, refs, 1<<20, true); ok {
		t.Error("a NAMED pull with no reachable span must fall back to the whole file")
	}
	excerpt, nums, ok := sliceFile("netutil/net.go", goHelper, refs, 1<<20, false)
	if !ok {
		t.Fatal("an UNNAMED pull with no reachable span must still slice to a skeleton")
	}
	checkLines(t, goHelper, excerpt, nums)
	// A skeleton is every signature and all package-level code: enough to see what
	// the file provides, without the bodies nothing in the change can call.
	for _, want := range []string{"func Fetch(url string) (string, error) {", "func RunShell(cmd string) error {", "var Timeout = 5", "package netutil"} {
		if !strings.Contains(excerpt, want) {
			t.Errorf("skeleton lost %q:\n%s", want, excerpt)
		}
	}
	for _, gone := range []string{"http.Get(url)", `exec.Command("sh"`} {
		if strings.Contains(excerpt, gone) {
			t.Errorf("skeleton kept the body %q:\n%s", gone, excerpt)
		}
	}
}

// Resolve-level: the reason is merged across changed files BEFORE any file is read.
// A helper pulled by name from one changed file and by its package from another is
// a named pull; reading it at first sight would take whichever reason arrived first,
// which would make the fallback depend on the order git happened to list the diff.
func TestResolveTreatsAFileNamedByAnyChangedFileAsNamed(t *testing.T) {
	// Python is the one language where the SAME file arrives by both routes:
	// `import netutil` names a module, `from netutil import TIMEOUT` names a symbol
	// in it. The unnamed changed file is listed FIRST on purpose.
	//
	// The named symbol here is a module CONSTANT, so no function span is reachable
	// and the pull reason is what decides the outcome — which is the only situation
	// in which it is consulted at all.
	root := writeRepo(t, map[string]string{
		"a.py":       "import netutil\n",
		"b.py":       "from netutil import TIMEOUT\n",
		"netutil.py": pyHelper,
	})
	got := Resolve(root, []transcript.Change{
		{FilePath: "a.py", AddedText: "import netutil\nnetutil.reset()\n", FullContent: "import netutil\n"},
		{FilePath: "b.py", AddedText: "from netutil import TIMEOUT\nwait = TIMEOUT\n", FullContent: "from netutil import TIMEOUT\n"},
	})
	if len(got) != 1 {
		t.Fatalf("expected the helper resolved once, got %d", len(got))
	}
	if !strings.Contains(got[0].Content, "requests.get(url") {
		t.Errorf("skeletonised a file a changed file names by symbol: the pull reason was taken from whichever import came first rather than merged across the turn:\n%s", got[0].Content)
	}
}
