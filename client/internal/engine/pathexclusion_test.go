package engine

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/agent/claude"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/agent/copilot"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/outcome"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/policycheck"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/vcs"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

type pathPolicyReviewer struct {
	*fakeReviewer
	answers map[string]policycheck.Answer
	err     error
}

func (p *pathPolicyReviewer) PolicyCheck(repo string) (policycheck.Answer, error) {
	return p.answers[repo], p.err
}

func seedRepoWith(t *testing.T,
	dir string,
	origin string,
	files ...string) {
	t.Helper()
	for _, f := range files {
		p := filepath.Join(dir, filepath.FromSlash(f))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("import os\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	seedRepo(t, dir)
	addOrigin(t, dir, origin)
}

func changedPaths(changes []transcript.Change) []string {
	var out []string
	for _, c := range changes {
		out = append(out, c.FilePath)
	}
	sort.Strings(out)
	return out
}

func workspaceTurn(t *testing.T,
	session string,
	writes ...string) string {
	t.Helper()
	ws := t.TempDir()
	seedRepoWith(t, filepath.Join(ws, "project-a"), "git@github.com:acme/project-a.git", "prototypes/demo.py")
	seedRepoWith(t, filepath.Join(ws, "project-b"), "git@github.com:acme/project-b.git", "prototypes/demo.py")
	if err := vcs.CaptureBaseline(ws, session); err != nil {
		t.Fatal(err)
	}
	for _, w := range writes {
		p := filepath.Join(ws, filepath.FromSlash(w))
		preTool(t, ws, p, session)
		touch(t, p, "x = requests.get(url)\n")
	}
	return ws
}

func TestExcludedPathIsNotSentAndIsRecorded(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	// Arrange
	session := uniqueSession(t, "engine-excluded-path")
	ws := workspaceTurn(t, session, "project-a/app.py", "project-a/prototypes/demo.py", "project-b/prototypes/demo.py")
	r := &pathPolicyReviewer{fakeReviewer: &fakeReviewer{}, answers: map[string]policycheck.Answer{
		"github.com/acme/project-a": {ExcludedPaths: []string{"prototypes/**"}},
		"github.com/acme/project-b": {ExcludedPaths: []string{"docs/**"}},
	}}

	// Act
	code, _, _ := runWith(copilot.New(), r, copilotStop(ws, session))

	// Assert
	if code != 0 || !r.called {
		t.Fatalf("the rest of the turn is still reviewed: code=%d called=%v", code, r.called)
	}
	got := changedPaths(r.gotChanges)
	if want := []string{"project-a/app.py", "project-b/prototypes/demo.py"}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("each repository is judged against its own list: got %v want %v", got, want)
	}
	for _, c := range r.gotChanges {
		if c.FilePath == "project-a/app.py" && (len(c.ExcludedPaths) != 1 || c.ExcludedPaths[0] != "prototypes/**") {
			t.Errorf("a sent change carries its repository's list for the context resolver: %+v", c.ExcludedPaths)
		}
	}
	d := r.gotMeta.FileDecisions
	if d == nil || d.Counts["relevance:excluded_path"] != 1 {
		t.Fatalf("the dropped file is recorded: %+v", d)
	}
	found := false
	for _, f := range d.Files {
		if f.Stage == "relevance" && f.Reason == "excluded_path" && f.Path == "project-a/prototypes/demo.py" {
			found = true
		}
	}
	if !found {
		t.Errorf("the decision names the dropped file: %+v", d.Files)
	}
	if wire.ValidFileDecisions(d) == nil {
		t.Error("the decisions stay valid on the wire")
	}
}

func TestEveryChangeOnAnExcludedPathSendsNoReview(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	// Arrange
	session := uniqueSession(t, "engine-excluded-all")
	ws := workspaceTurn(t, session, "project-a/prototypes/demo.py")
	r := &pathPolicyReviewer{fakeReviewer: &fakeReviewer{prompt: "FIX"}, answers: map[string]policycheck.Answer{
		"github.com/acme/project-a": {ExcludedPaths: []string{"prototypes/"}},
	}}

	// Act
	code, stdout, _ := runWith(copilot.New(), r, copilotStop(ws, session))

	// Assert
	if code != 0 || r.called || stdout != "" {
		t.Fatalf("nothing is sent and the stop proceeds silently: code=%d called=%v out=%q", code, r.called, stdout)
	}
	if r.telemetryCalls != 1 || r.telemetryReason != wire.TelemetryInert || r.telemetryChanged != 1 {
		t.Fatalf("reported as a turn with nothing reviewable: calls=%d reason=%q changed=%d", r.telemetryCalls, r.telemetryReason, r.telemetryChanged)
	}
	if d := r.telemetryMeta.FileDecisions; d == nil || d.Counts["relevance:excluded_path"] != 1 {
		t.Errorf("the telemetry carries the decision: %+v", d)
	}
}

func TestFailedPolicyCheckReviewsEveryPath(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	// Arrange
	session := uniqueSession(t, "engine-excluded-failopen")
	ws := workspaceTurn(t, session, "project-a/app.py", "project-a/prototypes/demo.py")
	r := &pathPolicyReviewer{fakeReviewer: &fakeReviewer{}, err: errors.New("dial tcp: refused")}

	// Act
	runWith(copilot.New(), r, copilotStop(ws, session))

	// Assert
	got := changedPaths(r.gotChanges)
	if want := []string{"project-a/app.py", "project-a/prototypes/demo.py"}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("a failed check has no path list, so everything is reviewed: got %v", got)
	}
}

func TestOutcomeNeverSendsAnExcludedPath(t *testing.T) {
	// Arrange
	session := uniqueSession(t, "engine-excluded-outcome")
	t.Cleanup(func() { outcome.Clear(session) })
	cwd := t.TempDir()
	x := filepath.Join(cwd, "x.py")
	p := filepath.Join(cwd, "proto", "p.py")
	q := filepath.Join(cwd, "proto", "q.py")
	for f, body := range map[string]string{x: "import requests\nresp = safe_get(url)\n", p: "import os\nos.system(cmd)\n", q: "import os\nos.system(other)\n"} {
		if err := os.MkdirAll(filepath.Dir(f), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	tp := filepath.Join(t.TempDir(), "transcript.jsonl")
	appendTranscript(t, tp,
		`{"type":"user","message":{"role":"user","content":"add a fetch helper"}}`,
		toolUse("Write", fmt.Sprintf(`{"file_path":%q,"content":"import requests\nresp = requests.get(url)"}`, x)),
		toolUse("Write", fmt.Sprintf(`{"file_path":%q,"content":"import os\nos.system(cmd)"}`, p)),
	)
	r := &pathPolicyReviewer{
		fakeReviewer: &fakeReviewer{
			prompt:         "FIX THIS",
			pending:        &outcome.Pending{ReviewID: "rid-x", Findings: []wire.Finding{{Rule: "ssrf", Location: "x.py:2"}}},
			snapshotBefore: true,
		},
		answers: map[string]policycheck.Answer{"": {ExcludedPaths: []string{"proto/**"}}},
	}
	first := fmt.Sprintf(`{"stop_hook_active":false,"session_id":%q,"transcript_path":%q,"cwd":%q}`, session, tp, cwd)
	if _, stdout, _ := runWith(claude.New(), r, first); stdout == "" {
		t.Fatal("the first Stop must block")
	}
	firstSent := changedPaths(r.gotChanges)
	appendTranscript(t, tp,
		`{"type":"user","message":{"role":"user","content":"Stop hook feedback:\nLeoPrevent: security review"}}`,
		toolUse("Edit", fmt.Sprintf(`{"file_path":%q,"old_string":"resp = requests.get(url)","new_string":"resp = safe_get(url)"}`, x)),
		toolUse("Write", fmt.Sprintf(`{"file_path":%q,"content":"import os\nos.system(other)"}`, q)),
	)
	r.prompt, r.pending, r.gotChanges = "", nil, nil
	second := fmt.Sprintf(`{"stop_hook_active":true,"session_id":%q,"transcript_path":%q,"cwd":%q,"last_assistant_message":"Fixed."}`, session, tp, cwd)

	// Act
	runWith(claude.New(), r, second)

	// Assert
	if fmt.Sprint(firstSent) != "[x.py]" {
		t.Fatalf("the first Stop sends only the file outside the excluded path: %v", firstSent)
	}
	if !r.shipped {
		t.Fatal("the outcome is still shipped")
	}
	for _, c := range append(append([]transcript.Change(nil), r.shippedAfter...), r.gotChanges...) {
		if filepath.ToSlash(filepath.Dir(c.FilePath)) == "proto" {
			t.Fatalf("an excluded file reached the outcome or the fix-turn review: %s", c.FilePath)
		}
	}
	if fmt.Sprint(changedPaths(r.shippedAfter)) != "[x.py]" {
		t.Errorf("the outcome carries the flagged file: %v", changedPaths(r.shippedAfter))
	}
}

func TestDependencyScanNeverListsAnExcludedPath(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	// Arrange
	root := filepath.Join(t.TempDir(), "project-a")
	seedRepoWith(t, root, "git@github.com:acme/project-a.git", "package.json", "prototypes/package.json")
	x := pathExclusions{"github.com/acme/project-a": {"prototypes/**"}}

	// Act
	files, err := x.lister().Files(root)

	// Assert
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(files)
	if fmt.Sprint(files) != "[app.py package.json]" {
		t.Fatalf("the excluded dependency file is never listed: %v", files)
	}
}

func TestFallbackPathsAreJudgedFromTheRepositoryRoot(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	// Arrange
	root := filepath.Join(t.TempDir(), "project-a")
	seedRepoWith(t, root, "git@github.com:acme/project-a.git", "web/prototypes/demo.py", "web/app.py")
	cwd := filepath.Join(root, "web")
	x := pathExclusions{"github.com/acme/project-a": {"web/prototypes/**"}}
	changes := []transcript.Change{{FilePath: "prototypes/demo.py"}, {FilePath: "app.py"}}

	// Act
	kept, dropped := x.split(cwd, false, changes)

	// Assert
	if fmt.Sprint(changedPaths(kept)) != "[app.py]" || fmt.Sprint(changedPaths(dropped)) != "[prototypes/demo.py]" {
		t.Fatalf("a cwd-relative fallback path is matched from the repository root: kept=%v dropped=%v", changedPaths(kept), changedPaths(dropped))
	}
}
