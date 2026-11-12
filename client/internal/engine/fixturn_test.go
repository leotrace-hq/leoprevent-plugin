package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/agent/claude"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/outcome"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/scratch"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/vcs"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

func appendTranscript(t *testing.T, path string, lines ...string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(strings.Join(lines, "\n") + "\n"); err != nil {
		t.Fatal(err)
	}
}

func changeFor(changes []transcript.Change, path string) (transcript.Change, bool) {
	for _, c := range changes {
		if c.FilePath == path {
			return c, true
		}
	}
	return transcript.Change{}, false
}

func toolUse(name, input string) string {
	return fmt.Sprintf(`{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","name":%q,"input":%s}]}}`, name, input)
}

func blockThenRewake(t *testing.T, session string) (*fakeReviewer, string, string, string) {
	t.Helper()
	t.Cleanup(func() {
		outcome.Clear(session)
		_ = outcome.SaveLedger(session, nil)
	})
	cwd := t.TempDir()
	x := filepath.Join(cwd, "x.py")
	y := filepath.Join(cwd, "y.py")
	tp := filepath.Join(t.TempDir(), "transcript.jsonl")
	appendTranscript(t, tp,
		`{"type":"user","message":{"role":"user","content":"add a fetch helper"}}`,
		toolUse("Write", fmt.Sprintf(`{"file_path":%q,"content":"import requests\nresp = requests.get(url)"}`, x)),
	)
	r := &fakeReviewer{
		prompt:         "FIX THIS",
		pending:        &outcome.Pending{ReviewID: "rid-1", Findings: []wire.Finding{{Rule: "ssrf", Location: x + ":2"}}},
		snapshotBefore: true,
	}
	stdin := fmt.Sprintf(`{"stop_hook_active":false,"session_id":%q,"transcript_path":%q,"cwd":%q}`, session, tp, cwd)
	if _, stdout, _ := runWith(claude.New(), r, stdin); stdout == "" {
		t.Fatal("turn A must block")
	}
	appendTranscript(t, tp,
		`{"type":"user","message":{"role":"user","content":"Stop hook feedback:\nLeoPrevent: security review"}}`,
		toolUse("Edit", fmt.Sprintf(`{"file_path":%q,"old_string":"resp = requests.get(url)","new_string":"resp = safe_get(url)"}`, x)),
		toolUse("Write", fmt.Sprintf(`{"file_path":%q,"content":"import os\nos.system(cmd)"}`, y)),
	)
	r.prompt, r.pending = "", nil
	return r, fmt.Sprintf(`{"stop_hook_active":true,"session_id":%q,"transcript_path":%q,"cwd":%q,"last_assistant_message":"Fixed, and added y."}`, session, tp, cwd), x, y
}

func TestFixTurnReviewsCodeWrittenAfterRewakeOnTranscriptFallback(t *testing.T) {
	// Arrange
	r, stdin, x, y := blockThenRewake(t, "engine-fixturn-fallback")
	r.findings = []wire.Finding{{Rule: "command-injection", Location: y + ":2", Issue: "Shell command built from input."}}

	// Act
	code, stdout, _ := runWith(claude.New(), r, stdin)

	// Assert
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !r.shipped || r.shippedPending.ReviewID != "rid-1" {
		t.Fatalf("the prior finding must still be re-verified, shipped=%v", r.shipped)
	}
	if r.reviewCalls != 2 {
		t.Fatalf("code written after the re-wake was never reviewed: %d review calls", r.reviewCalls)
	}
	gotY, ok := changeFor(r.gotChanges, filepath.Base(y))
	if !ok || !strings.Contains(gotY.AddedText, "os.system(cmd)") {
		t.Errorf("the new file must be reviewed whole, got %+v", r.gotChanges)
	}
	gotX, ok := changeFor(r.gotChanges, filepath.Base(x))
	if !ok || !strings.Contains(gotX.AddedText, "safe_get") || strings.Contains(gotX.AddedText, "import requests") {
		t.Errorf("the edited file must carry only what changed since the review, got %q", gotX.AddedText)
	}
	if r.gotMeta.RewakeOf != "rid-1" || r.gotMeta.Prompt != "" || r.gotMeta.InputTokens != 0 || r.gotMeta.DurationMs != 0 {
		t.Errorf("fix-turn meta must name its parent and carry no turn cost, got %+v", r.gotMeta)
	}
	var notice map[string]any
	if err := json.Unmarshal([]byte(stdout), &notice); err != nil {
		t.Fatalf("notice must be one JSON object, got %q", stdout)
	}
	if _, blocks := notice["decision"]; blocks {
		t.Errorf("fix-turn findings must never block again: %s", stdout)
	}
	if !strings.Contains(stdout, "code written after the review") || !strings.Contains(stdout, "command-injection") {
		t.Errorf("expected the fix-turn notice, got %s", stdout)
	}
}

func TestFixTurnDropsFindingsOutcomeAlreadyOwns(t *testing.T) {
	// Arrange
	r, stdin, x, _ := blockThenRewake(t, "engine-fixturn-dedupe")
	r.findings = []wire.Finding{{Rule: "ssrf", Location: x + ":7"}}

	// Act
	_, stdout, _ := runWith(claude.New(), r, stdin)

	// Assert
	if r.reviewCalls != 2 {
		t.Fatalf("expected the fix-turn review to run, got %d calls", r.reviewCalls)
	}
	if stdout != "" {
		t.Errorf("a re-fire of the flagged finding belongs to /outcome, got %s", stdout)
	}
}

func TestFixTurnNoticeJoinsStillVulnerable(t *testing.T) {
	// Arrange
	r, stdin, x, y := blockThenRewake(t, "engine-fixturn-joined")
	r.outcomeStillFiring = []wire.Finding{{Rule: "ssrf", Location: x + ":2"}}
	r.findings = []wire.Finding{{Rule: "command-injection", Location: y + ":2"}}

	// Act
	_, stdout, _ := runWith(claude.New(), r, stdin)

	// Assert
	var notice map[string]any
	if err := json.Unmarshal([]byte(stdout), &notice); err != nil {
		t.Fatalf("both notices must share one JSON object, got %q", stdout)
	}
	if !strings.Contains(stdout, "still vulnerable") || !strings.Contains(stdout, "code written after the review") {
		t.Errorf("expected both notices, got %s", stdout)
	}
}

func TestFixTurnSkippedWithoutSnapshot(t *testing.T) {
	// Arrange
	session := "engine-fixturn-nosnapshot"
	t.Cleanup(func() { outcome.Clear(session) })
	if err := outcome.Remember(session, outcome.Pending{ReviewID: "rid-1", Findings: []wire.Finding{{Rule: "ssrf"}}}); err != nil {
		t.Fatal(err)
	}
	r := &fakeReviewer{}

	// Act
	runWith(claude.New(), r, fmt.Sprintf(`{"stop_hook_active":true,"session_id":%q,"transcript_path":"/nonexistent/x.jsonl"}`, session))

	// Assert
	if r.called {
		t.Error("a pending with no snapshot must not trigger a fix-turn review")
	}
	if !r.shipped {
		t.Error("the outcome must still ship")
	}
}

func TestFixTurnGitPathNarrowsAddedLines(t *testing.T) {
	// Arrange
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	gitCmd := func(args ...string) {
		c := exec.Command("git", append([]string{"-C", dir}, args...)...)
		c.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	gitCmd("init", "-q")
	write("app.py", "import os\n")
	gitCmd("add", "-A")
	gitCmd("commit", "-q", "-m", "init")
	session := "engine-fixturn-git"
	t.Cleanup(func() {
		outcome.Clear(session)
		_ = os.Remove(filepath.Join(scratch.Dir("baselines"), session))
	})
	if err := vcs.CaptureBaseline(dir, session); err != nil {
		t.Fatal(err)
	}
	write("app.py", "import os\nresp = requests.get(url)\nprint(resp)\n")
	r := &fakeReviewer{
		prompt:         "FIX THIS",
		pending:        &outcome.Pending{ReviewID: "rid-1", Findings: []wire.Finding{{Rule: "ssrf", Location: "app.py:2"}}},
		snapshotBefore: true,
	}
	first := fmt.Sprintf(`{"stop_hook_active":false,"hook_event_name":"Stop","cwd":%q,"session_id":%q}`, dir, session)
	if _, stdout, _ := runWith(claude.New(), r, first); stdout == "" {
		t.Fatal("turn A must block")
	}
	write("app.py", "import os\nresp = safe_get(url)\nprint(resp)\nos.system(cmd)\n")
	write("new.py", "eval(x)\n")
	r.prompt, r.pending = "", nil
	second := fmt.Sprintf(`{"stop_hook_active":true,"hook_event_name":"Stop","cwd":%q,"session_id":%q}`, dir, session)

	// Act
	runWith(claude.New(), r, second)

	// Assert
	if r.reviewCalls != 2 {
		t.Fatalf("code written after the re-wake was never reviewed: %d review calls", r.reviewCalls)
	}
	app, ok := changeFor(r.gotChanges, "app.py")
	if !ok {
		t.Fatalf("app.py missing from the fix-turn review: %+v", r.gotChanges)
	}
	if !reflect.DeepEqual(app.AddedLines, []int{2, 4}) {
		t.Errorf("only lines written after the review may read as added, got %v", app.AddedLines)
	}
	if app.RemovedText != "resp = requests.get(url)" || !reflect.DeepEqual(app.RemovedAt, []int{2}) {
		t.Errorf("the fix's own removal must be visible, got %q at %v", app.RemovedText, app.RemovedAt)
	}
	if !strings.Contains(app.FullContent, "import os") {
		t.Error("whole-file context must survive the narrowing")
	}
	if _, ok := changeFor(r.gotChanges, "new.py"); !ok {
		t.Errorf("a file first written after the re-wake must be reviewed, got %+v", r.gotChanges)
	}
}

func TestFixTurnChangesDropsUnchangedReviewedFile(t *testing.T) {
	// Arrange
	before := []wire.ChangedFile{{Path: "a.py", AddedText: "x = 1\n", FullContent: "x = 1\n", AddedLines: []int{1}}}
	after := []transcript.Change{
		{FilePath: "a.py", AddedText: "x = 1\n", FullContent: "x = 1\n", AddedLines: []int{1}},
		{FilePath: "m", AddedText: "mcp", Virtual: true},
	}

	// Act
	got := fixTurnChanges(before, after)

	// Assert
	if len(got) != 0 {
		t.Errorf("an unchanged reviewed file and a virtual change must both be dropped, got %+v", got)
	}
}

func TestFixTurnIgnoresLinesRestoredToTurnStart(t *testing.T) {
	// Arrange
	before := []wire.ChangedFile{{Path: "a.py", FullContent: "keep\nnew\n", AddedLines: []int{2}}}
	after := []transcript.Change{{FilePath: "a.py", FullContent: "keep\nold\n", AddedLines: []int{}, RemovedText: "", RemovedAt: nil}}

	// Act
	got := fixTurnChanges(before, after)

	// Assert
	if len(got) != 1 || len(got[0].AddedLines) != 0 || got[0].RemovedText != "new" {
		t.Errorf("a line put back to its turn-start form is not the agent's, got %+v", got)
	}
}

func TestDiffLines(t *testing.T) {
	cases := []struct {
		name      string
		a, b      string
		added     []int
		removed   []string
		removedAt []int
	}{
		{"identical", "a\nb", "a\nb", nil, nil, nil},
		{"append", "a\nb", "a\nb\nc", []int{3}, nil, nil},
		{"prepend", "a\nb", "z\na\nb", []int{1}, nil, nil},
		{"replace middle", "a\nb\nc", "a\nB\nc", []int{2}, []string{"b"}, []int{2}},
		{"delete end", "a\nb\nc", "a", nil, []string{"b", "c"}, []int{2, 2}},
		{"scattered", "a\nb\nc\nd\ne", "a\nX\nc\nd\ne\nY", []int{2, 6}, []string{"b"}, []int{2}},
		{"from empty", "", "a\nb", []int{1, 2}, []string{""}, []int{1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Act
			d, ok := diffLines(splitLines(tc.a), splitLines(tc.b))

			// Assert
			if !ok {
				t.Fatal("diff gave up")
			}
			if !reflect.DeepEqual(d.added, tc.added) || !reflect.DeepEqual(d.removed, tc.removed) || !reflect.DeepEqual(d.removedAt, tc.removedAt) {
				t.Errorf("got added=%v removed=%q at=%v", d.added, d.removed, d.removedAt)
			}
		})
	}
}

func TestDiffLinesGivesUpPastTheEditBound(t *testing.T) {
	// Arrange
	a := make([]string, maxDiffEdits)
	b := make([]string, maxDiffEdits)
	for i := range a {
		a[i] = fmt.Sprintf("a%d", i)
		b[i] = fmt.Sprintf("b%d", i)
	}

	// Act
	_, ok := diffLines(a, b)

	// Assert
	if ok {
		t.Error("a rewrite past the bound must give up, so the caller over-reports")
	}
}

func TestFixTurnNarrowsASlicedBodyInFileLines(t *testing.T) {
	// Arrange
	before := []wire.ChangedFile{{Path: "a.py", FullContent: "a\nb\nc\n", BodyStartLine: 500, AddedLines: []int{501}}}
	after := []transcript.Change{{FilePath: "a.py", FullContent: "a\nB\nc\nd\n", BodyStartLine: 500, AddedLines: []int{501, 503}}}

	// Act
	got := fixTurnChanges(before, after)

	// Assert
	if len(got) != 1 {
		t.Fatalf("got %+v", got)
	}
	if !reflect.DeepEqual(got[0].AddedLines, []int{501, 503}) || got[0].AddedText != "B\nd" {
		t.Errorf("added lines must stay file lines, got %v %q", got[0].AddedLines, got[0].AddedText)
	}
	if got[0].RemovedText != "b" || !reflect.DeepEqual(got[0].RemovedAt, []int{501}) {
		t.Errorf("removal point must be a file line, got %q %v", got[0].RemovedText, got[0].RemovedAt)
	}
}

func TestFixTurnDoesNotDiffSlicesOfDifferentWindows(t *testing.T) {
	// Arrange
	before := []wire.ChangedFile{{Path: "a.py", FullContent: "a\nb\n", BodyStartLine: 10, AddedLines: []int{11}}}
	after := []transcript.Change{{FilePath: "a.py", FullContent: "a\nb\n", BodyStartLine: 40, AddedLines: []int{41}, AddedText: "b"}}

	// Act
	got := fixTurnChanges(before, after)

	// Assert
	if len(got) != 1 || !reflect.DeepEqual(got[0].AddedLines, []int{41}) {
		t.Errorf("two different windows are not comparable row for row, got %+v", got)
	}
}
