package engine

import (
	"io"
	"log/slog"
	"slices"
	"testing"
	"time"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/agent"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/agent/claude"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/agent/codex"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/depquiet"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/scratch"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

func vulnerable(name, version, change string, advs ...wire.DependencyAdvisory) wire.DependencyCheck {
	return wire.DependencyCheck{Name: name, Version: version, DependencyContext: wire.DependencyContext{Change: change},
		Security: &wire.DependencySecurity{NeedsFix: true, Advisories: advs}}
}

// What a scan's answer can quieten is what was already there and needs fixing, with its high and
// critical IDs: never the turn's own changes, never malware, and not again what's already quiet.
func TestTheScanListsWhatAnAnswerCanQuieten(t *testing.T) {
	high := wire.DependencyAdvisory{IDs: []string{"GHSA-h", "CVE-1"}, Severity: "high"}
	med := wire.DependencyAdvisory{IDs: []string{"GHSA-m"}, Severity: "moderate"}
	mal := wire.DependencyAdvisory{IDs: []string{"MAL-1"}, Malicious: true}
	resp := wire.DependenciesResponse{
		Packages: []wire.DependencyCheck{
			vulnerable("axios", "0.21.1", wire.DependencyUnchanged, high, med),
			vulnerable("tar", "6.2.1", "", high),
			vulnerable("added", "1.0.0", wire.DependencyAdded, high),
			vulnerable("evil", "1.0.0", wire.DependencyUnchanged, mal),
			vulnerable("ip", "1.1.8", wire.DependencyUnchanged, high),
			{Name: "clean", Version: "1.0.0", Security: &wire.DependencySecurity{}},
		},
		Quieted: []wire.QuietDependency{{Name: "ip", Version: "1.1.8", Advisories: []string{"CVE-1", "GHSA-h"}}},
	}
	var s scanSeen
	s.add("package-lock.json", resp)
	quieted, listed := s.snapshot()
	var names []string
	for _, e := range listed {
		names = append(names, e.Name)
	}
	if !slices.Equal(names, []string{"axios", "tar"}) {
		t.Errorf("listed = %v, want axios and tar", names)
	}
	if !slices.Equal(listed[0].Advisories, []string{"GHSA-h", "CVE-1"}) || listed[0].Path != "package-lock.json" {
		t.Errorf("axios entry = %+v (high and critical IDs only)", listed[0])
	}
	if len(quieted) != 1 || quieted[0].Name != "ip" {
		t.Errorf("quieted = %+v", quieted)
	}
}

// discard is a logger that writes nowhere.
var discard = slog.New(slog.NewTextHandler(io.Discard, nil))

func scanQuietScratch(t *testing.T) {
	t.Helper()
	t.Cleanup(scratch.SetUserCacheDirForTest(t.TempDir()))
}

// An answer to the offer, found in the transcript at a later Stop, quietens what the scan listed;
// with no answer, or an agent that can't tell, the offer stays pending and nothing goes quiet.
func TestAnAnsweredOfferQuietensWhatTheScanListed(t *testing.T) {
	scanQuietScratch(t)
	now := time.Date(2026, 10, 23, 10, 0, 0, 0, time.UTC)
	entries := []depquiet.Entry{{Path: "package-lock.json", Name: "axios", Version: "0.21.1", Advisories: []string{"GHSA-h"}}}
	depquiet.SetPending("s1", depquiet.Pending{Repo: "github.com/acme/app", Entries: entries})

	unanswered := writeTranscript(t, `{"type":"user","message":{"role":"user","content":"hi"}}`)
	settleScanAnswer(claude.New(), agent.Event{SessionID: "s1", TranscriptPath: unanswered}, now, discard)
	if !depquiet.PeekPending("s1") || depquiet.Load("github.com/acme/app", now).Active(now) {
		t.Fatal("quiet without an answer")
	}

	answered := writeTranscript(t, `{"type":"user","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":"answered"}]},"toolUseResult":{"questions":[{"question":"Fix the 1 dependency?","header":"LeoPrevent"}],"answers":{"Fix the 1 dependency?":"Not now"}}}`)
	settleScanAnswer(codex.New(), agent.Event{SessionID: "s1", TranscriptPath: answered}, now, discard)
	if !depquiet.PeekPending("s1") {
		t.Fatal("an agent that can't read the answer settled it")
	}
	settleScanAnswer(claude.New(), agent.Event{SessionID: "s1", TranscriptPath: answered}, now, discard)
	timer := depquiet.Load("github.com/acme/app", now)
	if depquiet.PeekPending("s1") || !timer.Until.Equal(now.Add(depquiet.Window)) || len(timer.For("package-lock.json")) != 1 {
		t.Errorf("after the answer: pending %v, timer %+v", depquiet.PeekPending("s1"), timer)
	}
}

// The scan sends the developer's quiet for each file, and quiet_existing from the fix session;
// a turn's own check sends neither.
func TestTheScanSendsTheQuietForEachFile(t *testing.T) {
	var got []wire.DependenciesRequest
	rec := requestRecorder(func(req wire.DependenciesRequest) { got = append(got, req) })
	timer := depquiet.Timer{Until: time.Now().Add(time.Hour), Entries: []depquiet.Entry{
		{Path: "package-lock.json", Name: "axios", Version: "0.21.1", Advisories: []string{"GHSA-h"}},
		{Path: "web/package-lock.json", Name: "ip", Version: "1.1.8"},
	}}
	scan := stamped{checker: rec, trigger: wire.DependencyTriggerScan, quiet: timer, quietExisting: true, seen: &scanSeen{}}
	_, _ = scan.CheckDependencies(wire.DependenciesRequest{Ecosystem: "npm", Path: "package-lock.json"})
	turn := stamped{checker: rec, trigger: wire.DependencyTriggerTurn, quiet: timer, quietExisting: true}
	_, _ = turn.CheckDependencies(wire.DependenciesRequest{Ecosystem: "npm", Path: "package-lock.json"})
	if len(got) != 2 {
		t.Fatalf("requests = %d", len(got))
	}
	if q := got[0].Quiet; len(q) != 1 || q[0].Name != "axios" || !got[0].QuietExisting {
		t.Errorf("scan request quiet = %+v, existing %v", q, got[0].QuietExisting)
	}
	if len(got[1].Quiet) != 0 || got[1].QuietExisting {
		t.Errorf("a turn's check sent a quiet: %+v", got[1])
	}
}

type requestRecorder func(wire.DependenciesRequest)

func (r requestRecorder) CheckDependencies(req wire.DependenciesRequest) (wire.DependenciesResponse, error) {
	r(req)
	return wire.DependenciesResponse{Ecosystem: req.Ecosystem}, nil
}

// Without AskUserQuestion the developer answers in their own words, and the agent ends its reply
// with the answered line: that settles the pending offer the same way.
func TestATypedAnswerQuietensThroughTheAgentsLine(t *testing.T) {
	scanQuietScratch(t)
	now := time.Date(2026, 10, 23, 10, 0, 0, 0, time.UTC)
	depquiet.SetPending("s2", depquiet.Pending{Repo: "github.com/acme/app", Entries: []depquiet.Entry{{Path: "package-lock.json", Name: "axios", Version: "0.21.1"}}})
	typed := writeTranscript(t,
		`{"type":"user","message":{"role":"user","content":"no, not now thanks"}}`,
		`{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"Leaving them as they are.\n\n`+wire.OfferAnsweredLine+`"}]}}`)
	settleScanAnswer(claude.New(), agent.Event{SessionID: "s2", TranscriptPath: typed}, now, discard)
	if depquiet.PeekPending("s2") || !depquiet.Load("github.com/acme/app", now).Active(now) {
		t.Error("a typed answer didn't quieten the scan")
	}
}

// The Stop fires before the reply ending with the answered line reaches the transcript, so the
// hook input's last message counts on that very Stop.
func TestTheAnsweredLineCountsBeforeTheTranscriptHasIt(t *testing.T) {
	scanQuietScratch(t)
	now := time.Date(2026, 10, 23, 14, 14, 0, 0, time.UTC)
	depquiet.SetPending("s3", depquiet.Pending{Repo: "github.com/acme/app", Entries: []depquiet.Entry{{Path: "package-lock.json", Name: "axios", Version: "0.21.1"}}})
	notYet := writeTranscript(t, `{"type":"user","message":{"role":"user","content":"no thanks"}}`)
	settleScanAnswer(claude.New(), agent.Event{SessionID: "s3", TranscriptPath: notYet, LastAssistantMessage: "Leaving them for now.\n\n" + wire.OfferAnsweredLine}, now, discard)
	if depquiet.PeekPending("s3") || !depquiet.Load("github.com/acme/app", now).Active(now) {
		t.Error("the answered line in the hook's last message didn't quieten the scan")
	}
	depquiet.SetPending("s4", depquiet.Pending{Repo: "github.com/acme/other", Entries: []depquiet.Entry{{Path: "package-lock.json", Name: "ip", Version: "1.1.8"}}})
	settleScanAnswer(claude.New(), agent.Event{SessionID: "s4", TranscriptPath: notYet, LastAssistantMessage: "I'll add " + wire.OfferAnsweredLine + " once you answer."}, now, discard)
	if !depquiet.PeekPending("s4") {
		t.Error("a mention mid-sentence counted as the answered line")
	}
}

// A server released before the line was reworded still asks for the old one; it counts as well.
func TestTheOldAnsweredLineStillCounts(t *testing.T) {
	scanQuietScratch(t)
	now := time.Date(2026, 10, 23, 15, 0, 0, 0, time.UTC)
	depquiet.SetPending("s5", depquiet.Pending{Repo: "github.com/acme/app", Entries: []depquiet.Entry{{Path: "package-lock.json", Name: "axios", Version: "0.21.1"}}})
	notYet := writeTranscript(t, `{"type":"user","message":{"role":"user","content":"no"}}`)
	settleScanAnswer(claude.New(), agent.Event{SessionID: "s5", TranscriptPath: notYet, LastAssistantMessage: "OK.\n\nLeoPrevent: offer answered"}, now, discard)
	if depquiet.PeekPending("s5") {
		t.Error("the old answered line didn't count")
	}
}
