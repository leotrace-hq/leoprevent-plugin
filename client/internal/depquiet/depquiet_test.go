package depquiet

import (
	"testing"
	"time"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/scratch"
)

var t0 = time.Date(2026, 10, 23, 10, 0, 0, 0, time.UTC)

func useTempScratch(t *testing.T) {
	t.Helper()
	t.Cleanup(scratch.SetUserCacheDirForTest(t.TempDir()))
}

// The first answer starts a day; a later one joins it, so everything comes back at the same time.
func TestALaterAnswerJoinsTheRunningTimer(t *testing.T) {
	useTempScratch(t)
	first := Answer("github.com/acme/app", []Entry{{Path: "package-lock.json", Name: "axios", Version: "0.21.1", Advisories: []string{"GHSA-b", "GHSA-a"}}}, t0)
	if !first.Until.Equal(t0.Add(Window)) {
		t.Fatalf("until = %v, want %v", first.Until, t0.Add(Window))
	}
	later := Answer("github.com/acme/app", []Entry{{Path: "package-lock.json", Name: "ip", Version: "1.1.8"}}, t0.Add(20*time.Hour))
	if !later.Until.Equal(first.Until) || len(later.Entries) != 2 {
		t.Errorf("joined timer = %+v, want two entries until %v", later, first.Until)
	}
	if got := Load("github.com/acme/app", t0.Add(23*time.Hour)).For("package-lock.json"); len(got) != 2 || got[0].Advisories[0] != "GHSA-a" {
		t.Errorf("for = %+v (advisories sorted)", got)
	}
	if got := Load("github.com/acme/app", t0.Add(23*time.Hour)).For("web/package-lock.json"); len(got) != 0 {
		t.Errorf("another file's quiet list = %+v", got)
	}
}

// Once the day is up, nothing is quiet, and the next answer starts a new day.
func TestATimerRunsOut(t *testing.T) {
	useTempScratch(t)
	Answer("repo", []Entry{{Path: "package-lock.json", Name: "axios", Version: "0.21.1"}}, t0)
	if Load("repo", t0.Add(Window)).Active(t0.Add(Window)) {
		t.Error("still quiet at the end of the window")
	}
	next := Answer("repo", []Entry{{Path: "package-lock.json", Name: "ip", Version: "1.1.8"}}, t0.Add(25*time.Hour))
	if !next.Until.Equal(t0.Add(25*time.Hour+Window)) || len(next.Entries) != 1 {
		t.Errorf("new timer = %+v", next)
	}
}

// An answer about a package already held replaces its advisories with the latest answered.
func TestAnAnswerReplacesTheSamePackage(t *testing.T) {
	useTempScratch(t)
	Answer("repo", []Entry{{Path: "p", Name: "hb", Version: "1.0.0", Advisories: []string{"GHSA-a"}}}, t0)
	got := Answer("repo", []Entry{{Path: "p", Name: "hb", Version: "1.0.0", Advisories: []string{"GHSA-a", "GHSA-c"}}}, t0.Add(time.Hour))
	if len(got.Entries) != 1 || len(got.Entries[0].Advisories) != 2 {
		t.Errorf("entries = %+v", got.Entries)
	}
}

// Repositories are kept apart, and a repository with no identity has no quiet at all.
func TestRepositoriesAreKeptApart(t *testing.T) {
	useTempScratch(t)
	Answer("a", []Entry{{Path: "p", Name: "hb", Version: "1.0.0"}}, t0)
	if Load("b", t0).Active(t0) {
		t.Error("b quiet from a's answer")
	}
	if Answer("", []Entry{{Path: "p", Name: "hb", Version: "1.0.0"}}, t0).Active(t0) || Load("", t0).Active(t0) {
		t.Error("a repository with no identity was quietened")
	}
}

// A session's offer waits for its answer, once.
func TestAPendingOfferIsTakenOnce(t *testing.T) {
	useTempScratch(t)
	if PeekPending("s1") {
		t.Fatal("pending before any offer")
	}
	SetPending("s1", Pending{Repo: "repo", Entries: []Entry{{Path: "p", Name: "hb", Version: "1.0.0"}}})
	if !PeekPending("s1") {
		t.Fatal("no pending after the offer")
	}
	p, ok := TakePending("s1")
	if !ok || p.Repo != "repo" || len(p.Entries) != 1 {
		t.Errorf("taken = %+v, %v", p, ok)
	}
	if _, ok := TakePending("s1"); ok || PeekPending("s1") {
		t.Error("pending taken twice")
	}
}
