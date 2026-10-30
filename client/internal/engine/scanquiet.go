package engine

import (
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/agent"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/depquiet"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

// The scan's quiet (LEO-673 follow-up, decided 23 Oct 2026; internal/depquiet). The session scan
// sends the developer's running answer back as each file's quiet list, and the server leaves those
// packages out of the notice and the offer. What the scan does show is kept as pending until the
// developer answers its offer, read from the transcript at a later Stop of the session; the session
// started to fix the offer quietens what was already there itself, on its own first Stop.

// scanAnswerReader is an adapter that can tell, from the transcript, how the developer answered
// the scan's offer: the Claude adapter, which asks it with AskUserQuestion and starts the fix
// session in the desktop app. Any other agent's offer is a plain question, so nothing goes quiet.
type scanAnswerReader interface {
	ScanOfferAnswered(transcriptPath string) bool
	ScanFixSession(transcriptPath string) bool
}

// settleScanAnswer moves a session's pending offer into the developer's quiet once they've
// answered it. Cheap when nothing is pending: one stat. Best-effort.
//
// ⚠️ THE AGENT'S LAST REPLY IS READ FROM THE HOOK INPUT FIRST. The answered line ends the reply after
// the developer answers, and the Stop hook fires before Claude Code has written that reply to the
// transcript (the same lag turnMeta and agentReply allow for), so the transcript alone missed it
// on the very Stop it should count on, and the next session asked again. The transcript still
// covers an AskUserQuestion answer and a line from an earlier reply in the session.
func settleScanAnswer(a agent.Agent, ev agent.Event, now time.Time, log *slog.Logger) {
	r, ok := a.(scanAnswerReader)
	if !ok || !depquiet.PeekPending(ev.SessionID) {
		return
	}
	if !saysAnswered(ev.LastAssistantMessage) && !r.ScanOfferAnswered(ev.TranscriptPath) {
		return
	}
	p, ok := depquiet.TakePending(ev.SessionID)
	if !ok {
		return
	}
	t := depquiet.Answer(p.Repo, p.Entries, now)
	log.Info("dependency scan: offer answered, quiet for this developer", "packages", len(p.Entries), "until", t.Until.Format(time.RFC3339))
}

// saysAnswered reports a reply with one of wire.OfferAnsweredLines on a line of its own.
func saysAnswered(reply string) bool {
	for _, l := range strings.Split(reply, "\n") {
		if slices.Contains(wire.OfferAnsweredLines, strings.TrimSpace(l)) {
			return true
		}
	}
	return false
}

// scanSeen gathers, across a scan's requests, what each answer quietened and what it still showed.
type scanSeen struct {
	mu              sync.Mutex
	quieted, listed []depquiet.Entry
}

// add records one file's answer: the packages it quietened, and the ones in its notice an answer
// could quieten (already there, needing a fix, not malware).
func (s *scanSeen) add(path string, resp wire.DependenciesResponse) {
	s.mu.Lock()
	defer s.mu.Unlock()
	quiet := map[string]bool{}
	for _, q := range resp.Quieted {
		quiet[q.Name+"@"+q.Version] = true
		s.quieted = append(s.quieted, depquiet.Entry{Path: path, Name: q.Name, Version: q.Version, Advisories: q.Advisories})
	}
	for _, c := range resp.Packages {
		if quiet[c.Name+"@"+c.Version] || !answerable(c) {
			continue
		}
		s.listed = append(s.listed, depquiet.Entry{Path: path, Name: c.Name, Version: c.Version, Advisories: seriousIDs(c)})
	}
}

func (s *scanSeen) snapshot() (quieted, listed []depquiet.Entry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]depquiet.Entry(nil), s.quieted...), append([]depquiet.Entry(nil), s.listed...)
}

// answerable is a package the server would quieten once answered: one that needs fixing, isn't
// malware, and wasn't added or changed by the turn (the server's own rule; malware never goes quiet).
func answerable(c wire.DependencyCheck) bool {
	if c.Security == nil || !c.Security.NeedsFix || c.Change == wire.DependencyAdded || c.Change == wire.DependencyChanged {
		return false
	}
	for _, a := range c.Security.Advisories {
		if a.Malicious {
			return false
		}
	}
	return true
}

// seriousIDs is every ID of a package's high and critical advisories: what an answer covers, so a
// new one brings the package back. The same set the server compares.
func seriousIDs(c wire.DependencyCheck) []string {
	var ids []string
	for _, a := range c.Security.Advisories {
		if a.Severity == "critical" || a.Severity == "high" {
			ids = append(ids, a.IDs...)
		}
	}
	return ids
}
