package engine

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/agent"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/outcome"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/vcs"
	"github.com/leotrace-hq/leoprevent-plugin/limits"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

func prepareRecovery(
	p *outcome.Pending,
	cwd string,
	changes []transcript.Change,
	meta wire.TurnMeta,
) {
	p.OriginalMeta = wire.TurnMeta{Agent: meta.Agent, AgentModel: meta.AgentModel, Prompt: meta.Prompt}
	byPath := map[string]transcript.Change{}
	for _, c := range changes {
		byPath[c.FilePath] = c
	}
	for _, f := range p.Before {
		c, ok := byPath[f.Path]
		if !ok {
			p.Sources = nil
			return
		}
		root := c.RepoRoot
		if root == "" {
			root = vcs.RepoRoot(cwd)
		}
		if root == "" {
			p.Sources = nil
			return
		}
		relative := c.FilePath
		if c.RepoDir != "" {
			relative = strings.TrimPrefix(relative, c.RepoDir+"/")
		}
		if filepath.IsAbs(relative) {
			var err error
			relative, err = filepath.Rel(root, relative)
			if err != nil {
				p.Sources = nil
				return
			}
		}
		p.Sources = append(p.Sources, outcome.Source{Path: f.Path, Root: root, Relative: relative})
	}
}

func CaptureRecovery(
	a agent.Agent,
	ev agent.Event,
) {
	// Fast path, non-authoritative: the capture below runs a diff and reads files, so
	// it works off this snapshot and only claims the record at the end.
	p, ok := outcome.Load(ev.SessionID)
	if !ok || !needsRecovery(p) {
		return
	}
	log := slog.With("agent", a.Name(), "review_id", p.ReviewID)
	after, _, _, _, err := changedFiles(a, ev, log)
	if err != nil {
		log.Info("outcome recovery capture failed", "err", err)
		return
	}
	files := make([]wire.ChangedFile, 0, len(after)+len(p.Sources))
	seen := map[string]bool{}
	total := 0
	for _, src := range p.Sources {
		body, err := recoveryContent(src)
		if err != nil {
			log.Info("outcome recovery capture failed", "err", err)
			return
		}
		total += len(body)
		if total > limits.MaxChangedTotalBytes {
			log.Info("outcome recovery exceeds file budget")
			return
		}
		files = append(files, wire.ChangedFile{Path: src.Path, FullContent: body})
		seen[src.Path] = true
	}
	for _, c := range after {
		if seen[c.FilePath] {
			continue
		}
		total += len(c.FullContent) + len(c.AddedText)
		if total > limits.MaxChangedTotalBytes {
			log.Info("outcome recovery exceeds file budget")
			return
		}
		files = append(files, wire.ChangedFile{Path: c.FilePath, FullContent: c.FullContent, AddedText: c.AddedText, AddedLines: c.AddedLines})
	}
	// Claim the record and attach the capture only if it is still the one snapshotted
	// above and still uncaptured. A plain Remember here could resurrect a record a
	// concurrent Stop already took and shipped (so it would ship twice), or overwrite
	// a newer review's record with this older one.
	claimed, ok := outcome.TakeIf(ev.SessionID, func(cur outcome.Pending) bool {
		return cur.ReviewID == p.ReviewID && needsRecovery(cur)
	})
	if !ok {
		log.Info("outcome recovery skipped: record taken or replaced concurrently")
		return
	}
	claimed.Recovery = &outcome.Recovery{After: files}
	if err := outcome.PutBack(ev.SessionID, claimed); err != nil {
		log.Info("outcome recovery save failed", "err", err)
		return
	}
	log.Info("outcome recovery captured before next prompt")
}

// needsRecovery reports whether p is a record CaptureRecovery should fill in: one
// with sources to read back and no capture yet.
func needsRecovery(p outcome.Pending) bool {
	return p.Recovery == nil && len(p.Sources) > 0
}

func recoveryContent(
	src outcome.Source,
) (string, error) {
	root, err := os.OpenRoot(src.Root)
	if err != nil {
		return "", err
	}
	defer root.Close()
	info, err := root.Stat(src.Relative)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("not a regular file: %s", src.Path)
	}
	f, err := root.Open(src.Relative)
	if err != nil {
		return "", err
	}
	defer f.Close()
	info, err = f.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("not a regular file: %s", src.Path)
	}
	body, err := io.ReadAll(io.LimitReader(f, limits.MaxChangedFileBytes+1))
	if err != nil {
		return "", err
	}
	if len(body) > limits.MaxChangedFileBytes || !utf8.Valid(body) {
		return "", fmt.Errorf("unsupported recovery content: %s", src.Path)
	}
	return string(body), nil
}

func shipRecovery(
	r Reviewer,
	sessionID string,
	log *slog.Logger,
) bool {
	// Load is only a fast path for the common no-recovery case; TakeIf is the claim.
	// Of concurrent Stop hooks on one session, exactly one gets the record and ships
	// it, and a record without a recovery is put back untouched rather than lost.
	if p, ok := outcome.Load(sessionID); !ok || p.Recovery == nil {
		return false
	}
	p, ok := outcome.TakeIf(sessionID, func(p outcome.Pending) bool { return p.Recovery != nil })
	if !ok {
		return false
	}
	after := make([]transcript.Change, 0, len(p.Recovery.After))
	for _, f := range p.Recovery.After {
		after = append(after, transcript.Change{FilePath: f.Path, AddedText: f.AddedText, FullContent: f.FullContent, AddedLines: f.AddedLines})
	}
	intro, pre, err := r.ShipOutcome(p, after, "", p.OriginalMeta)
	if err != nil {
		log.Info("recovered outcome delivery unscored or failed", "review_id", p.ReviewID, "err", err)
		return true
	}
	seedLedger(sessionID, p, intro, pre, log)
	log.Info("recovered outcome delivered", "review_id", p.ReviewID)
	return true
}
