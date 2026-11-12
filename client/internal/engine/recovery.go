package engine

import (
	"errors"
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
	after = withoutDeletedFiles(after)
	files := make([]wire.ChangedFile, 0, len(after)+len(p.Sources))
	seen := map[string]bool{}
	total := 0
	for _, src := range p.Sources {
		body, err := recoveryContent(src)
		if err != nil {
			if flaggedFileDeleted(src) {
				files = append(files, wire.ChangedFile{Path: src.Path, Deleted: true})
				seen[src.Path] = true
				continue
			}
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
		total += len(c.FullContent) + len(c.AddedText) + len(c.RemovedText)
		if total > limits.MaxChangedTotalBytes {
			log.Info("outcome recovery exceeds file budget")
			return
		}
		files = append(files, wire.ChangedFile{Path: c.FilePath, FullContent: c.FullContent, BodyStartLine: c.BodyStartLine, AddedText: c.AddedText, AddedLines: c.AddedLines, RemovedText: c.RemovedText, RemovedAt: c.RemovedAt, Deleted: c.Deleted})
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

// flaggedFileDeleted reports whether src's path is gone from its repository: the root
// opens and the path itself does not exist. Lstat, so a dangling symlink is not a
// deletion, and only os.ErrNotExist counts; any other failure, including a repository
// root that is gone too, is not evidence of a fix and stays unreadable.
func flaggedFileDeleted(
	src outcome.Source,
) bool {
	root, err := os.OpenRoot(src.Root)
	if err != nil {
		return false
	}
	defer root.Close()
	_, err = root.Lstat(src.Relative)
	return errors.Is(err, os.ErrNotExist)
}

// withoutDeletedFiles drops the files the turn removed ENTIRELY from an outcome's
// after-state. /review sends them (LEO-483) so the judge sees a deleted guard; an outcome
// asks whether a flagged finding is still there, and a deleted file carries only its
// FORMER content, which must never be read back as the after-state.
//
// A FLAGGED file the fix deleted is not lost: withFlaggedFiles, which runs after this,
// adds it back body-less as Deleted, so the re-judge can credit the deletion (LEO-516). A
// deleted file nobody flagged stays out, since no finding asks about it.
func withoutDeletedFiles(after []transcript.Change) []transcript.Change {
	kept := after[:0:0]
	for _, c := range after {
		if !c.Deleted {
			kept = append(kept, c)
		}
	}
	return kept
}

// withFlaggedFiles adds back every flagged file the turn-start diff no longer lists, read
// as it is on disk now.
//
// ⚠️ A FILE THE FIX RETURNED TO ITS TURN-START STATE HAS NO DIFF, SO IT IS MISSING FROM
// `after`. Removing the lines the agent added this turn is the commonest fix there is, and
// when those were the only changes to the file, git reports nothing for it. The re-judge
// then sees the flagged code in BEFORE and nothing in AFTER, and an unverifiable fix
// resolves to still-firing: a completed fix recorded as declined (LEO-485: three logging
// fixes on a pilot account, each then counted as a dispute). The recovery path never had
// this bug because it reads p.Sources back the same way.
//
// A flagged file the fix DELETED is sent as Deleted with no body, so the re-judge can
// credit a deletion that removed the flagged construct (LEO-516). A file that cannot be
// read for any other reason (no longer a regular file, invalid UTF-8, over the budget)
// is left out, which keeps the conservative still-firing verdict rather than implying a
// fix.
func withFlaggedFiles(
	after []transcript.Change,
	p outcome.Pending,
	log *slog.Logger,
) []transcript.Change {
	seen := make(map[string]bool, len(after))
	total := 0
	for _, c := range after {
		seen[c.FilePath] = true
		total += len(c.FullContent) + len(c.AddedText)
	}
	for _, src := range p.Sources {
		if seen[src.Path] {
			continue
		}
		body, err := recoveryContent(src)
		if err != nil {
			if flaggedFileDeleted(src) {
				seen[src.Path] = true
				after = append(after, transcript.Change{FilePath: src.Path, Deleted: true})
				continue
			}
			log.Info("flagged file not readable for the outcome", "path", src.Path, "err", err)
			continue
		}
		if total+len(body) > limits.MaxChangedTotalBytes {
			log.Info("flagged file exceeds the outcome file budget", "path", src.Path)
			continue
		}
		total += len(body)
		seen[src.Path] = true
		after = append(after, transcript.Change{FilePath: src.Path, FullContent: body})
	}
	return after
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
		after = append(after, transcript.Change{FilePath: f.Path, AddedText: f.AddedText, FullContent: f.FullContent, BodyStartLine: f.BodyStartLine, AddedLines: f.AddedLines, RemovedText: f.RemovedText, RemovedAt: f.RemovedAt, Deleted: f.Deleted})
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
