// Package depcheck is the end-of-turn dependency check (LEO-511, decision D58): for the
// dependency files a turn changed, it reads them now and as they were at the start of the turn,
// sends what changed to POST /dependencies, and returns the server's developer notice.
//
// ⚠️ A PLACEHOLDER FOR TESTING, OFF BY DEFAULT. It runs only with LEOPREVENT_SEND_DEPENDENCIES=on.
// How the notice reaches the developer is still tentative (LEO-511, "Delivering the dependency
// notice"); until that's agreed the caller shows it as a plain notice, which the Claude desktop
// app and claude.ai don't display. It sends only the turn's changes, never the whole file on a
// session's first change (that rule isn't built), and nothing it does changes the review.
//
// Which files it looks at comes only from the readers (deps.All): nothing here names a file.
package depcheck

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/deps"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

// switchEnv turns the check on. It's the plugin's switch, separate from the server's
// LEOPREVENT_DEPENDENCY_CHECK.
const switchEnv = "LEOPREVENT_SEND_DEPENDENCIES"

// Enabled reports whether the check is switched on for this process.
func Enabled() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv(switchEnv)), "on")
}

// maxPerRequest is the server's MaxDependencyPackages (config.go in the server module, which the
// plugin can't import). A larger list is sent as several requests.
var maxPerRequest = 10000

// budget bounds the whole check on the Stop path: no request starts after it, and each request
// has its own client timeout too. Past it the rest is skipped and logged, never reported clean.
const budget = 8 * time.Second

// Checker posts one request to /dependencies. The cloud reviewer implements it; the local tier
// doesn't (no dependency check there, D6).
type Checker interface {
	CheckDependencies(wire.DependenciesRequest) (wire.DependenciesResponse, error)
}

// TurnStart returns the reader of the repository at root as it was at the start of the turn,
// or nil when there's no turn-start copy (then every dependency is sent with no change known).
type TurnStart func(root string) deps.Opener

// Run checks the dependency files among changes and returns the developer notice, "" when
// there's nothing to say. It fails open: any error is logged and that file is skipped.
// It logs counts and the file path (on the developer's own machine), never package names.
func Run(changes []transcript.Change, cwd string, turnStart TurnStart, c Checker, log *slog.Logger) string {
	start := time.Now()
	type fileNotice struct{ path, notice string }
	var notices []fileNotice
	for _, ch := range changes {
		if ch.Deleted || ch.Virtual {
			continue // a deleted file has nothing to check; its removals are for the fix check
		}
		if _, ok := deps.All.For(ch.FilePath); !ok {
			continue
		}
		path, inside := onDisk(ch, cwd)
		if !inside {
			log.Warn("dependency check: file outside the project, NOT read", "file", ch.FilePath)
			continue
		}
		marked, ecosystem, ok := read(ch, path, turnStart, log)
		if !ok {
			continue
		}
		var pkgs []wire.DependencyVersion
		private := 0
		for _, m := range deps.Collapse(marked) {
			if m.Private {
				private++ // never sent: it may be the customer's own package
				continue
			}
			pkgs = append(pkgs, wire.DependencyVersion{Name: m.Name, Version: m.Version, Line: m.Line,
				DependencyContext: wire.DependencyContext{Indirect: m.Indirect, Dev: m.Dev, Change: m.Change, Previous: m.Previous}})
		}
		log.Info("dependency check: read", "file", ch.FilePath, "ecosystem", ecosystem,
			"marked", len(marked), "to_send", len(pkgs), "private_withheld", private)
		for i := 0; i < len(pkgs); i += maxPerRequest {
			if time.Since(start) > budget {
				log.Warn("dependency check: out of time, the rest was NOT checked", "file", ch.FilePath, "unsent", len(pkgs)-i)
				break
			}
			batch := pkgs[i:min(i+maxPerRequest, len(pkgs))]
			resp, err := c.CheckDependencies(wire.DependenciesRequest{Ecosystem: ecosystem, Packages: batch})
			if err != nil {
				log.Warn("dependency check failed: NOT checked (fail-open)", "file", ch.FilePath, "packages", len(batch), "err", err.Error())
				continue
			}
			flagged := 0
			for _, p := range resp.Packages {
				if p.Security != nil && p.Security.NeedsFix {
					flagged++
				}
			}
			verdict := answer(resp, flagged)
			log.Info("dependency check: answered", "file", ch.FilePath, "packages", len(batch),
				"verdict", verdict, "needs_fix", flagged, "unchecked", resp.Unchecked)
			if resp.Unchecked > 0 {
				// A clean verdict here means "nothing found", not "everything checked".
				log.Warn("dependency check: PARTIAL, some packages couldn't be fully checked", "file", ch.FilePath, "unchecked", resp.Unchecked)
			}
			hasNotice := resp.Messages.Developer != nil && strings.TrimSpace(*resp.Messages.Developer) != ""
			switch {
			case hasNotice:
				notices = append(notices, fileNotice{ch.FilePath, *resp.Messages.Developer})
			case verdict == wire.VerdictTriggered:
				log.Warn("dependency check: something needs fixing but the server sent no notice", "file", ch.FilePath, "needs_fix", flagged)
			}
		}
	}
	log.Info("dependency check: done", "notices", len(notices), "took_ms", time.Since(start).Milliseconds())
	if len(notices) == 1 {
		return notices[0].notice
	}
	var parts []string
	for _, n := range notices {
		parts = append(parts, fmt.Sprintf("%s:\n%s", n.path, n.notice))
	}
	return strings.Join(parts, "\n\n")
}

// read reads the file now and at the start of the turn, and marks each dependency. ok is false
// when the file couldn't be read now (logged).
func read(ch transcript.Change, path string, turnStart TurnStart, log *slog.Logger) ([]deps.Marked, string, bool) {
	after, reader, err := deps.All.ReadWith(path, deps.Disk)
	if err != nil {
		n := deps.Note{Code: deps.NoteFileUnreadable, File: ch.FilePath, Reason: err.Error()}
		log.Warn("dependency check: file NOT checked", "file", ch.FilePath, "note", n.Code, "reason", n.Reason)
		return nil, "", false
	}
	for _, n := range after.Notes {
		log.Info("dependency check: note", "file", ch.FilePath, "note", n.String())
	}
	if turnStart == nil || ch.RepoRoot == "" {
		log.Info("dependency check: no start-of-turn copy, so no change is marked", "file", ch.FilePath)
		return deps.Unmarked(after.Dependencies), reader.Ecosystem(), true
	}
	before, _, err := deps.All.ReadWith(path, turnStart(ch.RepoRoot))
	switch {
	case err == nil:
		return deps.Compare(before.Dependencies, after.Dependencies).Changes, reader.Ecosystem(), true
	case errors.Is(err, fs.ErrNotExist):
		return deps.Compare(nil, after.Dependencies).Changes, reader.Ecosystem(), true // created this turn
	default:
		log.Info("dependency check: start-of-turn copy unreadable, so no change is marked", "file", ch.FilePath, "err", err.Error())
		return deps.Unmarked(after.Dependencies), reader.Ecosystem(), true
	}
}

// onDisk is where the changed file is now: under its repository's root on the git path (its
// FilePath carries the repository's label as a prefix when the turn spans several), or as the
// transcript recorded it, under cwd. ok is false when that place isn't inside the root or cwd:
// the path comes from the agent's own record of the turn, so a "../" path or a symlinked folder
// must never make the plugin read a file outside the project.
func onDisk(ch transcript.Change, cwd string) (path string, ok bool) {
	root := cwd
	switch {
	case ch.RepoRoot != "":
		root = ch.RepoRoot
		rel := ch.FilePath
		if ch.RepoDir != "" {
			rel = strings.TrimPrefix(rel, ch.RepoDir+"/")
		}
		path = filepath.Join(root, filepath.FromSlash(rel))
	case filepath.IsAbs(ch.FilePath):
		path = ch.FilePath
	default:
		path = filepath.Join(cwd, ch.FilePath)
	}
	if root == "" {
		return "", false
	}
	return path, within(root, path)
}

// within reports whether path is root or inside it, once symlinks in either are resolved.
func within(root, path string) bool {
	rel, err := filepath.Rel(resolved(root), resolved(path))
	return err == nil && !filepath.IsAbs(rel) && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// resolved is path with its symlinks resolved: the whole path when it exists, else its folder
// (a file can be missing at the start of the turn), else just cleaned.
func resolved(path string) string {
	path = filepath.Clean(path)
	if r, err := filepath.EvalSymlinks(path); err == nil {
		return r
	}
	if dir, err := filepath.EvalSymlinks(filepath.Dir(path)); err == nil {
		return filepath.Join(dir, filepath.Base(path))
	}
	return path
}

// answer is the response's verdict. A server older than the field (before PR #1061) sends none,
// so it's worked out the same way the server does: triggered when any package needs fixing.
func answer(resp wire.DependenciesResponse, needsFix int) string {
	if resp.Verdict != "" {
		return resp.Verdict
	}
	if needsFix > 0 {
		return wire.VerdictTriggered
	}
	return wire.VerdictClean
}
