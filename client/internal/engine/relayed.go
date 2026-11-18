package engine

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/scratch"
)

// The markdown a Stop asked the agent to print for the developer, kept until the next Stop of the
// same session. The next Stop takes it back and removes it from the agent's reply before /outcome
// sees that reply: the dependency check's notice is never evidence about the code review's
// findings (LEO-620, D59: no effect on /outcome). Best-effort: losing it only means the re-judge
// sees text it is told to disregard.

func relayedPath(sessionID string) string {
	return filepath.Join(scratch.Dir("relayed"), filepath.Base(sessionID))
}

func rememberRelayed(sessionID, markdown string, log *slog.Logger) {
	if sessionID == "" {
		return
	}
	p := relayedPath(sessionID)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		log.Debug("remember relayed notice failed (continuing)", "err", err.Error())
		return
	}
	if err := os.WriteFile(p, []byte(markdown), 0o600); err != nil {
		log.Debug("remember relayed notice failed (continuing)", "err", err.Error())
	}
}

// takeRelayed returns the markdown the last Stop asked the agent to print, and forgets it.
func takeRelayed(sessionID string) string {
	if sessionID == "" {
		return ""
	}
	p := relayedPath(sessionID)
	b, err := os.ReadFile(p)
	_ = os.Remove(p)
	if err != nil {
		return ""
	}
	return string(b)
}

// A mark that a Stop woke the agent with the dependency check's instructions, kept until the next
// Stop of the same session, which takes it and re-checks the turn's dependency files (LEO-620).
// It holds the developer notice shown with the wake, so the re-check can leave out a notice that
// says exactly the same again (LEO-695: an agent that rightly left a package alone saw it twice).
// Best-effort: losing it only means that Stop says nothing about the dependencies.

// wakeRoot opens the folder the wake marks live in, created if missing. Every mark is opened
// through it, so a name can only ever reach a file inside that folder (os.Root), whatever the
// session ID holds.
func wakeRoot() (*os.Root, error) {
	dir := scratch.Dir("dependency-wake")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return os.OpenRoot(dir)
}

func rememberDependencyWake(sessionID, notice string, log *slog.Logger) {
	if sessionID == "" {
		return
	}
	root, err := wakeRoot()
	if err != nil {
		log.Debug("remember dependency wake failed (continuing)", "err", err.Error())
		return
	}
	defer root.Close()
	name := filepath.Base(sessionID)
	_ = root.Remove(name + takenSuffix) // a new wake: the last one's claim no longer applies
	sweepTaken(root)
	if err := root.WriteFile(name, []byte(notice), 0o600); err != nil {
		log.Debug("remember dependency wake failed (continuing)", "err", err.Error())
	}
}

// takenSuffix names the claim beside the mark: whoever creates it took the mark.
const takenSuffix = ".taken"

// sweepTaken removes claims older than a day: a session whose last wake was taken leaves its claim
// behind, and nothing else would clear it. Best-effort.
func sweepTaken(root *os.Root) {
	dir, err := root.Open(".")
	if err != nil {
		return
	}
	entries, err := dir.ReadDir(-1)
	_ = dir.Close()
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-24 * time.Hour)
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), takenSuffix) {
			continue
		}
		if info, err := e.Info(); err == nil && info.ModTime().Before(cutoff) {
			_ = root.Remove(e.Name())
		}
	}
}

// wakeNotice is the developer notice shown with the last dependency wake, "" when there's none.
// Read it before taking the mark, which removes it.
func wakeNotice(sessionID string) string {
	if sessionID == "" {
		return ""
	}
	root, err := wakeRoot()
	if err != nil {
		return ""
	}
	defer root.Close()
	b, err := root.ReadFile(filepath.Base(sessionID))
	if err != nil {
		return ""
	}
	return string(b)
}

// takeDependencyWake reports whether the last Stop woke the agent for the dependency check, and
// forgets it. Exactly one caller takes a mark, however many Stops overlap: the claim is creating a
// file with O_EXCL, which is atomic on every platform. Removing the mark is not a claim (two
// removes of one file can both report success), and neither is a rename (LEO-652). The claim stays
// until the next wake is remembered, so a caller that saw the mark a moment late can't take it too.
func takeDependencyWake(sessionID string) bool {
	if sessionID == "" {
		return false
	}
	root, err := wakeRoot()
	if err != nil {
		return false
	}
	defer root.Close()
	name := filepath.Base(sessionID)
	if _, err := root.Stat(name); err != nil {
		return false // no wake: the common case, with nothing created
	}
	f, err := root.OpenFile(name+takenSuffix, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return false // another Stop took it
	}
	_ = f.Close()
	_ = root.Remove(name)
	return true
}
