package engine

import (
	"log/slog"
	"os"
	"path/filepath"

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
