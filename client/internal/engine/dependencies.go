package engine

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/agent"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/depcheck"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/deps"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/vcs"
)

// checkDependencies runs the dependency check for this turn (a placeholder, off unless
// LEOPREVENT_SEND_DEPENDENCIES=on; see internal/depcheck) and, when the server has a notice,
// returns the writer the rest of the Stop should use and a function that flushes it with the
// notice attached. Otherwise it returns stdout and a no-op.
//
// ⚠️ THE NOTICE IS ATTACHED, NEVER A DECISION. It is added to the systemMessage of whatever this
// Stop prints (a review wake, a first-clean notice) or printed as a plain notice when the Stop
// prints nothing. It never blocks, never wakes the agent and never enters its context, so the
// review and /outcome run exactly as before. That also means the Claude desktop app and
// claude.ai don't show it; how they will is the tentative delivery plan (LEO-511).
func checkDependencies(a agent.Agent, r Reviewer, ev agent.Event, changes []transcript.Change, usedGit bool,
	log *slog.Logger, stdout io.Writer) (io.Writer, func()) {
	noop := func() {}
	if !depcheck.Enabled() {
		return stdout, noop
	}
	c, ok := r.(depcheck.Checker)
	if !ok {
		log.Debug("dependency check: not available on this tier")
		return stdout, noop
	}
	var turnStart depcheck.TurnStart
	if usedGit {
		if ts, ok := vcs.LoadTurnStart(ev.Cwd, ev.SessionID); ok {
			turnStart = func(root string) deps.Opener { return ts.Opener(root) }
		}
	}
	notice := depcheck.Run(changes, ev.Cwd, turnStart, c, log)
	if notice == "" {
		return stdout, noop
	}
	var buf bytes.Buffer
	return &buf, func() { fmt.Fprint(stdout, string(attachNotice(a, buf.Bytes(), notice, log))) }
}

// attachNotice adds notice to the hook output out. With no output it is the agent's own plain
// notice. Otherwise it joins the output's systemMessage, but only for an agent whose own notice
// is a systemMessage (asked of the adapter, never assumed); for any other the output is left
// as it is and the notice is logged.
func attachNotice(a agent.Agent, out []byte, notice string, log *slog.Logger) []byte {
	if len(bytes.TrimSpace(out)) == 0 {
		plain, err := a.DeliverNotice(notice)
		if err != nil {
			log.Warn("dependency notice NOT shown", "err", err.Error())
			return out
		}
		return plain
	}
	probe, err := a.DeliverNotice("x")
	var shape map[string]json.RawMessage
	if err != nil || json.Unmarshal(probe, &shape) != nil || shape["systemMessage"] == nil {
		log.Info("dependency notice NOT shown: this agent's hook output has no notice field", "agent", a.Name())
		return out
	}
	var hook map[string]json.RawMessage
	if json.Unmarshal(out, &hook) != nil {
		log.Info("dependency notice NOT shown: hook output isn't a JSON object", "agent", a.Name())
		return out
	}
	var existing string
	if raw, ok := hook["systemMessage"]; ok {
		_ = json.Unmarshal(raw, &existing)
	}
	joined := strings.TrimSpace(strings.Join([]string{existing, notice}, "\n\n"))
	msg, _ := json.Marshal(joined)
	hook["systemMessage"] = msg
	merged, err := json.Marshal(hook)
	if err != nil {
		return out
	}
	return merged
}
