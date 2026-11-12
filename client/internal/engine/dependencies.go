package engine

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/agent"
)

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
