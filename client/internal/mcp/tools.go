package mcp

import (
	"fmt"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/stats"
)

// Reader is what the tools read through — the dashboard's agent API.
//
// An interface rather than the concrete client so the tool layer is testable without a
// network, and so this package never grows a second idea of how to reach the dashboard.
type Reader interface {
	Read(q stats.Query) ([]byte, error)
}

// The tool names, as the agent sees them after its own namespacing (Claude Code renders
// them `mcp__leoprevent__<name>`).
//
// Deliberately UNPREFIXED here: repeating "leoprevent" inside a name the client already
// qualifies gives an agent `mcp__leoprevent__leoprevent_stats` to reason about, which is
// noise in every tool listing and in every transcript.
const (
	ToolStats    = "security_stats"
	ToolFindings = "security_findings"
	ToolRepos    = "repository_security"
	ToolRule     = "rule_detail"
)

// scopeProperty is shared by every tool, so `me` and `team` mean the same thing everywhere
// and an agent that learned the parameter on one tool can use it on the next.
//
// ⚠️ THE DESCRIPTION HAS TO SAY WHAT `team` COSTS, because the agent is choosing on the
// developer's behalf and cannot be asked. Defaulting to `me` in the schema is not enough on
// its own: a model reading an undescribed enum picks the value that answers the broadest
// question, which here means quietly putting a colleague's activity into a transcript when
// the developer asked about their own week.
func scopeProperty() map[string]any {
	return map[string]any{
		"type": "string",
		"enum": []string{"me", "team"},
		"description": "Whose activity to report. 'me' (the default) is the signed-in " +
			"developer's own turns. 'team' covers everyone on the account and is refused " +
			"unless this developer is an admin on it, so only use it when the developer " +
			"has asked about the team rather than about themselves.",
	}
}

func daysProperty() map[string]any {
	return map[string]any{
		"type":        "integer",
		"description": "How many days back to read. Defaults to 30, capped at 365.",
	}
}

func limitProperty(what string) map[string]any {
	return map[string]any{
		"type":        "integer",
		"description": "Maximum " + what + " to return. Defaults to 20, capped at 100.",
	}
}

// Tools is the compiled-in tool set.
//
// ⚠️ EVERY DESCRIPTION SAYS WHAT THE NUMBERS MEAN, not just what the tool fetches. These are
// the product's own metric definitions reaching a model that will paraphrase them to a
// developer — so `docs/ui.md`'s vocabulary is used verbatim (new vs existing, caught vs
// prevented) and the one distinction that is easiest to overclaim is stated outright:
// LeoPrevent force-fixes flaws the agent just wrote and only SURFACES ones that were already
// there. An agent told merely "returns flaw counts" reports the total as prevented, which is
// the exact overclaim CLAUDE.md forbids on every surface we control.
func Tools() []Tool {
	return []Tool{
		{
			Name: ToolStats,
			Description: "LeoPrevent security review figures for a period: turns, reviews, " +
				"how many flaws were caught, and how many were fixed. Use this when the " +
				"developer asks how their security review activity is going, what LeoPrevent " +
				"has caught recently, or how many issues they are introducing. " +
				"Flaws split two ways: NEW flaws were written during the turn and LeoPrevent " +
				"made the agent fix them before the turn could finish; EXISTING flaws were " +
				"already in the code and are only reported to the developer, never edited " +
				"automatically. Do not describe existing flaws as prevented or fixed unless " +
				"the response says they were.",
			Schema: object(map[string]any{
				"scope": scopeProperty(),
				"days":  daysProperty(),
			}),
		},
		{
			Name: ToolFindings,
			Description: "Individual security flaws LeoPrevent has flagged recently, newest " +
				"first: the rule, its severity, the file and line, whether the flaw was new " +
				"or already existing, and whether it ended up fixed. Use this to answer 'what " +
				"has LeoPrevent found', to triage what is still open, or to check one " +
				"repository or one rule. Each row is one logged occurrence, so the same flaw " +
				"can appear more than once if it was flagged on more than one turn.",
			Schema: object(map[string]any{
				"scope": scopeProperty(),
				"days":  daysProperty(),
				"repo": map[string]any{
					"type": "string",
					"description": "Restrict to one repository. Accepts the short name " +
						"('leoprevent') or the full 'host/org/repo'.",
				},
				"rule": map[string]any{
					"type":        "string",
					"description": "Restrict to one rule id, for example 'ssrf' or 'sql-injection'.",
				},
				"limit": limitProperty("findings"),
			}),
		},
		{
			Name: ToolRepos,
			Description: "Per-repository security review figures: how many diffs were " +
				"reviewed, how many flaws were caught in each, the share of reviews that " +
				"found something, and a letter grade. Use this to compare repositories or to " +
				"answer how a particular codebase is doing. A grade of 'n/a' means too few " +
				"reviews to grade yet, not a bad grade.",
			Schema: object(map[string]any{
				"scope": scopeProperty(),
				"days":  daysProperty(),
				"limit": limitProperty("repositories"),
			}),
		},
		{
			Name: ToolRule,
			Description: "Which security rules have been firing, with each rule's id, title, " +
				"severity, how often it fired, and where. Use this to answer which kinds of " +
				"flaw keep coming up, or to look one rule up by id. This returns a rule's " +
				"NAME and SEVERITY only; the rule's detection criteria are not available to " +
				"the agent and must not be guessed at.",
			Schema: object(map[string]any{
				"scope": scopeProperty(),
				"days":  daysProperty(),
				"rule": map[string]any{
					"type":        "string",
					"description": "Look up one rule id, for example 'ssrf'. Omit for all rules that fired.",
				},
				"limit": limitProperty("rules"),
			}),
		},
	}
}

// object wraps properties in the JSON Schema envelope a tool's `inputSchema` needs.
//
// No `required` list on any tool: every parameter has a server-side default, and a required
// argument is one an agent can get wrong in a way that costs a round trip to discover.
func object(props map[string]any) map[string]any {
	return map[string]any{
		"type":       "object",
		"properties": props,
	}
}

// Dispatch builds the Handler that answers a call by reading the dashboard.
//
// ⚠️ THE BODY IS RETURNED VERBATIM. Reformatting it here would put a second description of
// every figure inside the shipped, open-source client — the one place a change to the
// dashboard's shape could not reach — so the JSON the dashboard computed is what the agent
// reads. See the note on package `stats` for the longer version.
func Dispatch(r Reader) Handler {
	return func(name string, args map[string]any) (string, error) {
		q := stats.Query{
			Scope: str(args, "scope"),
			Days:  intOf(args, "days"),
			Limit: intOf(args, "limit"),
			Repo:  str(args, "repo"),
			Rule:  str(args, "rule"),
		}

		switch name {
		case ToolStats:
			q.View = "stats"
		case ToolFindings:
			q.View = "findings"
		case ToolRepos:
			q.View = "repos"
		case ToolRule:
			q.View = "rules"
		default:
			// Unreachable — Server.callTool checks the name against the advertised set first
			// — but a handler that silently answered the wrong view would be worse than one
			// that says so.
			return "", fmt.Errorf("unknown tool: %s", name)
		}

		body, err := r.Read(q)
		if err != nil {
			return "", err
		}
		return string(body), nil
	}
}

func str(args map[string]any, key string) string {
	if v, ok := args[key].(string); ok {
		return v
	}
	return ""
}

// intOf reads a numeric argument.
//
// JSON numbers decode into `float64`, so that is the case that actually fires; the string
// case is there because models do send `"days": "30"` and the alternative is a silent
// fallback to the default with nothing anywhere saying the argument was ignored. Anything
// unparseable returns 0, which the API reads as "use the default".
func intOf(args map[string]any, key string) int {
	switch v := args[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case string:
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil {
			return n
		}
	}
	return 0
}
