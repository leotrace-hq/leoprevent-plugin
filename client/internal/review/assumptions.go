package review

import (
	"strings"
	"unicode/utf8"

	"github.com/leotrace-hq/leoprevent-plugin/limits"
)

// The ask and the parser live in ONE file on purpose: the block below is a contract
// between a prompt the model reads and a parser that reads the model back, and the
// two failing to agree is silent (a reworded ask simply yields nothing, on every
// turn, with no error anywhere). Change one, change the other, and re-run
// TestParseAssumptionsAcceptsTheAskAsWritten — it parses the literal example the ask
// shows, so a drift between them fails the build rather than the dataset.
//
// The ask itself is currently NOT SENT (LEO-113) — see AssumptionsAsk. The contract is
// maintained anyway: it is what makes re-enabling a one-line change rather than a
// re-derivation, and a drift introduced while nothing is asking would only surface as
// an empty dataset long after the fact.
const (
	assumptionsOpen  = "<leoprevent-assumptions>"
	assumptionsClose = "</leoprevent-assumptions>"
)

// AssumptionsAsk asks the agent to report the assumptions it made this turn.
//
// ⚠️ IT IS NOT SENT (LEO-113). BuildFindingsPrompt no longer appends it, so nothing
// asks and ParseAssumptions consequently reports `false` on every turn. The text and
// the parser are kept so re-enabling is one WriteString, and so the drift guard below
// keeps holding if that happens.
//
// WHY IT WAS REMOVED, since the original reasoning reads as sound and the ask would
// otherwise be re-added: it was priced as free because it rides a re-wake that already
// happens, needing no extra round trip, no tokens of its own and no second block. What
// that pricing left out is the developer's screen. A Stop hook's only channel to the
// agent is the injected re-wake message, and the only channel back is the agent's
// reply; both are rendered in the session, so the ask paragraph AND a ten-bullet answer
// block landed in the transcript on every blocked turn, directly beneath a security
// finding the developer was meant to be reading. Reported live as the loudest thing on
// screen after a block. There is no quieter variant: telling the agent to write the
// block to a file instead trades the noise for a Write/Bash permission prompt on every
// blocked turn, which interrupts harder and blocks the turn until answered.
//
// So the ask cannot be made invisible while the agent is the one answering it, and the
// data it collected has no consumer: nothing gates on it and no surface renders it.
// Re-enabling therefore needs a reason that outweighs the attention it spends, not just
// a wish for the dataset.
//
// If it IS re-enabled, three properties of the wording are load-bearing:
//
//   - It sits LAST, after every finding. The re-wake's job is to get the vulnerability
//     fixed; an unrelated request competing with that instruction is how the fix gets
//     half-done. It also states outright that it changes no code, so an agent cannot
//     read it as further work.
//   - The example block is shown EMPTY. A worked example with placeholder entries reads
//     back as real data if the agent echoes it verbatim, which would quietly seed the
//     dataset with our own text; an empty one degrades to an empty list instead. It
//     doubles as the "I made none" answer, so there is one shape to follow rather than
//     two, and no sentinel word to spell.
//   - It asks for the block at the END of the reply. The parser takes the LAST block,
//     so an agent that restates the instruction mid-reply cannot displace the answer.
//
// NO EM DASHES: this is the plugin's user-facing terminal output (see CLAUDE.md
// § Conventions).
const AssumptionsAsk = "Finally, a data-collection step that changes no code: list the assumptions you made while working on this turn, meaning anything you treated as true without verifying it. " +
	"For example: that a value is already validated upstream, that the caller is authenticated, that an input is trusted, that a config value is present.\n\n" +
	"End your reply with exactly this block, one assumption per line starting with \"- \", and nothing after it:\n\n" +
	assumptionsOpen + "\n" + assumptionsClose + "\n\n" +
	"Keep each assumption to one sentence. If you made none, send the block exactly as shown, with nothing between the tags.\n"

// ParseAssumptions extracts the reported assumptions from the agent's post-re-wake
// reply. reported is false when the agent never answered (no block in the reply);
// it is true with an empty list when the agent answered and had none. The caller
// must keep those apart — see wire.OutcomeRequest.AssumptionsReported.
//
// DETERMINISTIC, no model call: the whole point of asking in a fixed block is that
// reading it back costs nothing and cannot itself hallucinate. It is deliberately
// forgiving about the bullet style (agents reformat lists freely) and strict about
// the delimiters, since those are the only thing separating the answer from ordinary
// prose.
//
// Bounded here AND server-side (api.capAssumptions): this text is model-authored and
// egresses, so a cap that lives only in the shipped client is not a guard.
func ParseAssumptions(reply string) (assumptions []string, reported bool) {
	// LAST opening tag, then the FIRST close after it. An agent that restates the ask
	// earlier in its reply leaves an extra block behind; the answer is the final one.
	start := strings.LastIndex(reply, assumptionsOpen)
	if start < 0 {
		return nil, false
	}
	body := reply[start+len(assumptionsOpen):]
	end := strings.Index(body, assumptionsClose)
	if end < 0 {
		// Opened but never closed: a truncated or malformed reply. Treat it as no
		// answer rather than guessing where it ended — an unterminated block would
		// otherwise swallow whatever prose followed it as "assumptions".
		return nil, false
	}

	out := make([]string, 0, 4)
	for _, line := range strings.Split(body[:end], "\n") {
		item := strings.TrimSpace(stripBullet(line))
		if item == "" {
			continue
		}
		if len(out) >= limits.MaxAssumptions {
			break
		}
		out = append(out, capRunes(item, limits.MaxAssumptionBytes))
	}
	// Defensive: the ask says to send an empty block, but agents reach for a sentinel
	// word anyway. A lone "none" is an empty answer, not an assumption that the agent
	// made an assumption called "none".
	if len(out) == 1 && isNoneSentinel(out[0]) {
		out = out[:0]
	}
	return out, true
}

// stripBullet removes a leading list marker so "- foo", "* foo", "• foo" and "1. foo"
// all yield "foo". Agents reformat lists freely between replies, and the marker is
// never part of the assumption.
func stripBullet(line string) string {
	s := strings.TrimSpace(line)
	for _, m := range []string{"- ", "* ", "• ", "– "} {
		if rest, ok := strings.CutPrefix(s, m); ok {
			return rest
		}
	}
	// "1. foo" / "1) foo" — digits then a separator.
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i > 0 && i < len(s) && (s[i] == '.' || s[i] == ')') {
		return strings.TrimSpace(s[i+1:])
	}
	return s
}

// isNoneSentinel reports whether an entry is one of the ways an agent writes "I made
// no assumptions" instead of sending an empty block.
func isNoneSentinel(s string) bool {
	switch strings.ToLower(strings.Trim(s, " .")) {
	case "none", "n/a", "na", "no assumptions", "none.", "nothing":
		return true
	}
	return false
}

// capRunes truncates s to at most n bytes on a UTF-8 boundary, so a runaway entry is
// bounded without ever emitting a broken rune.
func capRunes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}
