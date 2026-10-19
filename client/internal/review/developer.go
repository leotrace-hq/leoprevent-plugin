package review

import "strings"

// Relaying a notice meant for the developer through the agent's reply, on surfaces that don't
// show a Stop-hook systemMessage (the Claude desktop app and claude.ai). LEO-620, decision D59.
// The first is the dependency check's notice; the first-clean notice already works this way.
//
// ⚠️ PLACEHOLDER WORDING, WRITTEN HERE. The review's own relay text comes from the server
// (WrapIntro, WrapOutro in Messaging); these become server-overridable the same way.

// DeveloperMarkdown quotes a notice as the markdown block the agent is asked to print, line by
// line, so it reads as LeoPrevent's and not the agent's.
func DeveloperMarkdown(notice string) string {
	lines := strings.Split(strings.TrimRight(notice, "\n"), "\n")
	for i, l := range lines {
		if strings.TrimSpace(l) == "" {
			lines[i] = ">"
			continue
		}
		lines[i] = "> " + l
	}
	return strings.Join(lines, "\n")
}

// DeveloperRelayPrompt is the wake reason when a developer notice is the only thing the Stop has
// to say: print it and stop.
func DeveloperRelayPrompt(markdown string) string {
	return "LeoPrevent has a notice for the developer. It is information for them, not something to act on. " +
		"Reply with exactly this markdown and nothing else, then end your turn without doing any other work:\n\n" +
		markdown + "\n"
}

// WithFirstClean appends a developer notice to the first-clean relay, so one reply carries both.
func WithFirstClean(firstCleanPrompt, markdown string) string {
	return strings.TrimRight(firstCleanPrompt, "\n") + "\n\n" + markdown + "\n"
}

// DeveloperAddendum is appended to a review's wake: the review's own instructions are left as
// they are, and the agent is also asked to print the notice.
func DeveloperAddendum(markdown string) string {
	return "In your reply, right after LeoPrevent's review block, include exactly this markdown. " +
		"It is information for the developer from LeoPrevent's dependency check, not something to act on:\n\n" +
		markdown + "\n"
}

// WithoutRelayed removes the markdown the agent was asked to print from its reply, so text that
// was only relayed for the developer is never read as the agent's own account (it goes to
// /outcome, which must not see the dependency check). An exact copy is removed; so is one whose
// lines match once surrounding spaces are ignored, since agents re-flow whitespace. A paraphrase
// can't be found, and is left as it is (the judge isn't changed for SCA, so nothing tells it to
// disregard one).
func WithoutRelayed(reply, markdown string) string {
	if strings.TrimSpace(markdown) == "" {
		return reply
	}
	if i := strings.Index(reply, markdown); i >= 0 {
		return joinAround(reply[:i], reply[i+len(markdown):])
	}
	want := nonEmptyTrimmed(markdown)
	lines := strings.Split(reply, "\n")
	for start := 0; start < len(lines); start++ {
		k, end := 0, start
		for end < len(lines) && k < len(want) {
			t := strings.TrimSpace(lines[end])
			if t == "" && k > 0 {
				end++
				continue
			}
			if t != want[k] {
				break
			}
			k++
			end++
		}
		if k == len(want) {
			return joinAround(strings.Join(lines[:start], "\n"), strings.Join(lines[end:], "\n"))
		}
	}
	return reply
}

func nonEmptyTrimmed(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(l); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func joinAround(before, after string) string {
	b, a := strings.TrimSpace(before), strings.TrimSpace(after)
	switch {
	case b == "":
		return a
	case a == "":
		return b
	}
	return b + "\n\n" + a
}
