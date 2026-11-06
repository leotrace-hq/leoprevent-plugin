package main

import "testing"

// An agent that doesn't fill in ${CLAUDE_SESSION_ID} (Copilot, Cursor, an older Claude Code)
// passes it literally, or through a shell as nothing: either is no session.
func TestScaSession(t *testing.T) {
	for in, want := range map[string]string{
		"0f1e2d3c-aaaa-bbbb-cccc-111122223333": "0f1e2d3c-aaaa-bbbb-cccc-111122223333",
		"${CLAUDE_SESSION_ID}":                 "",
		"":                                     "",
		"../../etc":                            "",
	} {
		if got := scaSession(in); got != want {
			t.Errorf("scaSession(%q) = %q, want %q", in, got, want)
		}
	}
}
