package review

import (
	"strings"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/limits"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

// The ask and the parser are a contract between a prompt and a regex-ish reader, and
// a drift between them fails SILENTLY: the block simply stops matching and the field
// is empty on every turn, with no error anywhere. So parse the ask's own literal
// example and require it to read back as a clean empty answer.
func TestParseAssumptionsAcceptsTheAskAsWritten(t *testing.T) {
	got, reported := ParseAssumptions("Here is what I did.\n\n" + AssumptionsAsk)
	if !reported {
		t.Fatal("the ask's own example block did not parse — the prompt and the parser have drifted")
	}
	if len(got) != 0 {
		t.Fatalf("the example block is empty by design, got %q", got)
	}
}

// The whole point of the ask riding the re-wake is that it reaches the agent, so the
// blocked-turn prompt must actually carry it.
func TestFindingsPromptCarriesTheAssumptionsAsk(t *testing.T) {
	p := BuildFindingsPrompt([]wire.Finding{{
		Rule: "ssrf", Name: "Server-Side Request Forgery",
		Location: "app.py:12", Issue: "url comes from the request", Fix: "resolve and deny private ranges",
	}})
	if !strings.Contains(p, AssumptionsAsk) {
		t.Fatal("the cloud re-wake prompt does not carry the assumptions ask")
	}
	// It must come last: the prompt's actual job is the fix, and an unrelated request
	// competing with that instruction is how the fix gets half-done.
	if !strings.HasSuffix(p, AssumptionsAsk) {
		t.Fatal("the assumptions ask must be the LAST thing in the prompt, after every finding")
	}
}

// "answered and had none" and "never answered" are different facts about whether the
// ask is working at all, and a slice alone cannot tell them apart.
func TestParseAssumptionsSeparatesEmptyFromUnanswered(t *testing.T) {
	got, reported := ParseAssumptions("I fixed it.\n" + assumptionsOpen + "\n" + assumptionsClose)
	if !reported || len(got) != 0 {
		t.Fatalf("an empty block is an ANSWER of none: got %q reported=%v", got, reported)
	}

	got, reported = ParseAssumptions("I fixed it and said nothing about assumptions.")
	if reported || got != nil {
		t.Fatalf("no block means the agent never answered: got %q reported=%v", got, reported)
	}
}

func TestParseAssumptions(t *testing.T) {
	tests := []struct {
		name     string
		reply    string
		want     []string
		reported bool
	}{{
		name:     "plain list",
		reply:    assumptionsOpen + "\n- the caller is authenticated\n- the URL is internal\n" + assumptionsClose,
		want:     []string{"the caller is authenticated", "the URL is internal"},
		reported: true,
	}, {
		// Agents reformat lists freely between replies; the marker is never part of
		// the assumption itself.
		name:     "mixed bullet styles",
		reply:    assumptionsOpen + "\n* starred\n• dotted\n1. numbered\n2) parenthesised\nbare\n" + assumptionsClose,
		want:     []string{"starred", "dotted", "numbered", "parenthesised", "bare"},
		reported: true,
	}, {
		// The ask says to send an empty block, but agents reach for a sentinel word
		// anyway. "none" is an empty answer, not an assumption named "none".
		name:     "none sentinel is an empty answer",
		reply:    assumptionsOpen + "\n- None.\n" + assumptionsClose,
		want:     nil,
		reported: true,
	}, {
		// An agent that restates the instruction mid-reply leaves an extra block
		// behind; the answer is the final one.
		name: "last block wins over an echoed instruction",
		reply: "You asked me to end with " + assumptionsOpen + "\n" + assumptionsClose + "\n" +
			"Done.\n" + assumptionsOpen + "\n- the real answer\n" + assumptionsClose,
		want:     []string{"the real answer"},
		reported: true,
	}, {
		// An unterminated block would otherwise swallow the rest of the reply as
		// "assumptions", which is worse than recording no answer.
		name:     "unopened close tag",
		reply:    "some prose " + assumptionsClose,
		want:     nil,
		reported: false,
	}, {
		name:     "unterminated block",
		reply:    assumptionsOpen + "\n- half a thought and then the reply was cut",
		want:     nil,
		reported: false,
	}, {
		name:     "blank lines inside the block are skipped",
		reply:    assumptionsOpen + "\n\n- one\n   \n- two\n\n" + assumptionsClose,
		want:     []string{"one", "two"},
		reported: true,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, reported := ParseAssumptions(tc.reply)
			if reported != tc.reported {
				t.Fatalf("reported = %v, want %v", reported, tc.reported)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("entry %d = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

// This text is model-authored and egresses, so its length is the agent's to choose
// unless we bound it. (The server re-applies the same caps at ingest; a cap that
// lives only in the shipped client is not a guard.)
func TestParseAssumptionsIsBounded(t *testing.T) {
	var b strings.Builder
	b.WriteString(assumptionsOpen + "\n")
	for i := 0; i < limits.MaxAssumptions*3; i++ {
		b.WriteString("- " + strings.Repeat("x", limits.MaxAssumptionBytes*2) + "\n")
	}
	b.WriteString(assumptionsClose)

	got, reported := ParseAssumptions(b.String())
	if !reported {
		t.Fatal("reported = false, want true")
	}
	if len(got) != limits.MaxAssumptions {
		t.Fatalf("kept %d entries, want the cap of %d", len(got), limits.MaxAssumptions)
	}
	for i, a := range got {
		if len(a) > limits.MaxAssumptionBytes {
			t.Fatalf("entry %d is %d bytes, over the %d cap", i, len(a), limits.MaxAssumptionBytes)
		}
	}
}

// A multi-byte entry cut at the cap must never emit a broken rune.
func TestParseAssumptionsTruncatesOnRuneBoundaries(t *testing.T) {
	long := strings.Repeat("é", limits.MaxAssumptionBytes) // 2 bytes each, so well over the cap
	got, _ := ParseAssumptions(assumptionsOpen + "\n- " + long + "\n" + assumptionsClose)
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1", len(got))
	}
	if !strings.ContainsRune(got[0], 'é') || strings.ContainsRune(got[0], '�') {
		t.Fatalf("entry was cut mid-rune: %q", got[0])
	}
}
