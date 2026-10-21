package review

import (
	"strings"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

func reset(t *testing.T) {
	t.Helper()
	SetMessaging(nil)
	t.Cleanup(func() { SetMessaging(nil) })
}

func TestNoServerMessagingKeepsTheDefaults(t *testing.T) {
	reset(t)
	if got := Banner(2); got != "🛡️ LeoPrevent · security review (2 files)" {
		t.Fatalf("banner %q", got)
	}
	if got := Banner(1); !strings.HasSuffix(got, "(1 file)") {
		t.Fatalf("banner %q", got)
	}
	if !strings.HasPrefix(FirstCleanNotice(), "🛡️ LeoPrevent · found no new") {
		t.Fatalf("first clean %q", FirstCleanNotice())
	}
}

func TestServerMessagingReplacesEveryField(t *testing.T) {
	reset(t)
	SetMessaging(&wire.Messaging{
		Mark:        "🦁",
		Banner:      "{mark} Leo · {count} {files} checked",
		BylineLabel: "review notice",
		FirstClean:  "All clear.",
		WrapIntro:   "Open with this:",
		WrapOutro:   "Carry on.",
	})
	if got := Banner(3); got != "🦁 Leo · 3 files checked" {
		t.Fatalf("banner %q", got)
	}
	if got := FirstCleanNotice(); got != "🦁 LeoPrevent · all clear." {
		t.Fatalf("first clean %q", got)
	}
	ctx := contextWrap("> hi")
	for _, want := range []string{"Open with this:", "> 🦁 **LeoPrevent** · review notice", "Carry on."} {
		if !strings.Contains(ctx, want) {
			t.Errorf("wrap missing %q in %q", want, ctx)
		}
	}
	if !strings.HasPrefix(BuildFindingsPrompt([]wire.Finding{{Rule: "r", Location: "a.go:1", Issue: "i", Fix: "f"}}, ""), "🦁 LeoPrevent: security review") {
		t.Fatal("prompt prefix does not carry the server mark")
	}
}

func TestBadServerFieldsFallBackIndividually(t *testing.T) {
	reset(t)
	SetMessaging(&wire.Messaging{
		Mark:        "hello",                    // letters
		Banner:      "{mark} {bogus} ({count})", // unknown placeholder
		BylineLabel: strings.Repeat("x", 500),   // too long
		FirstClean:  "Kept.",                    // fine
		WrapIntro:   "ok\x1b[31m",               // control char stripped, not rejected
	})
	if Mark() != "🛡️" {
		t.Errorf("mark %q", Mark())
	}
	if got := Banner(2); got != "🛡️ LeoPrevent · security review (2 files)" {
		t.Errorf("banner %q", got)
	}
	if bylineLabel() != defaultBylineLabel {
		t.Errorf("byline %q", bylineLabel())
	}
	if firstCleanSentence() != "Kept." {
		t.Errorf("first clean %q", firstCleanSentence())
	}
	if strings.ContainsRune(wrapIntro(), 0x1b) {
		t.Errorf("control char survived: %q", wrapIntro())
	}
}

func TestMarkSanitiser(t *testing.T) {
	for _, ok := range []string{"🛡️", "🦁", "👨‍💻"} {
		if cleanMark(ok) == "" {
			t.Errorf("%q rejected", ok)
		}
	}
	for _, bad := range []string{"", "a", "1", "> ", "🛡️ x", "‮🛡️", "🛡️\n🛡️", strings.Repeat("🛡", 9), "**"} {
		if cleanMark(bad) != "" {
			t.Errorf("%q accepted", bad)
		}
	}
}
