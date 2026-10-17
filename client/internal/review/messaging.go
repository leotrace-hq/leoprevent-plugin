package review

import (
	"strconv"
	"strings"
	"sync"
	"unicode"

	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

// The compiled-in wording of every server-controllable notice. Each is what the client
// printed before wire.ReviewResponse.Messaging existed, apart from the mark itself, and is
// what an empty or rejected server field falls back to. Change wording on the SERVER; these
// exist so an old server, an unreachable one and a rejected value all still read correctly.
const (
	defaultMark        = "🛡️"
	defaultBanner      = "{mark} LeoPrevent · security review ({count} {files})"
	defaultBylineLabel = "automated security review, not part of your request"
	defaultFirstClean  = "Found no new or pre-existing flaws. You will only see LeoPrevent again when it finds something."
	defaultWrapIntro   = "Begin your reply with exactly this markdown, before anything else:"
	defaultWrapOutro   = "Then continue with the developer's request as normal, reporting the review result and any changes you made."
)

const (
	maxMarkRunes     = 8
	maxTemplateRunes = 200
	maxWrapRunes     = 600
)

// active is the sanitised server messaging for THIS process. The hook is one short-lived
// process per Stop, so a package-level value set when the /review response arrives is
// visible to every notice composed after it without threading a parameter through the agent
// seam. Notices composed before or without a response (skip notices, login, set-license)
// read the zero value and so the defaults.
var active struct {
	sync.RWMutex
	m wire.Messaging
}

// SetMessaging records the server's messaging after sanitising each field independently;
// a field that fails is dropped to its default. Nil clears it.
func SetMessaging(m *wire.Messaging) {
	var clean wire.Messaging
	if m != nil {
		clean = wire.Messaging{
			Mark:        cleanMark(m.Mark),
			Banner:      cleanTemplate(m.Banner),
			BylineLabel: cleanLine(m.BylineLabel, maxTemplateRunes),
			FirstClean:  cleanLine(m.FirstClean, maxTemplateRunes),
			WrapIntro:   cleanParagraph(m.WrapIntro),
			WrapOutro:   cleanParagraph(m.WrapOutro),
		}
	}
	active.Lock()
	active.m = clean
	active.Unlock()
}

func current() wire.Messaging {
	active.RLock()
	defer active.RUnlock()
	return active.m
}

func pick(server, fallback string) string {
	if server != "" {
		return server
	}
	return fallback
}

// Mark is the emoji that leads every LeoPrevent message.
func Mark() string { return pick(current().Mark, defaultMark) }

func bylineLabel() string { return pick(current().BylineLabel, defaultBylineLabel) }
func wrapIntro() string   { return pick(current().WrapIntro, defaultWrapIntro) }
func wrapOutro() string   { return pick(current().WrapOutro, defaultWrapOutro) }

// firstCleanSentence is the first-clean sentence, capitalised, for the relay block.
func firstCleanSentence() string { return pick(current().FirstClean, defaultFirstClean) }

// expand fills a template's placeholders. It returns ok=false on any other {placeholder}.
func expand(tmpl string, vals map[string]string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(tmpl); {
		if tmpl[i] != '{' {
			b.WriteByte(tmpl[i])
			i++
			continue
		}
		end := strings.IndexByte(tmpl[i:], '}')
		if end < 0 {
			return "", false
		}
		v, known := vals[tmpl[i+1:i+end]]
		if !known {
			return "", false
		}
		b.WriteString(v)
		i += end + 1
	}
	return b.String(), true
}

// cleanMark accepts only a short run of symbol characters: no letters, digits, whitespace,
// ASCII punctuation or controls, so a mark cannot smuggle markup or a second sentence into a
// line every notice begins with. The zero-width joiner and variation selectors that compose
// emoji are allowed; bidi controls are not.
func cleanMark(s string) string {
	s = strings.TrimSpace(s)
	runes := []rune(s)
	if len(runes) == 0 || len(runes) > maxMarkRunes {
		return ""
	}
	for _, r := range runes {
		switch {
		case r == 0x200D, r >= 0xFE00 && r <= 0xFE0F:
			continue
		case r < 0x80, unicode.IsLetter(r), unicode.IsNumber(r), unicode.IsSpace(r),
			unicode.IsControl(r), unicode.Is(unicode.Cf, r):
			return ""
		}
	}
	return s
}

// cleanLine is one bounded line: breaks collapsed, controls dropped. Empty on overflow, since
// a truncated sentence is worse than the default.
func cleanLine(s string, limit int) string {
	s = strings.Join(strings.Fields(strings.Map(dropControl, s)), " ")
	if len([]rune(s)) > limit {
		return ""
	}
	return s
}

// cleanTemplate is cleanLine that also requires every placeholder to be a known one.
func cleanTemplate(s string) string {
	s = cleanLine(s, maxTemplateRunes)
	if s == "" {
		return ""
	}
	if _, ok := expand(s, map[string]string{"mark": "", "count": "", "files": ""}); !ok {
		return ""
	}
	return s
}

// cleanParagraph keeps line breaks (these are instruction paragraphs) but drops controls and
// bounds the length.
func cleanParagraph(s string) string {
	s = strings.TrimSpace(strings.Map(func(r rune) rune {
		if r == '\n' {
			return r
		}
		return dropControl(r)
	}, s))
	if len([]rune(s)) > maxWrapRunes {
		return ""
	}
	return s
}

func dropControl(r rune) rune {
	if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) && r != 0x200D {
		return -1
	}
	return r
}

// bannerText renders the console banner for n files.
func bannerText(n int) string {
	noun := "files"
	if n == 1 {
		noun = "file"
	}
	vals := map[string]string{"mark": Mark(), "count": strconv.Itoa(n), "files": noun}
	tmpl := pick(current().Banner, defaultBanner)
	if out, ok := expand(tmpl, vals); ok {
		return out
	}
	out, _ := expand(defaultBanner, vals)
	return out
}

// FirstCleanNotice is the one-time notice on the first clean review.
func FirstCleanNotice() string {
	s := firstCleanSentence()
	return Mark() + " LeoPrevent · " + strings.ToLower(s[:1]) + s[1:]
}

// firstCleanLine is FirstCleanNotice's sentence without its prefix, for the relayed block.
func firstCleanLine() string { return firstCleanSentence() }
