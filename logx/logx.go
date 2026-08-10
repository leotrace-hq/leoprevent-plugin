// Package logx configures structured logging (slog) to a rotating-friendly log
// file for both deployables. It is fail-safe by design: if the log file cannot
// be opened it falls back to stderr and never errors — logging must never break
// the fail-open Stop hook.
//
// Log destination, in order of precedence:
//   - $LEOPREVENT_LOG (explicit file path), else the per-component default:
//   - server: <cwd>/server.log — the server runs from server/, so this sits next
//     to it in one known spot and is gitignored (*.log).
//   - client: <os.UserConfigDir>/leoprevent/client.log — the client is a shipped
//     hook that runs in whatever project the agent is in, so it logs to a stable
//     per-user dir, NEVER the cwd (which would litter the dev's repos).
//   - stderr (last-resort fallback)
//
// Level is INFO unless $LEOPREVENT_DEBUG is set (then DEBUG). The server also
// tees to stdout so operators see activity live; the client logs to the file
// only (its stdout is reserved for the re-wake JSON).
//
// The two destinations carry DIFFERENT formats by design: the file is always
// machine-parseable JSON (it is the gitignored, grep/jq-able record), while the
// console tee is a compact, colored, human-readable line — operators read it,
// nothing parses it. Color is emitted only when stdout is a real terminal (same
// rule as the startup banner), so a redirected/captured stdout stays clean.
package logx

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// Setup points slog.Default at the resolved log file and returns a closer to be
// deferred by main. component labels every line ("client" | "server"); when
// alsoConsole is true, lines are ALSO written to stdout in a colored
// human-readable format (the file always stays JSON).
func Setup(component string, alsoConsole bool) func() {
	return SetupWith(component, alsoConsole, nil)
}

// SetupWith is Setup plus OPTIONAL extra handlers fanned the same records — the
// seam the server uses to mirror its logs into MongoDB now that the Fly volume is
// gone and the file destination is ephemeral.
//
// The extra handlers live OUTSIDE this package on purpose. logx is imported by the
// PLUGIN CLIENT (plugin/client/…), which ships as a binary to developer machines;
// importing the Mongo driver here would link it into every plugin build for a
// server-only feature. Callers pass handlers in instead, so the dependency stays in
// the server's own tree.
//
// Each extra handler decides its own level (a Mongo mirror wants WARN+, not the
// file's INFO), so they are NOT filtered by the file level here — multiHandler asks
// each child. A nil or empty extras slice is exactly Setup's behaviour.
//
// The returned closer runs the extras' own closers BEFORE the file's, so a buffered
// mirror flushes while the process is still alive.
func SetupWith(component string, alsoConsole bool, extras []slog.Handler) func() {
	file, closer := openWriter(component)
	level := slog.LevelInfo
	if os.Getenv("LEOPREVENT_DEBUG") != "" {
		level = slog.LevelDebug
	}

	var h slog.Handler = slog.NewJSONHandler(file, &slog.HandlerOptions{Level: level})
	// Tee to stdout only when asked AND the file actually opened (openWriter
	// falls back to stderr — teeing then would double-write the same stream).
	if alsoConsole && file != os.Stderr {
		h = multiHandler{h, newConsoleHandler(os.Stdout, level)}
	}
	if len(extras) > 0 {
		combined := multiHandler{h}
		for _, e := range extras {
			if e != nil {
				combined = append(combined, e)
			}
		}
		h = combined
	}
	slog.SetDefault(slog.New(h).With("component", component))
	return closer
}

// AuditBodies reports whether code-body logging is enabled via $LEOPREVENT_AUDIT.
// It is the single source of truth for the body-logging gate, read by BOTH
// deployables so they agree: the server (whether the review-event log records the
// diff / finding bodies, which its operator dashboard then shows) and the plugin/client
// (whether its cloud-tier client.log records the diff / findings detail). Metadata
// is logged regardless; only code bodies are gated.
//
// DEFAULT ON — bodies are logged unless explicitly disabled with
// LEOPREVENT_AUDIT set to a falsey value (0|false|off|no). NOTE: on the SERVER this
// means customer code (diffs + finding text) is persisted to review-events.jsonl by
// default; the server prints a loud startup banner stating ON/OFF so it is never a
// silent state. Disable with LEOPREVENT_AUDIT=0 for metadata-only.
func AuditBodies() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("LEOPREVENT_AUDIT"))) {
	case "0", "false", "off", "no":
		return false
	default:
		return true
	}
}

// AuditCleanBodies reports whether code bodies should be retained on CLEAN reviews
// too (the dev's prompt + the diff). Default OFF: a clean verdict normally drops
// the prompt + code — we keep someone's code only when a vuln was caught (the
// privacy-preserving default). Set LEOPREVENT_AUDIT_CLEAN truthy to also log
// clean-review code. Only takes effect when AuditBodies() is already on.
func AuditCleanBodies() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("LEOPREVENT_AUDIT_CLEAN"))) {
	case "1", "true", "on", "yes":
		return true
	default:
		return false
	}
}

// logPath resolves the log file path: $LEOPREVENT_LOG, else
// <user config dir>/leoprevent/<component>.log, else "" (→ stderr fallback).
func logPath(component string) string {
	if p := os.Getenv("LEOPREVENT_LOG"); p != "" {
		return p
	}
	// Server: cwd-relative (it runs from server/) → next to the server, gitignored.
	// Client: per-user config dir, stable across whatever project the hook runs in.
	if component == "server" {
		return component + ".log"
	}
	if dir, err := os.UserConfigDir(); err == nil {
		return filepath.Join(dir, "leoprevent", component+".log")
	}
	return ""
}

// multiHandler fans one record out to several slog handlers (here: JSON→file +
// colored text→stdout). Each child decides its own format and level.
type multiHandler []slog.Handler

func (m multiHandler) Enabled(ctx context.Context, l slog.Level) bool {
	for _, h := range m {
		if h.Enabled(ctx, l) {
			return true
		}
	}
	return false
}

// Handle fans the record to EVERY enabled child, even if an earlier one failed.
// A short-circuit here would let one bad destination silence the others — with a
// Mongo mirror in the chain (see SetupWith) a network blip would otherwise stop
// the record reaching the file and the console tee, which are the destinations an
// operator is actually watching. The first error is remembered and returned so the
// failure is still reported, but only after everyone has had the record.
func (m multiHandler) Handle(ctx context.Context, r slog.Record) error {
	var first error
	for _, h := range m {
		if h.Enabled(ctx, r.Level) {
			if err := h.Handle(ctx, r); err != nil && first == nil {
				first = err
			}
		}
	}
	return first
}

func (m multiHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	out := make(multiHandler, len(m))
	for i, h := range m {
		out[i] = h.WithAttrs(attrs)
	}
	return out
}

func (m multiHandler) WithGroup(name string) slog.Handler {
	out := make(multiHandler, len(m))
	for i, h := range m {
		out[i] = h.WithGroup(name)
	}
	return out
}

// consoleHandler renders a compact, human-readable line — "HH:MM:SS LEVEL msg
// key=val …" — for operators watching the server live. The level word is
// ANSI-colored only when the destination is a real terminal (color is decided
// once at construction). The "component" attr is dropped: on the console it is
// always the same and adds noise; the JSON file keeps it.
type consoleHandler struct {
	out   io.Writer
	level slog.Level
	color bool
	attrs string // preformatted " key=val" carried in from WithAttrs
}

func newConsoleHandler(out *os.File, level slog.Level) *consoleHandler {
	color := false
	if fi, err := out.Stat(); err == nil && fi.Mode()&os.ModeCharDevice != 0 {
		color = true
	}
	return &consoleHandler{out: out, level: level, color: color}
}

func (c *consoleHandler) Enabled(_ context.Context, l slog.Level) bool { return l >= c.level }

func (c *consoleHandler) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder
	b.WriteString(r.Time.Format("15:04:05"))
	b.WriteByte(' ')
	b.WriteString(c.levelTag(r.Level))
	b.WriteByte(' ')
	b.WriteString(r.Message)
	b.WriteString(c.attrs)
	r.Attrs(func(a slog.Attr) bool {
		writeAttr(&b, a)
		return true
	})
	b.WriteByte('\n')
	_, err := io.WriteString(c.out, b.String())
	return err
}

func (c *consoleHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	var b strings.Builder
	b.WriteString(c.attrs)
	for _, a := range attrs {
		if a.Key == "component" {
			continue // redundant on the console; kept in the JSON file
		}
		writeAttr(&b, a)
	}
	nc := *c
	nc.attrs = b.String()
	return &nc
}

// WithGroup is a no-op: the server logs flat key/vals (no groups). Keeping it
// simple avoids a prefix-tracking scheme nothing here exercises.
func (c *consoleHandler) WithGroup(string) slog.Handler { return c }

func writeAttr(b *strings.Builder, a slog.Attr) {
	b.WriteByte(' ')
	b.WriteString(a.Key)
	b.WriteByte('=')
	b.WriteString(escapeControl(a.Value.String()))
}

// escapeControl renders newlines / carriage returns / other control bytes as escape
// sequences so an attacker-influenced attr value (e.g. the git developer or repo from
// a /review request) cannot forge extra lines in the human-readable console tee. The
// JSON file handler already escapes these; this brings the stdout tee to parity.
func escapeControl(s string) string {
	if strings.IndexFunc(s, func(r rune) bool { return r < 0x20 }) < 0 {
		return s // common case: nothing to escape
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20:
			fmt.Fprintf(&b, `\x%02x`, r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// levelTag returns the 5-char level label, ANSI-colored when color is on.
func (c *consoleHandler) levelTag(l slog.Level) string {
	var label, code string
	switch {
	case l >= slog.LevelError:
		label, code = "ERROR", "\x1b[1;31m" // bold red
	case l >= slog.LevelWarn:
		label, code = "WARN ", "\x1b[1;33m" // bold yellow
	case l >= slog.LevelInfo:
		label, code = "INFO ", "\x1b[1;32m" // bold green
	default:
		label, code = "DEBUG", "\x1b[1;36m" // bold cyan
	}
	if !c.color {
		return label
	}
	return code + label + "\x1b[0m"
}

func openWriter(component string) (io.Writer, func()) {
	path := logPath(component)
	if path == "" {
		return os.Stderr, func() {}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return os.Stderr, func() {}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return os.Stderr, func() {}
	}
	return f, func() { _ = f.Close() }
}
