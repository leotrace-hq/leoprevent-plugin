package logx

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSetupWritesToLogFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.log")
	t.Setenv("LEOPREVENT_LOG", path)

	closeLog := Setup("client", false)
	slog.Info("hello", "k", "v")
	closeLog()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("log file not written: %v", err)
	}
	s := string(data)
	if !strings.Contains(s, `"msg":"hello"`) || !strings.Contains(s, `"component":"client"`) {
		t.Errorf("log line missing expected fields: %s", s)
	}
}

func TestLogPathPrecedence(t *testing.T) {
	// $LEOPREVENT_LOG wins for any component.
	t.Setenv("LEOPREVENT_LOG", "/tmp/explicit.log")
	if got := logPath("server"); got != "/tmp/explicit.log" {
		t.Errorf("env should win, got %q", got)
	}
	t.Setenv("LEOPREVENT_LOG", "")
	// Server defaults to a cwd-relative file (it runs from server/; gitignored).
	if got := logPath("server"); got != "server.log" {
		t.Errorf("server default should be cwd-relative server.log, got %q", got)
	}
	// Client defaults to the stable per-user config dir (never the cwd).
	if got := logPath("client"); got == "" || !strings.HasSuffix(got, filepath.Join("leoprevent", "client.log")) {
		t.Errorf("client default path unexpected: %q", got)
	}
}

// TestAuditBodiesGate: AuditBodies is the single body-logging switch read by BOTH
// deployables. It defaults ON — pin it: empty/unset → on; 0/false/off/no → off;
// any other value → on.
func TestAuditBodiesGate(t *testing.T) {
	// DEFAULT ON: unset/empty → bodies logged.
	t.Setenv("LEOPREVENT_AUDIT", "")
	if !AuditBodies() {
		t.Error("AuditBodies must DEFAULT ON when LEOPREVENT_AUDIT is empty/unset")
	}
	// Explicit falsey values → OFF.
	for _, off := range []string{"0", "false", "off", "no", "OFF", " no "} {
		t.Setenv("LEOPREVENT_AUDIT", off)
		if AuditBodies() {
			t.Errorf("AuditBodies must be false for LEOPREVENT_AUDIT=%q", off)
		}
	}
	// Any other value → ON.
	t.Setenv("LEOPREVENT_AUDIT", "1")
	if !AuditBodies() {
		t.Error("AuditBodies must be true for LEOPREVENT_AUDIT=1")
	}
}

// failingHandler always errors, standing in for a Mongo mirror whose network is down.
type failingHandler struct{ handled int }

func (h *failingHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *failingHandler) Handle(context.Context, slog.Record) error {
	h.handled++
	return errors.New("mirror unavailable")
}
func (h *failingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *failingHandler) WithGroup(string) slog.Handler      { return h }

// TestSetupWithFanoutSurvivesAFailingExtra pins the multiHandler fix: Handle must
// deliver the record to EVERY child even when one fails. Before the fix it returned on
// the first error, so a failing Mongo mirror ordered ahead of the file would silence the
// file and the console tee — the destinations an operator actually watches.
func TestSetupWithFanoutSurvivesAFailingExtra(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.log")
	t.Setenv("LEOPREVENT_LOG", path)

	bad := &failingHandler{}
	// Put the failing handler FIRST in the chain to prove ordering doesn't matter.
	h := multiHandler{bad, slog.NewJSONHandler(mustCreate(t, path), nil)}
	logger := slog.New(h)
	logger.Error("event lost", "review_id", "rev_1")

	if bad.handled != 1 {
		t.Errorf("failing handler saw %d records, want 1", bad.handled)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	if !strings.Contains(string(data), `"msg":"event lost"`) {
		t.Errorf("a failing extra handler suppressed the file write: %q", string(data))
	}
}

// TestSetupWithMirrorsToExtraHandler covers the seam itself: an extra handler passed to
// SetupWith receives the same records as the file.
func TestSetupWithMirrorsToExtraHandler(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.log")
	t.Setenv("LEOPREVENT_LOG", path)

	spy := &countingHandler{}
	closeLog := SetupWith("server", false, []slog.Handler{spy})
	slog.Warn("insert failed")
	closeLog()

	if spy.handled != 1 {
		t.Errorf("extra handler saw %d records, want 1", spy.handled)
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), `"msg":"insert failed"`) {
		t.Errorf("file destination lost the record: %q", string(data))
	}
}

// TestSetupWithNilExtrasMatchesSetup guards the compatibility promise: a nil/empty
// extras slice must behave exactly like the original Setup.
func TestSetupWithNilExtrasMatchesSetup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.log")
	t.Setenv("LEOPREVENT_LOG", path)

	closeLog := SetupWith("server", false, nil)
	slog.Info("plain")
	closeLog()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	if !strings.Contains(string(data), `"msg":"plain"`) {
		t.Errorf("nil extras broke the file destination: %q", string(data))
	}
}

type countingHandler struct{ handled int }

func (h *countingHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *countingHandler) Handle(context.Context, slog.Record) error {
	h.handled++
	return nil
}
func (h *countingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *countingHandler) WithGroup(string) slog.Handler      { return h }

func mustCreate(t *testing.T, path string) *os.File {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

// With audit-body logging on by default, the log holds code diffs and prompts —
// a world-readable file would quietly disclose them on a shared machine.
func TestLogFileIsOwnerOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permission bits")
	}
	dir := t.TempDir()
	t.Setenv("LEOPREVENT_LOG", filepath.Join(dir, "sub", "client.log"))
	w, closeFn := openWriter("client")
	defer closeFn()
	if _, err := fmt.Fprintln(w, "x"); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(dir, "sub", "client.log"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("log file mode = %o, want 0600 (audit bodies land here)", perm)
	}
	di, err := os.Stat(filepath.Join(dir, "sub"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := di.Mode().Perm(); perm != 0o700 {
		t.Errorf("log dir mode = %o, want 0700", perm)
	}
}
