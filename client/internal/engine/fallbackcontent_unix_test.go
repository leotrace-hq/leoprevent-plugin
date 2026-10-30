//go:build unix

package engine

import (
	"log/slog"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
)

// A FIFO at a changed path must not hang the Stop hook: opening one blocks until a writer
// appears, so it has to be refused before the open.
func TestFallbackContentDoesNotHangOnAFIFO(t *testing.T) {
	// Arrange
	project := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(project, "worker.py"), 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	changes := []transcript.Change{{FilePath: "worker.py", AddedText: "x = 1"}}
	done := make(chan []transcript.Change, 1)

	// Act
	go func() { done <- withFileContent(changes, project, slog.Default()) }()

	// Assert
	select {
	case got := <-done:
		if len(got) != 1 || got[0].FullContent != "" {
			t.Fatalf("got %+v, want the change kept without content", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("withFileContent blocked opening a FIFO")
	}
}

// The swap case: a path that passed the Lstat and became a FIFO before the open. The open
// fallbackContent uses must return at once, and what it opened must fail the regular-file
// check.
func TestFallbackOpenDoesNotBlockOnAFIFO(t *testing.T) {
	// Arrange
	project := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(project, "worker.py"), 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	root, err := os.OpenRoot(project)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	done := make(chan os.FileMode, 1)

	// Act
	go func() {
		f, err := root.OpenFile("worker.py", os.O_RDONLY|openNonblock, 0)
		if err != nil {
			done <- 0
			return
		}
		defer f.Close()
		fi, _ := f.Stat()
		done <- fi.Mode()
	}()

	// Assert
	select {
	case mode := <-done:
		if mode.IsRegular() {
			t.Fatalf("FIFO opened as a regular file: %v", mode)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the fallback's open blocked on a FIFO")
	}
}
