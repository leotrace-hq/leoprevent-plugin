package receipts

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/scratch"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

func entry(n int, now time.Time) wire.ReviewReceiptEnvelope {
	return wire.ReviewReceiptEnvelope{Repo: "github.com/acme/app", Receipt: wire.ReviewReceipt{ID: fmt.Sprintf("%024x", n), ReviewIDs: []string{"abcdef0123456789abcdef01"}, ElapsedMs: 42, CompletedAt: now}}
}
func isolate(t *testing.T) { t.Helper(); t.Cleanup(scratch.SetUserCacheDirForTest(t.TempDir())) }

func TestQueueSurvivesRestartAndScopesAccounts(t *testing.T) {
	isolate(t)
	now := time.Now()
	scope := Scope("https://one", "key-a")
	if err := Save(scope, entry(1, now), now); err != nil {
		t.Fatal(err)
	}
	if len(Batch(Scope("https://one", "key-b"), now)) != 0 || len(Batch(Scope("https://two", "key-a"), now)) != 0 {
		t.Fatal("queue crossed account or server")
	}
	sent := Batch(scope, now)
	if len(sent) != 1 {
		t.Fatal("saved entry lost")
	}
	info, err := os.Stat(filepath.Join(scratch.Dir("review-receipts"), sent[0].name))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatal("receipt is not private")
	}
	Ack(sent, "ffffffffffffffffffffffff")
	if len(Batch(scope, now)) != 1 {
		t.Fatal("unrelated ack deleted receipt")
	}
	Ack(sent, sent[0].Entry.Receipt.ID)
	if len(Batch(scope, now)) != 0 {
		t.Fatal("ack did not clear receipt")
	}
	if err := Save(scope, entry(2, now), now); err != nil {
		t.Fatal(err)
	}
	Ack(sent, sent[0].Entry.Receipt.ID) // repeated ACK after slot reuse
	if got := Batch(scope, now); len(got) != 1 || got[0].Entry.Receipt.ID != entry(2, now).Receipt.ID {
		t.Fatal("late ack deleted newer occupant")
	}
}

func TestQueueBoundExpiryAndConcurrency(t *testing.T) {
	isolate(t)
	now := time.Now()
	scope := Scope("https://one", "key")
	var wg sync.WaitGroup
	for i := 0; i < MaxPending+16; i++ {
		wg.Add(1)
		go func(i int) { defer wg.Done(); _ = Save(scope, entry(i, now), now) }(i)
	}
	wg.Wait()
	if err := Save(scope, entry(999, now), now); err == nil {
		t.Fatal("queue exceeded cap")
	}
	files, err := os.ReadDir(scratch.Dir("review-receipts"))
	if err != nil || len(files) != MaxPending {
		t.Fatalf("slots=%d err=%v", len(files), err)
	}
	batch := Batch(scope, now)
	if len(batch) != wire.MaxReceiptBatch {
		t.Fatal("batch limit")
	}
	entries := make([]wire.ReviewReceiptEnvelope, 0, len(batch))
	for _, p := range batch {
		entries = append(entries, p.Entry)
	}
	if h := wire.EncodeReviewReceipts(entries); h == "" || len(h) > wire.MaxReceiptHeaderBytes {
		t.Fatal("header bound")
	}
	later := now.Add(wire.ReceiptMaxAge + time.Second)
	if len(Batch(scope, later)) != 0 {
		t.Fatal("expired receipt sent")
	}
	if err := Save(scope, entry(1000, later), later); err != nil {
		t.Fatalf("expired queue not reclaimed: %v", err)
	}
}

func TestQueueRefusesUnsafeStorageAndSkipsCorruption(t *testing.T) {
	isolate(t)
	now := time.Now()
	scope := "scope"
	dir := scratch.Dir("review-receipts")
	outside := t.TempDir()
	if err := os.Symlink(outside, dir); err != nil {
		t.Skip(err)
	}
	if err := Save(scope, entry(1, now), now); err == nil {
		t.Fatal("followed queue symlink")
	}
	if len(Batch(scope, now)) != 0 {
		t.Fatal("unsafe queue read")
	}
	_ = os.Remove(dir)
	if err := Save(scope, entry(2, now), now); err != nil {
		t.Fatal(err)
	}
	p := Batch(scope, now)[0]
	if err := os.WriteFile(filepath.Join(dir, p.name), []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if len(Batch(scope, now)) != 0 {
		t.Fatal("corrupt receipt sent")
	}
	if err := Save(scope, entry(3, now), now); err != nil {
		t.Fatal(err)
	}
}

func TestQueueProcessWriter(t *testing.T) {
	dir := os.Getenv("LEOPREVENT_RECEIPT_TEST_DIR")
	if dir == "" {
		t.Skip("subprocess helper")
	}
	restore := scratch.SetUserCacheDirForTest(dir)
	defer restore()
	id, err := strconv.Atoi(os.Getenv("LEOPREVENT_RECEIPT_TEST_ID"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := Save("process", entry(id, now), now); err != nil {
		t.Fatal(err)
	}
}

func TestReceiptsPersistAcrossConcurrentHookProcesses(t *testing.T) {
	dir := t.TempDir()
	t.Cleanup(scratch.SetUserCacheDirForTest(dir))
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cmd := exec.Command(os.Args[0], "-test.run=^TestQueueProcessWriter$")
			cmd.Env = append(os.Environ(), "LEOPREVENT_RECEIPT_TEST_DIR="+dir, "LEOPREVENT_RECEIPT_TEST_ID="+strconv.Itoa(i))
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Errorf("writer: %v %s", err, out)
			}
		}(i)
	}
	wg.Wait()
	if got := Batch("process", time.Now()); len(got) != 4 {
		t.Fatalf("processes saved %d receipts", len(got))
	}
}
