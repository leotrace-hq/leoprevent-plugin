// Package receipts keeps bounded, best-effort measurement state between hook processes.
package receipts

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/scratch"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

// Slots are claimed with atomic mkdir, without locks or waits. The bound includes
// all server/account scopes and interrupted writes, not just this process's queue.
const MaxPending = 128
const maxRecordBytes = 8192

type record struct {
	Scope string                     `json:"scope"`
	Entry wire.ReviewReceiptEnvelope `json:"entry"`
}
type Pending struct {
	Entry wire.ReviewReceiptEnvelope
	name  string
	slot  string
}

// Scope never puts the credential or server URL on disk. Rotating either isolates
// the old queue, which expires rather than being attributed to a different account.
func Scope(server, credential string) string {
	sum := sha256.Sum256([]byte(server + "\x00" + credential))
	return hex.EncodeToString(sum[:])
}

func open() (*os.Root, error) {
	dir := scratch.Dir("review-receipts")
	if err := os.Mkdir(dir, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || (runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0) {
		return nil, errors.New("unsafe receipt directory")
	}
	return os.OpenRoot(dir)
}

func Save(scope string, e wire.ReviewReceiptEnvelope, now time.Time) error {
	if !wire.ValidReviewReceipt(e, now) || wire.EncodeReviewReceipts([]wire.ReviewReceiptEnvelope{e}) == "" {
		return errors.New("invalid receipt")
	}
	root, err := open()
	if err != nil {
		return err
	}
	defer root.Close()
	scan(root, scope, now) // also reclaims expired/corrupt slots
	b, err := json.Marshal(record{scope, e})
	if err != nil {
		return err
	}
	for i := 0; i < MaxPending; i++ {
		slot := fmt.Sprintf("%03d", i)
		if err = root.Mkdir(slot, 0700); err != nil {
			continue
		}
		name := slot + "/" + e.Receipt.ID + ".json"
		tmp := name + ".tmp"
		f, err := root.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			_ = root.Remove(slot)
			return err
		}
		_, err = f.Write(b)
		closeErr := f.Close()
		if err == nil {
			err = closeErr
		}
		if err == nil {
			err = root.Rename(tmp, name)
		}
		if err != nil {
			_ = root.Remove(tmp)
			_ = root.Remove(slot)
		}
		return err
	}
	return errors.New("receipt queue full")
}

func Batch(scope string, now time.Time) []Pending {
	root, err := open()
	if err != nil {
		return nil
	}
	defer root.Close()
	all := scan(root, scope, now)
	sort.Slice(all, func(i, j int) bool { return all[i].Entry.Receipt.CompletedAt.Before(all[j].Entry.Receipt.CompletedAt) })
	var batch []Pending
	var entries []wire.ReviewReceiptEnvelope
	for _, p := range all {
		if len(batch) == wire.MaxReceiptBatch {
			break
		}
		proposed := append(append([]wire.ReviewReceiptEnvelope(nil), entries...), p.Entry)
		if wire.EncodeReviewReceipts(proposed) == "" {
			break
		}
		entries = proposed
		batch = append(batch, p)
	}
	return batch
}

// Ack removes only the immutable files sent by this request. Concurrent sends may
// duplicate a receipt, but a late acknowledgment cannot delete a newer slot occupant.
func Ack(sent []Pending, acknowledged string) {
	if len(acknowledged) > wire.MaxReceiptBatch*25 {
		return
	}
	ids := map[string]bool{}
	for _, id := range strings.Split(acknowledged, ",") {
		ids[id] = true
	}
	root, err := open()
	if err != nil {
		return
	}
	defer root.Close()
	for _, p := range sent {
		if ids[p.Entry.Receipt.ID] {
			if root.Remove(p.name) == nil {
				_ = root.Remove(p.slot)
			}
		}
	}
}

func scan(root *os.Root, scope string, now time.Time) []Pending {
	var pending []Pending
	directory, err := root.Open(".")
	if err != nil {
		return nil
	}
	// Read only the bounded set of existing slots, rather than statting 128 missing
	// paths on every request. Keep disk reads bounded even if the cache is corrupt.
	slots, err := directory.ReadDir(MaxPending + 1)
	_ = directory.Close()
	if (err != nil && err != io.EOF) || len(slots) > MaxPending {
		return nil
	}
	for _, entry := range slots {
		slot := entry.Name()
		n, err := strconv.Atoi(slot)
		if err != nil || n < 0 || n >= MaxPending || slot != fmt.Sprintf("%03d", n) {
			continue
		}
		info, err := root.Lstat(slot)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			continue
		}
		dir, err := root.Open(slot)
		if err != nil {
			continue
		}
		entries, err := dir.ReadDir(3)
		_ = dir.Close()
		if err != nil && err != io.EOF {
			continue
		}
		for _, entry := range entries {
			name := slot + "/" + entry.Name()
			if entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
				continue
			}
			if !strings.HasSuffix(entry.Name(), ".json") {
				if now.Sub(info.ModTime()) > wire.ReceiptMaxAge {
					_ = root.Remove(name)
				}
				continue
			}
			f, err := root.Open(name)
			if err != nil {
				continue
			}
			b, err := io.ReadAll(io.LimitReader(f, maxRecordBytes+1))
			_ = f.Close()
			var r record
			if err != nil || len(b) > maxRecordBytes || json.Unmarshal(b, &r) != nil || entry.Name() != r.Entry.Receipt.ID+".json" || !wire.ValidReviewReceipt(r.Entry, now) || wire.EncodeReviewReceipts([]wire.ReviewReceiptEnvelope{r.Entry}) == "" {
				_ = root.Remove(name)
				_ = root.Remove(slot)
				continue
			}
			if r.Scope == scope {
				pending = append(pending, Pending{r.Entry, name, slot})
			}
		}
		// Empty or abandoned slots can be reclaimed. Never remove a just-claimed slot
		// while another process is preparing its write.
		if now.Sub(info.ModTime()) > wire.ReceiptMaxAge {
			_ = root.Remove(slot)
		}
	}
	return pending
}
