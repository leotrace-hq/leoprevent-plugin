package imports

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
	"github.com/leotrace-hq/leoprevent-plugin/limits"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

// Writes the A/B fixture the SERVER's live replay (slice_ab_replay_test.go) needs:
// the same turns, resolved once with whole-file context and once sliced, so the two
// arms differ in nothing but this change. It lives here because the slicer does, and
// the server module cannot import it (client/internal is private to the client).
//
// It is a GENERATOR, not a check — skipped unless a destination is named:
//
//	LEOPREVENT_WRITE_AB_FIXTURE=../../../server/internal/api/testdata/slice_ab_fixture.jsonl \
//	  go test -run TestWriteSliceABFixture ./client/internal/imports/
//
// Regenerate it when the slicer changes; the committed copy is what makes the live
// replay reproducible run to run.
func TestWriteSliceABFixture(t *testing.T) {
	dest := os.Getenv("LEOPREVENT_WRITE_AB_FIXTURE")
	if dest == "" {
		t.Skip("set LEOPREVENT_WRITE_AB_FIXTURE=<path> to regenerate the live A/B fixture")
	}
	root := measureRoot(t)
	turns, _ := measureTurns(t, root, measureCorpus(t, root))
	if len(turns) == 0 {
		t.Skip("no turn in this repo resolves imported context")
	}

	var out []abCase
	budget := 220 << 10 // keep the committed fixture reviewable
	for _, ch := range turns {
		sliceBodies, skipTypeOnlyImports = false, false
		whole := Resolve(root, []transcript.Change{ch})
		sliceBodies, skipTypeOnlyImports = true, true
		sliced := Resolve(root, []transcript.Change{ch})
		if len(whole) == 0 || len(sliced) == 0 {
			continue
		}
		w, sl := ctxBytes(whole), ctxBytes(sliced)
		// Keep cases where the arms differ enough to read through model jitter, and
		// keep the committed fixture small: a case that barely changes costs two live
		// model calls to demonstrate nothing.
		if w-sl < 5000 || float64(w-sl)/float64(w) < 0.30 {
			continue
		}
		if budget-w < 0 {
			continue
		}
		budget -= w
		out = append(out, abCase{
			Name:          ch.FilePath,
			Changes:       []wire.ChangedFile{{Path: ch.FilePath, AddedText: ch.AddedText, FullContent: ch.FullContent}},
			ContextWhole:  whole,
			ContextSliced: sliced,
		})
		if len(out) >= 5 {
			break
		}
	}
	sliceBodies, skipTypeOnlyImports = true, true
	if len(out) == 0 {
		t.Skip("no turn showed a large enough difference to replay")
	}

	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, c := range out {
		line, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	if err := os.WriteFile(dest, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %d cases to %s (%d B)", len(out), dest, b.Len())
	for _, c := range out {
		t.Logf("  %-52s context %7d B -> %7d B", c.Name, ctxBytes(c.ContextWhole), ctxBytes(c.ContextSliced))
	}
	_ = limits.MaxContextFileBytes
}

// abCase mirrors the struct the server-side replay decodes.
type abCase struct {
	Name          string             `json:"name"`
	Changes       []wire.ChangedFile `json:"changes"`
	ContextWhole  []wire.ContextFile `json:"context_whole"`
	ContextSliced []wire.ContextFile `json:"context_sliced"`
}

func ctxBytes(cf []wire.ContextFile) int {
	n := 0
	for _, c := range cf {
		n += len(c.Content)
	}
	return n
}
