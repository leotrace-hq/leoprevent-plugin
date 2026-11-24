package depcheck

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

// batchingServer is a BatchChecker over a single-file Checker: each batch is answered file by
// file, as the server does (LEO-792). It records what it was sent, and can fail a file, a batch,
// or say it takes no batches.
type batchingServer struct {
	inner   Checker
	batches *[][]string // each batch's paths
	singles *[]string   // each single request's path
	// failPath fails that file alone; batchErr fails every batch; noBatches answers ErrNoBatches.
	failPath  string
	batchErr  error
	noBatches bool
}

func newBatchingServer(inner Checker) batchingServer {
	return batchingServer{inner: inner, batches: &[][]string{}, singles: &[]string{}}
}

func (b batchingServer) CheckDependencies(req wire.DependenciesRequest) (wire.DependenciesResponse, error) {
	*b.singles = append(*b.singles, req.Path)
	if req.Path == b.failPath {
		return wire.DependenciesResponse{}, errors.New("status 503")
	}
	return b.inner.CheckDependencies(req)
}

func (b batchingServer) CheckDependencyBatch(reqs []wire.DependenciesRequest) ([]BatchAnswer, error) {
	if b.noBatches {
		return nil, ErrNoBatches
	}
	var paths []string
	for _, r := range reqs {
		paths = append(paths, r.Path)
	}
	*b.batches = append(*b.batches, paths)
	if b.batchErr != nil {
		return nil, b.batchErr
	}
	out := make([]BatchAnswer, len(reqs))
	for i, r := range reqs {
		if r.Path == b.failPath {
			out[i].Err = errors.New("dependency check: status 503")
			continue
		}
		out[i].Response, out[i].Err = b.inner.CheckDependencies(r)
	}
	return out, nil
}

// failingOne is a single-file Checker that fails one path, for the answer a batch must match.
type failingOne struct {
	inner Checker
	path  string
}

func (f failingOne) CheckDependencies(req wire.DependenciesRequest) (wire.DependenciesResponse, error) {
	if req.Path == f.path {
		return wire.DependenciesResponse{}, errors.New("status 503")
	}
	return f.inner.CheckDependencies(req)
}

func sizes(batches [][]string) string {
	var s []string
	for _, b := range batches {
		s = append(s, fmt.Sprint(len(b)))
	}
	return strings.Join(s, ",")
}

// A server that takes batches gets the scan's files 10 at a time, in order, and the scan says
// exactly what it says when each file is sent on its own.
func TestABatchingServerGetsTheScanTenFilesAtATime(t *testing.T) {
	// Arrange
	srv := briefServer{severity: map[string]string{"lodash": "high"}}
	some := func(i int) map[string]string {
		if i%3 == 0 {
			return map[string]string{"lodash": "4.17.15"}
		}
		return map[string]string{"left-pad": "1.3.0"}
	}
	root, w := scanFiles(t, 23, some)
	batching := newBatchingServer(srv)

	// Act
	wantText, wantMD, wantAgent, wantOffer := Scan(w, nil, root, nil, srv, quiet)
	text, md, agent, offer := Scan(w, nil, root, nil, batching, quiet)

	// Assert
	if text != wantText || md != wantMD || agent != wantAgent || offer != wantOffer {
		t.Errorf("batched scan differs from one file per request:\n%s\n---\n%s", text, wantText)
	}
	if got := sizes(*batching.batches); got != "10,10,3" || len(*batching.singles) != 0 {
		t.Fatalf("batches %s, singles %d: want 10,10,3 and none alone", got, len(*batching.singles))
	}
	var order []string
	for _, b := range *batching.batches {
		order = append(order, b...)
	}
	for i, p := range order {
		if want := fmt.Sprintf("a%d/package-lock.json", i); p != want {
			t.Fatalf("file %d sent as %s, want %s: the files' order is kept", i, p, want)
		}
	}
}

// A server older than batches gets one file per request, from the first batch on, and the scan
// says the same.
func TestAServerWithoutBatchesGetsOneFileAtATime(t *testing.T) {
	srv := briefServer{severity: map[string]string{"lodash": "high"}}
	root, w := scanFiles(t, 12, func(int) map[string]string { return map[string]string{"lodash": "4.17.15"} })
	old := newBatchingServer(srv)
	old.noBatches = true

	wantText, _, _, wantOffer := Scan(w, nil, root, nil, srv, quiet)
	text, _, _, offer := Scan(w, nil, root, nil, old, quiet)

	if text != wantText || offer != wantOffer {
		t.Errorf("fallback scan differs:\n%s\n---\n%s", text, wantText)
	}
	if len(*old.singles) != 12 {
		t.Errorf("%d single requests, want all 12", len(*old.singles))
	}
}

// A check with one request sends it on its own, as before batches: a turn's check of one file
// doesn't change.
func TestOneRequestIsNeverBatched(t *testing.T) {
	srv := briefServer{severity: map[string]string{"lodash": "high"}}
	root, w := scanFiles(t, 1, func(int) map[string]string { return map[string]string{"lodash": "4.17.15"} })
	b := newBatchingServer(srv)

	Scan(w, nil, root, nil, b, quiet)

	if len(*b.batches) != 0 || len(*b.singles) != 1 {
		t.Errorf("batches %v singles %v, want the one file alone", *b.batches, *b.singles)
	}
}

// A file that fails inside a batch is that file not checked, exactly as when it fails on its own;
// the rest of its batch is answered.
func TestAFileThatFailsInABatchIsNotCheckedAlone(t *testing.T) {
	srv := briefServer{severity: map[string]string{"lodash": "high"}}
	root, w := scanFiles(t, 3, func(int) map[string]string { return map[string]string{"lodash": "4.17.15"} })
	b := newBatchingServer(srv)
	b.failPath = "a1/package-lock.json"

	wantText, _, _, wantOffer := Scan(w, nil, root, nil, failingOne{srv, b.failPath}, quiet)
	text, _, _, offer := Scan(w, nil, root, nil, b, quiet)

	if text != wantText || offer != wantOffer {
		t.Errorf("batch with a failed file differs from it failing alone:\n%s\n---\n%s", text, wantText)
	}
	if !strings.Contains(text, "a0/package-lock.json") || !strings.Contains(text, "a2/package-lock.json") {
		t.Errorf("the rest of the batch is answered:\n%s", text)
	}
}

// A batch that fails as a whole leaves every file in it not checked, and the other batches answered.
func TestABatchThatFailsLeavesItsFilesNotChecked(t *testing.T) {
	srv := briefServer{severity: map[string]string{"lodash": "high"}}
	root, w := scanFiles(t, 12, func(int) map[string]string { return map[string]string{"lodash": "4.17.15"} })
	b := newBatchingServer(srv)
	b.batchErr = errors.New("status 503")

	text, _, _, _ := Scan(w, nil, root, nil, b, quiet)

	if sizes(*b.batches) != "10,2" {
		t.Errorf("batches %s, want 10,2: a failed batch doesn't stop the next", sizes(*b.batches))
	}
	if !strings.Contains(text, "none of the 12 dependency files could be checked") {
		t.Errorf("every file is reported as not checked:\n%s", text)
	}
}

// A batch answered with no dependency check (a 404) says nothing at all, as one file does.
func TestABatchWithNoDependencyCheckSaysNothing(t *testing.T) {
	srv := briefServer{severity: map[string]string{"lodash": "high"}}
	root, w := scanFiles(t, 3, func(int) map[string]string { return map[string]string{"lodash": "4.17.15"} })
	b := newBatchingServer(srv)
	b.batchErr = fmt.Errorf("%w: status 404", ErrUnavailable)

	text, md, agent, offer := Scan(w, nil, root, nil, b, quiet)

	if text != "" || md != "" || agent != "" || offer != "" {
		t.Errorf("a server with no dependency check is never mentioned: %q %q %q %q", text, md, agent, offer)
	}
}
