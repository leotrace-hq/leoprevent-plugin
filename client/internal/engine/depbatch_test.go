package engine

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/apiclient"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/depcheck"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/notify"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

// freshSession is a session ID no earlier run has used: notify keeps its records in the scratch
// folder, which outlives a test run.
func freshSession(name string) string { return fmt.Sprintf("%s-%d", name, time.Now().UnixNano()) }

// batchChecker is the cloud reviewer's two dependency calls, faked: it records the batches and
// single requests it's sent, and answers a batch from answer, or fails it with err.
type batchChecker struct {
	batches []wire.DependenciesBatchRequest
	singles []wire.DependenciesRequest
	answer  func(wire.DependenciesBatchRequest) wire.DependenciesBatchResponse
	err     error
}

func (b *batchChecker) CheckDependencies(req wire.DependenciesRequest) (wire.DependenciesResponse, error) {
	b.singles = append(b.singles, req)
	return wire.DependenciesResponse{Ecosystem: req.Ecosystem}, nil
}

func (b *batchChecker) CheckDependencyBatch(req wire.DependenciesBatchRequest) (wire.DependenciesBatchResponse, error) {
	b.batches = append(b.batches, req)
	if b.err != nil {
		return wire.DependenciesBatchResponse{}, b.err
	}
	return b.answer(req), nil
}

// A batch is stamped as one request is: meta, trigger and scan once for the batch, and each file
// its baseline, what was already asked in it and its quiet. Each file's answer is gathered as one
// request's is, and a file's own failure is that file's error.
func TestADependencyBatchIsStampedAsOneRequestIs(t *testing.T) {
	// Arrange
	var _ depcheck.BatchChecker = stamped{}
	session := freshSession("batch-stamp")
	notify.Record(session, askKey("web/package-lock.json", "lodash@4.17.15"))
	offer := "🛡️ fix them?"
	rec := &batchChecker{answer: func(b wire.DependenciesBatchRequest) wire.DependenciesBatchResponse {
		web := wire.DependenciesResponse{Ecosystem: "npm", Messages: wire.DependencyMessages{AgentOffer: &offer, AgentOfferPackages: []string{"minimist@1.2.0"}}}
		return wire.DependenciesBatchResponse{Files: []wire.DependenciesFileResult{{DependenciesResponse: &web}, {Status: 503, Error: "the dependency check failed; nothing was checked"}}}
	}}
	meta := &wire.TurnMeta{Agent: "claude", Repo: "github.com/acme/web"}
	put := &askedKeys{}
	c := stamped{checker: rec, meta: meta, trigger: wire.DependencyTriggerScan, scanID: "s1", sessionID: session, put: put}

	// Act
	answers, err := c.CheckDependencyBatch([]wire.DependenciesRequest{
		{Ecosystem: "npm", Path: "web/package-lock.json"},
		{Ecosystem: "Go", Path: "go.mod"},
	})

	// Assert
	if err != nil {
		t.Fatal(err)
	}
	b := rec.batches[0]
	if b.Meta != meta || b.Trigger != "scan" || b.ScanID != "s1" || len(b.Files) != 2 {
		t.Fatalf("batch = %+v", b)
	}
	for _, f := range b.Files {
		if f.Meta != nil || f.Trigger != "" || f.ScanID != "" {
			t.Errorf("file %s carries the batch's fields: %+v", f.Path, f)
		}
	}
	if got := b.Files[0].Asked; len(got) != 1 || got[0] != "lodash@4.17.15" {
		t.Errorf("web's asked = %v", got)
	}
	if answers[0].Err != nil || answers[0].Response.Messages.AgentOffer == nil {
		t.Errorf("web answer = %+v", answers[0])
	}
	if answers[1].Err == nil {
		t.Error("go.mod's 503 is its own error")
	}
	if got := put.list(); len(got) != 1 || got[0] != askKey("web/package-lock.json", "minimist@1.2.0") {
		t.Errorf("offered is asked, as for one request: %v", got)
	}
	if len(rec.singles) != 0 {
		t.Errorf("single requests: %v", rec.singles)
	}
}

// An older server's 400 for the unknown "files" field is ErrNoBatches, remembered for the
// session so its later Stops don't ask; any other 400 is a plain failure, never a fallback.
func TestAnOlderServerIsAskedForBatchesOncePerSession(t *testing.T) {
	old := &batchChecker{err: &apiclient.StatusError{Path: "/dependencies", Status: 400,
		Body: `{"error":"invalid request body: json: unknown field \"files\""}`}}
	c := stamped{checker: old, trigger: wire.DependencyTriggerScan, sessionID: freshSession("batch-old-server")}
	reqs := []wire.DependenciesRequest{{Ecosystem: "npm", Path: "a"}, {Ecosystem: "npm", Path: "b"}}

	if _, err := c.CheckDependencyBatch(reqs); !errors.Is(err, depcheck.ErrNoBatches) {
		t.Fatalf("err = %v, want ErrNoBatches", err)
	}
	if _, err := c.CheckDependencyBatch(reqs); !errors.Is(err, depcheck.ErrNoBatches) || len(old.batches) != 1 {
		t.Errorf("err = %v after %d batches: the session asks once", err, len(old.batches))
	}

	other := &batchChecker{err: &apiclient.StatusError{Path: "/dependencies", Status: 400, Body: `{"error":"files is empty"}`}}
	c = stamped{checker: other, trigger: wire.DependencyTriggerScan, sessionID: freshSession("batch-new-server-400")}
	if _, err := c.CheckDependencyBatch(reqs); err == nil || errors.Is(err, depcheck.ErrNoBatches) {
		t.Errorf("a newer server's own 400 = %v, want a plain failure", err)
	}
}

// A batch's 404 is a server with no dependency check, for the session, as one request's is.
func TestABatch404IsNoDependencyCheck(t *testing.T) {
	session := freshSession("batch-404")
	none := &batchChecker{err: &apiclient.StatusError{Path: "/dependencies", Status: 404}}
	c := stamped{checker: none, trigger: wire.DependencyTriggerScan, sessionID: session}

	_, err := c.CheckDependencyBatch([]wire.DependenciesRequest{{Ecosystem: "npm"}, {Ecosystem: "npm"}})

	if !errors.Is(err, depcheck.ErrUnavailable) || !dependenciesUnavailable(session) {
		t.Errorf("err = %v, unavailable for the session %v", err, dependenciesUnavailable(session))
	}
}

// A checker that can't batch (a test double, a tier without it) is ErrNoBatches, so the check
// sends one file at a time.
func TestACheckerWithoutBatchesIsSentOneFileAtATime(t *testing.T) {
	c := stamped{checker: &recordingChecker{}, trigger: wire.DependencyTriggerScan}
	if _, err := c.CheckDependencyBatch([]wire.DependenciesRequest{{Ecosystem: "npm"}, {Ecosystem: "npm"}}); !errors.Is(err, depcheck.ErrNoBatches) {
		t.Errorf("err = %v", err)
	}
}
