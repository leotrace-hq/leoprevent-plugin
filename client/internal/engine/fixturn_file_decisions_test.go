package engine

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/agent/claude"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/outcome"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/scratch"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

func TestFixTurnDoesNotRepeatTurnDiscoveryDecisions(t *testing.T) {
	t.Cleanup(scratch.SetUserCacheDirForTest(t.TempDir()))
	session := "engine-fixturn-file-decisions"
	cwd := t.TempDir()
	x := filepath.Join(cwd, "x.py")
	secret := filepath.Join(cwd, ".env")
	tp := filepath.Join(t.TempDir(), "transcript.jsonl")
	// The original turn touches a protected file and code that causes a block.
	appendTranscript(t, tp,
		`{"type":"user","message":{"role":"user","content":"add a fetch helper"}}`,
		toolUse("Write", fmt.Sprintf(`{"file_path":%q,"content":"PRIVATE=dummy"}`, secret)),
		toolUse("Write", fmt.Sprintf(`{"file_path":%q,"content":"import requests\nresp = requests.get(url)"}`, x)),
	)
	r := &fakeReviewer{
		prompt:         "FIX THIS",
		pending:        &outcome.Pending{ReviewID: "rid-1", Findings: []wire.Finding{{Rule: "ssrf", Location: x + ":2"}}},
		snapshotBefore: true,
	}
	first := fmt.Sprintf(`{"stop_hook_active":false,"session_id":%q,"transcript_path":%q,"cwd":%q}`, session, tp, cwd)
	if _, out, _ := runWith(claude.New(), r, first); out == "" {
		t.Fatal("first review did not block")
	}
	if r.gotMeta.FileDecisions == nil {
		t.Fatal("original review lost its discovery manifest")
	}
	initial := r.gotMeta.FileDecisions.Clone()
	// The fix changes code, but never touches the secret again. Discovery still
	// sees the original Write because the transcript spans the whole user turn.
	appendTranscript(t, tp,
		`{"type":"user","message":{"role":"user","content":"Stop hook feedback:\nLeoPrevent: security review"}}`,
		toolUse("Edit", fmt.Sprintf(`{"file_path":%q,"old_string":"resp = requests.get(url)","new_string":"resp = safe_get(url)"}`, x)),
		toolUse("Write", fmt.Sprintf(`{"file_path":%q,"content":"import os\nos.system(cmd)"}`, filepath.Join(cwd, "y.py"))),
	)
	r.prompt, r.pending = "", nil
	second := fmt.Sprintf(`{"stop_hook_active":true,"session_id":%q,"transcript_path":%q,"cwd":%q,"last_assistant_message":"Fixed"}`, session, tp, cwd)
	runWith(claude.New(), r, second)
	if r.reviewCalls != 2 || r.gotMeta.RewakeOf != "rid-1" {
		t.Fatalf("did not exercise re-wake: calls=%d parent=%s", r.reviewCalls, r.gotMeta.RewakeOf)
	}
	if initial.Counts["discovery:secret"] != 1 {
		t.Fatalf("first manifest: %+v", initial)
	}
	if r.gotMeta.FileDecisions != nil {
		t.Fatalf("fix review inherited whole-turn discovery instead of leaving it unmeasured: %+v", r.gotMeta.FileDecisions)
	}
	if !r.shipped || r.shippedPending.ReviewID != "rid-1" {
		t.Fatal("fix outcome was not verified")
	}
	if len(r.gotChanges) != 2 {
		t.Fatalf("fix review changed its coverage: %+v", r.gotChanges)
	}
}
