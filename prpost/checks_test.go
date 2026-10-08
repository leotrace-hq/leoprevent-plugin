package prpost

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"
)

const headSHA = "0123456789abcdef0123456789abcdef01234567"

type checkCall struct {
	Method string
	Path   string
	Body   map[string]any
}

// checksAPI is a fake Checks API. existing is what the list endpoint returns; status, when set,
// is answered to every request instead.
func checksAPI(t *testing.T, existing []map[string]any, status int, patchStatus int) (Client, *[]checkCall) {
	t.Helper()
	var mu sync.Mutex
	var calls []checkCall
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		mu.Lock()
		calls = append(calls, checkCall{Method: r.Method, Path: r.URL.Path, Body: body})
		mu.Unlock()
		if status != 0 {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"message":"Resource not accessible by integration"}`))
			return
		}
		switch {
		case r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]any{"check_runs": existing})
		case r.Method == http.MethodPatch && patchStatus != 0:
			w.WriteHeader(patchStatus)
		case r.Method == http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":77}`))
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	t.Cleanup(srv.Close)
	return Client{Token: "t", Owner: "acme", Repo: "api", API: srv.URL}, &calls
}

func TestStartCheckCreatesARunningRowOnTheHeadCommit(t *testing.T) {
	// Arrange
	c, calls := checksAPI(t, nil, 0, 0)

	// Act
	id, err := c.StartCheck(headSHA)

	// Assert
	if err != nil || id != 77 {
		t.Fatalf("StartCheck = %d, %v; want 77, nil", id, err)
	}
	last := (*calls)[len(*calls)-1]
	if last.Method != http.MethodPost || last.Path != "/repos/acme/api/check-runs" {
		t.Fatalf("created with %s %s", last.Method, last.Path)
	}
	if last.Body["name"] != CheckName || last.Body["head_sha"] != headSHA ||
		last.Body["status"] != "in_progress" || last.Body["external_id"] != checkExternalID {
		t.Fatalf("create payload = %v", last.Body)
	}
}

func TestARerunOfTheSameCommitUpdatesItsRowRatherThanStackingOne(t *testing.T) {
	// Arrange
	c, calls := checksAPI(t, []map[string]any{{"id": 5, "external_id": checkExternalID}}, 0, 0)

	// Act
	id, err := c.StartCheck(headSHA)

	// Assert
	if err != nil || id != 5 {
		t.Fatalf("StartCheck = %d, %v; want the existing run 5", id, err)
	}
	for _, cl := range *calls {
		if cl.Method == http.MethodPost {
			t.Fatal("a second row was created for a commit that already has one")
		}
	}
}

func TestARowSomebodyElseNamedLeoPreventIsNotReused(t *testing.T) {
	// A customer's own Actions job can carry the same name; only our external id is ours.
	// Arrange
	c, calls := checksAPI(t, []map[string]any{{"id": 9, "external_id": ""}}, 0, 0)

	// Act
	id, _ := c.StartCheck(headSHA)

	// Assert
	if id != 77 {
		t.Fatalf("reused a run this lane did not create (id %d)", id)
	}
	for _, cl := range *calls {
		if cl.Method == http.MethodPatch {
			t.Fatal("patched somebody else's check run")
		}
	}
}

func TestAnExistingRowThatCannotBeUpdatedFallsBackToANewOne(t *testing.T) {
	// Arrange
	c, _ := checksAPI(t, []map[string]any{{"id": 5, "external_id": checkExternalID}}, 0, http.StatusUnprocessableEntity)

	// Act
	id, err := c.StartCheck(headSHA)

	// Assert
	if err != nil || id != 77 {
		t.Fatalf("StartCheck = %d, %v; a review with no row is worse than two rows", id, err)
	}
}

func TestAnInstallationWithoutChecksWriteIsReportedAsSuch(t *testing.T) {
	// Arrange
	c, _ := checksAPI(t, nil, http.StatusForbidden, 0)

	// Act
	_, err := c.StartCheck(headSHA)

	// Assert
	if !errors.Is(err, ErrChecksNotPermitted) {
		t.Fatalf("err = %v, want ErrChecksNotPermitted", err)
	}
}

func TestFinishCheckCompletesWithTheVerdict(t *testing.T) {
	// Arrange
	c, calls := checksAPI(t, nil, 0, 0)

	// Act
	err := c.FinishCheck(77, ConclusionFailure, "2 findings reported", "summary")

	// Assert
	if err != nil {
		t.Fatalf("FinishCheck: %v", err)
	}
	last := (*calls)[len(*calls)-1]
	if last.Method != http.MethodPatch || last.Path != "/repos/acme/api/check-runs/77" {
		t.Fatalf("finished with %s %s", last.Method, last.Path)
	}
	out, _ := last.Body["output"].(map[string]any)
	if last.Body["status"] != "completed" || last.Body["conclusion"] != "failure" || out["title"] != "2 findings reported" {
		t.Fatalf("finish payload = %v", last.Body)
	}
}

func TestFinishCheckRefusesAnUnknownConclusion(t *testing.T) {
	// action_required and cancelled ask a reader to do something, and are not ours to claim.
	// Arrange
	c, calls := checksAPI(t, nil, 0, 0)

	// Act
	err := c.FinishCheck(77, Conclusion("action_required"), "x", "y")

	// Assert
	if err == nil || len(*calls) != 0 {
		t.Fatalf("err = %v, calls = %d", err, len(*calls))
	}
}

func TestStartCheckRefusesAnythingButACommitSHA(t *testing.T) {
	// Arrange
	c, calls := checksAPI(t, nil, 0, 0)

	// Act
	_, err := c.StartCheck("../../evil")

	// Assert
	if err == nil || len(*calls) != 0 {
		t.Fatalf("err = %v, calls = %d", err, len(*calls))
	}
}

func TestClipKeepsUTF8Intact(t *testing.T) {
	// Arrange
	s := strings.Repeat("é", 200)

	// Act
	got := clip(s, 255)

	// Assert
	if len(got) > 255 || !strings.HasSuffix(got, "…") || !utf8.ValidString(got) {
		t.Fatalf("clip = %q (%d bytes)", got, len(got))
	}
}
