package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/apiclient"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

func TestSweepNoticeIsTheServers(
	t *testing.T,
) {
	// Arrange
	var got wire.SweepNoticeRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/aikido/sweep/notice" {
			t.Errorf("path %q", r.URL.Path)
		}
		json.NewDecoder(r.Body).Decode(&got)
		json.NewEncoder(w).Encode(wire.SweepNoticeResponse{Notice: "> server words\n"})
	}))
	defer srv.Close()
	client := apiclient.New(srv.URL, "lp_test")

	// Act
	notice := resolveNotice(client, resolveReport{Fixed: []string{"a.go:1"}, StillOpen: []string{}, Unchanged: 2})

	// Assert
	if notice != "> server words\n" {
		t.Errorf("notice %q", notice)
	}
	if got.Kind != wire.SweepNoticeResolve || got.Fixed != 1 || got.Unchanged != 2 {
		t.Errorf("request %+v", got)
	}
}

func TestSweepNoticeIsEmptyWhenTheServerHasNone(
	t *testing.T,
) {
	// Arrange
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	client := apiclient.New(srv.URL, "lp_test")

	// Act
	notice := sweepNotice(client, wire.SweepNoticeRequest{Kind: wire.SweepNoticePlan})

	// Assert
	if notice != "" {
		t.Errorf("notice %q, want none from an old server", notice)
	}
}

func TestSweepNoticeIsPrintedAsPlainMarkdownAboveTheJSON(
	t *testing.T,
) {
	// Arrange
	var out strings.Builder

	// Act
	writeNotice(&out, "> 🛡️ **LeoPrevent** · Aikido sweep\n> \n> Checked 3.\n")
	writeNotice(&out, "")

	// Assert
	want := "> 🛡️ **LeoPrevent** · Aikido sweep\n> \n> Checked 3.\n\n" + sweepRelay + "\n\n"
	if out.String() != want {
		t.Errorf("output:\n%q\nwant:\n%q", out.String(), want)
	}
}
