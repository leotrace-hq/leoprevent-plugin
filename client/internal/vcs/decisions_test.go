package vcs

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

func TestDiscoveryReportsBinaryAndSecretExclusions(t *testing.T) {
	dir, session := initRepo(t)
	if err := CaptureBaseline(dir, session); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"asset.bin": "binary\x00body", ".env": "PRIVATE=never-send", "app.go": "package main\n"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	changes, ok, skip, info, err := ChangedFilesWithInfo(dir, session)
	if err != nil || !ok {
		t.Fatalf("discovery: %v %s %v", ok, skip, err)
	}
	if len(changes) != 1 || changes[0].FilePath != "app.go" {
		t.Fatalf("changed capture: %+v", changes)
	}
	d := info.FileDecisions
	if wire.ValidFileDecisions(d) == nil || d.Counts["discovery:binary"] != 1 || d.Counts["discovery:secret"] != 1 {
		t.Fatalf("missing exclusions: %+v", d)
	}
	for _, f := range d.Files {
		if f.Reason == "secret" && f.Path != "" {
			t.Fatal("secret filename retained")
		}
	}
}
