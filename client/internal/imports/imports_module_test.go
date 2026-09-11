package imports

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
)

func TestGoModuleSymlinkCannotSelectContext(
	t *testing.T,
) {
	root := writeRepo(t, map[string]string{
		"store/store.go": "package store\nfunc Find(id string) any { return nil }\n",
	})
	external := filepath.Join(t.TempDir(), "go.mod")
	if err := os.WriteFile(external, []byte("module github.com/external/app\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, filepath.Join(root, "go.mod")); err != nil {
		t.Fatal(err)
	}
	ch := transcript.Change{
		FilePath:    "handler.go",
		AddedText:   "return store.Find(id)",
		FullContent: "package main\nimport \"github.com/external/app/store\"\nfunc h(id string) any { return store.Find(id) }\n",
	}
	if got := Resolve(root, []transcript.Change{ch}); len(got) != 0 {
		t.Fatalf("external module file selected repository context: %v", got)
	}
}
