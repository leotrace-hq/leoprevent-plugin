package engine

import (
	"os/exec"
	"reflect"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/vcs"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

func TestFixTurnAttributionUsesTheReviewedBlob(t *testing.T) {
	root := t.TempDir()
	if out, err := exec.Command("git", "-C", root, "init", "-q").CombinedOutput(); err != nil {
		t.Fatalf("git init: %v %s", err, out)
	}
	cases := []struct {
		name, before, after string
		added               []int
		hunks               []wire.Hunk
	}{
		{"repair new file", "def lookup():\n    unsafe()\n    return rows\n", "def lookup():\n    safe()\n    return rows\n", []int{2}, []wire.Hunk{{2, 1, 2, 1}}},
		{"insert and delete", "a\nb\nc\nd\ne\n", "intro\na\nb\nd\ne\n", []int{1}, []wire.Hunk{{1, 0, 1, 1}, {3, 1, 4, 0}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prior := wire.ChangedFile{Path: "app.py", FullContent: tc.before, BlobSHA: vcs.BlobID(root, "app.py", []byte(tc.before))}
			c := transcript.Change{FilePath: "app.py", RepoRoot: root, FullContent: tc.after, BlobSHA: vcs.BlobID(root, "app.py", []byte(tc.after))}
			for i := range splitLines(tc.after) {
				c.AddedLines = append(c.AddedLines, i+1)
			}
			got := fixTurnChanges([]wire.ChangedFile{prior}, []transcript.Change{c})
			if len(got) != 1 {
				t.Fatalf("changes = %v", got)
			}
			if !reflect.DeepEqual(got[0].AddedLines, tc.added) {
				t.Fatalf("repair additions = %v, want %v", got[0].AddedLines, tc.added)
			}
			if got[0].BaseBlobSHA != prior.BlobSHA || !reflect.DeepEqual(got[0].Hunks, tc.hunks) {
				t.Fatalf("repair attribution base %q hunks %v, want %q %v", got[0].BaseBlobSHA, got[0].Hunks, prior.BlobSHA, tc.hunks)
			}
		})
	}
}

func TestFixTurnAttributionDoesNotTrustIncompleteBodies(t *testing.T) {
	root := t.TempDir()
	if out, err := exec.Command("git", "-C", root, "init", "-q").CombinedOutput(); err != nil {
		t.Fatalf("git init: %v %s", err, out)
	}
	before, after := "a\nunsafe()\nz\n", "a\nsafe()\nz\n"
	for _, name := range []string{"sliced before", "sliced after", "no positional basis", "missing reviewed blob"} {
		t.Run(name, func(t *testing.T) {
			prior := wire.ChangedFile{Path: "app.py", FullContent: before, BlobSHA: vcs.BlobID(root, "app.py", []byte(before))}
			c := transcript.Change{FilePath: "app.py", RepoRoot: root, FullContent: after, BlobSHA: vcs.BlobID(root, "app.py", []byte(after)), AddedLines: []int{1, 2, 3}, BaseBlobSHA: "obsolete turn baseline", Hunks: []wire.Hunk{{1, 0, 1, 3}}}
			switch name {
			case "sliced before":
				prior.FullContent = "a\nunsafe()\n"
			case "sliced after":
				c.FullContent = "a\nsafe()\n"
			case "no positional basis":
				c.AddedLines = nil
			case "missing reviewed blob":
				prior.BlobSHA = ""
			}
			got := fixTurnChanges([]wire.ChangedFile{prior}, []transcript.Change{c})
			if len(got) != 1 {
				t.Fatalf("changes = %v", got)
			}
			if got[0].BaseBlobSHA != "" || got[0].Hunks != nil {
				t.Fatalf("unproven repair attribution base %q hunks %v", got[0].BaseBlobSHA, got[0].Hunks)
			}
		})
	}
}
