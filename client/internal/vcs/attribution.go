package vcs

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

var hunkBothRE = regexp.MustCompile(`^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@`)

func editHunks(diff string) []wire.Hunk {
	hunks := []wire.Hunk{}
	oldLine, newLine := 0, 0
	var cur *wire.Hunk
	flush := func() {
		if cur != nil {
			hunks = append(hunks, *cur)
			cur = nil
		}
	}
	open := func() {
		if cur == nil {
			cur = &wire.Hunk{oldLine, 0, newLine, 0}
		}
	}
	seen := false
	for _, line := range strings.Split(diff, "\n") {
		if m := hunkBothRE.FindStringSubmatch(line); m != nil {
			flush()
			oldLine, _ = strconv.Atoi(m[1])
			newLine, _ = strconv.Atoi(m[3])
			if m[2] == "0" {
				oldLine++
			}
			if m[4] == "0" {
				newLine++
			}
			seen = true
			continue
		}
		if !seen {
			continue
		}
		switch {
		case strings.HasPrefix(line, "-"):
			open()
			cur[1]++
			oldLine++
		case strings.HasPrefix(line, "+"):
			open()
			cur[3]++
			newLine++
		case strings.HasPrefix(line, `\`), line == "":
		default:
			flush()
			oldLine++
			newLine++
		}
		if len(hunks) > wire.MaxHunks {
			return nil
		}
	}
	flush()
	if !seen || len(hunks) > wire.MaxHunks {
		return nil
	}
	return hunks
}

func baseBlobAt(root string,
	ref string,
	path string) string {
	if ref == "" || ref == emptyTree || path == "" {
		return ""
	}
	entry, err := git(root, "ls-tree", ref, "--", path)
	if err != nil || !(strings.HasPrefix(entry, "100644 ") || strings.HasPrefix(entry, "100755 ")) {
		return ""
	}
	f := strings.Fields(entry)
	if len(f) < 3 {
		return ""
	}
	return validBlobID(f[2])
}

func basePath(tf trackedFile) string {
	if tf.oldPath != "" {
		return tf.oldPath
	}
	return tf.path
}

func withBase(ch *transcript.Change,
	root string,
	ref string,
	path string,
	diff string) {
	if ch.BlobSHA == "" || diff == "" {
		return
	}
	base := baseBlobAt(root, ref, path)
	if base == "" {
		return
	}
	hunks := editHunks(diff)
	if hunks == nil {
		return
	}
	ch.BaseBlobSHA, ch.Hunks = base, hunks
}
