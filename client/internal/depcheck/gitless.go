package depcheck

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
)

// Without git (LEO-659): a folder with no repository has no start-of-turn copy, so no package can
// be marked as added or changed, and a lockfile written by a shell command (npm install) isn't
// one of the turn's changes at all. So every Stop walks the folder (Find) and sends the dependency
// files whose content hasn't been checked this session (Fingerprint tells), each whole, with the
// server told there's no baseline.

// Fingerprint names the content of rel, a file inside dir, so a later Stop can tell whether it
// changed. "" when it can't be read. It reads through an os.Root at dir, so whatever rel holds
// (".." or a symlink out), nothing outside dir is read.
func Fingerprint(dir, rel string) string {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return ""
	}
	defer root.Close()
	f, err := root.Open(filepath.FromSlash(rel))
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// RunWhole is a turn's check in a folder with no repository: each of files whole, and the turn's
// own changed dependency files that the walk didn't find (walked) as at any other Stop. It returns
// what Run does: the notice, with a summary line when several files have one, and what the server
// put to the agent.
func RunWhole(files, walked []ScanFile, changes []transcript.Change, cwd string, c Checker, log *slog.Logger) (text, markdown, agent string) {
	covered := map[string]bool{}
	for _, f := range walked {
		covered[resolved(f.Path)] = true
	}
	var items []item
	for _, f := range files {
		items = append(items, item{label: f.Label, path: f.Path, root: f.Root, rel: relativeOnly(f.Label), whole: true})
	}
	items = append(items, turnItems(changes, cwd, covered, log)...)
	r := check(items, nil, c, log)
	if r.unavailable || len(r.notices) == 0 {
		return "", "", r.agentText()
	}
	text, markdown = r.compose(r.t.summary())
	return text, markdown, r.agentText()
}
