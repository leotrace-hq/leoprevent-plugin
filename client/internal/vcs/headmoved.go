package vcs

import (
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const SkipHeadMovedNoAgentEdits SkipReason = "head_moved_no_agent_edits"

const headMovedNotAgent = "head_moved_not_agent"

func touchedPath(sessionID string) string {
	return scratchPath("touched-" + keyFor(sessionID))
}

func RecordTouchedPaths(paths []string,
	cwd string,
	sessionID string) {
	if sessionID == "" {
		return
	}
	path := touchedPath(sessionID)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	for _, p := range paths {
		if abs := absoluteAgentPath(p, cwd); abs != "" {
			_, _ = f.Write([]byte(abs + "\n"))
		}
	}
}

func clearTouched(sessionID string) {
	if sessionID != "" {
		_ = os.Remove(touchedPath(sessionID))
	}
}

func readTouched(sessionID string) (map[string]bool, bool) {
	data, err := os.ReadFile(touchedPath(sessionID))
	if err != nil {
		return nil, false
	}
	set := map[string]bool{}
	for _, ln := range strings.Split(string(data), "\n") {
		if ln != "" {
			set[ln] = true
		}
	}
	return set, true
}

func absoluteAgentPath(p string,
	cwd string) string {
	if p == "" || strings.ContainsAny(p, "\n\x00") {
		return ""
	}
	if !filepath.IsAbs(p) {
		if cwd == "" {
			return ""
		}
		p = filepath.Join(cwd, p)
	}
	return canonicalFile(p)
}

func canonicalFile(p string) string {
	p = filepath.Clean(p)
	dir, rest := filepath.Dir(p), filepath.Base(p)
	for {
		if resolved, err := filepath.EvalSymlinks(dir); err == nil {
			return filepath.Join(resolved, rest)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return p
		}
		rest = filepath.Join(filepath.Base(dir), rest)
		dir = parent
	}
}

type agentAttribution struct {
	transcript func() []string
	sessionID  string
	cwd        string
	loaded     bool
	paths      map[string]bool
	known      bool
}

func (a *agentAttribution) edits() (map[string]bool, bool) {
	if a == nil {
		return nil, false
	}
	if a.loaded {
		return a.paths, a.known
	}
	a.loaded = true
	a.paths, a.known = readTouched(a.sessionID)
	if a.paths == nil {
		a.paths = map[string]bool{}
	}
	if a.transcript != nil {
		for _, p := range a.transcript() {
			if abs := absoluteAgentPath(p, a.cwd); abs != "" {
				a.paths[abs] = true
				a.known = true
			}
		}
	}
	return a.paths, a.known
}

func headMovedThroughHistory(dir string,
	s repoBaseline) bool {
	if s.head == "" || s.headOnly {
		return false
	}
	head, err := git(dir, "rev-parse", "HEAD")
	if err != nil || strings.TrimSpace(head) == s.head {
		return false
	}
	if s.at <= 0 {
		return true
	}
	if _, err := git(dir, "merge-base", "--is-ancestor", s.head, "HEAD"); err != nil {
		return true
	}
	older, err := git(dir, "rev-list", "-n", "1", "--before=@"+strconv.FormatInt(s.at-1, 10), s.head+"..HEAD")
	return err != nil || strings.TrimSpace(older) != ""
}

func (cc *changeCollector) keepAgentEdited(root string,
	s repoBaseline,
	files []trackedFile,
	edits map[string]bool) ([]trackedFile, map[string]bool) {
	kept := make([]trackedFile, 0, len(files))
	protected := map[string]bool{}
	dropped := 0
	for _, tf := range files {
		if edits[canonicalFile(filepath.Join(root, filepath.FromSlash(tf.path)))] {
			kept = append(kept, tf)
			protected[tf.path] = true
			continue
		}
		cc.decisions.Add("discovery", s.join(tf.path), headMovedNotAgent)
		dropped++
	}
	slog.Info("vcs: HEAD moved through history this turn; files NOT reviewed because the agent did not edit them",
		"repo", s.label, "dropped", dropped, "kept", len(kept))
	return kept, protected
}

func defaultRemoteTip(cwd string) string {
	for _, ref := range []string{"refs/remotes/origin/HEAD", "refs/remotes/origin/main", "refs/remotes/origin/master"} {
		if out, err := git(cwd, "rev-parse", "--verify", "--quiet", ref+"^{commit}"); err == nil {
			if sha := strings.TrimSpace(out); sha != "" {
				return sha
			}
		}
	}
	return ""
}

func remoteTips(cwd string) ([]string, error) {
	out, err := git(cwd, "for-each-ref", "--format=%(objectname)", "refs/remotes/")
	if err != nil {
		return nil, err
	}
	var tips []string
	seen := map[string]bool{}
	add := func(sha string) {
		sha = strings.TrimSpace(sha)
		if sha == "" || seen[sha] || len(tips) >= maxPublishedTips {
			return
		}
		seen[sha] = true
		tips = append(tips, sha)
	}
	if strings.TrimSpace(out) != "" {
		add(defaultRemoteTip(cwd))
	}
	for _, ln := range strings.Split(out, "\n") {
		add(ln)
	}
	return tips, nil
}

func tipsAtStop(cwd string,
	baseHead string,
	at int64,
	recorded []string) []string {
	fresh, err := remoteTips(cwd)
	if err != nil {
		return recorded
	}
	known := map[string]bool{}
	for _, tip := range recorded {
		known[tip] = true
	}
	tips := append([]string(nil), recorded...)
	for _, tip := range fresh {
		if known[tip] || !publishedBeforeTurn(cwd, baseHead, at, tip) {
			continue
		}
		known[tip] = true
		tips = append(tips, tip)
	}
	return tips
}

func publishedBeforeTurn(cwd string,
	baseHead string,
	at int64,
	tip string) bool {
	if at <= 0 {
		return false
	}
	if _, err := git(cwd, "merge-base", "--is-ancestor", tip, "HEAD"); err != nil {
		return false
	}
	newer, err := git(cwd, "rev-list", "-n", "1", "--since=@"+strconv.FormatInt(at, 10), tip, "^"+baseHead)
	return err == nil && strings.TrimSpace(newer) == ""
}
