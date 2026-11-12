package engine

import (
	"log/slog"
	"strings"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/gate"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/outcome"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

func fixTurnChanges(
	before []wire.ChangedFile,
	after []transcript.Change,
) []transcript.Change {
	reviewed := make(map[string]wire.ChangedFile, len(before))
	for _, f := range before {
		reviewed[f.Path] = f
	}
	var out []transcript.Change
	for _, c := range after {
		if c.Virtual {
			continue
		}
		prior, seen := reviewed[c.FilePath]
		switch {
		case !seen:
			out = append(out, c)
		case c.Deleted:
			if !prior.Deleted {
				out = append(out, c)
			}
		default:
			if narrowed, ok := sinceReviewed(prior, c); ok {
				out = append(out, narrowed)
			}
		}
	}
	return out
}

func sinceReviewed(
	prior wire.ChangedFile,
	c transcript.Change,
) (transcript.Change, bool) {
	if c.FullContent != "" && prior.FullContent != "" {
		if c.FullContent == prior.FullContent && c.StartLine() == prior.StartLine() {
			return c, false
		}
		if c.StartLine() != prior.StartLine() {
			return c, true
		}
		d, ok := diffLines(splitLines(prior.FullContent), splitLines(c.FullContent))
		if ok {
			return narrowToDiff(c, d)
		}
		return c, true
	}
	if c.AddedText == prior.AddedText {
		return c, false
	}
	text := linesNotIn(c.AddedText, prior.AddedText)
	if strings.TrimSpace(text) == "" {
		return c, false
	}
	n := c
	n.AddedText = text
	n.AddedLines = nil
	n.RemovedText, n.RemovedAt = "", nil
	return n, true
}

// narrowToDiff keeps, of the diff between the review's copy and the file now, the lines
// the capture attributes to this turn. A capture with no positional basis (AddedLines
// nil: the transcript fallback and a HEAD-only git section, LEO-637) keeps none: the
// lines that changed since the review are a line diff, not a diff against the turn's
// start, and neither shape force-fixes. Its removed lines still go, as context the judge
// reads and never an anchor (api.reanchorToAddedLine needs a positional basis).
func narrowToDiff(
	c transcript.Change,
	d lineDiff,
) (transcript.Change, bool) {
	positional := c.AddedLines != nil
	baseline := map[int]bool{}
	for _, ln := range c.AddedLines {
		baseline[ln] = true
	}
	lines := splitLines(c.FullContent)
	offset := c.StartLine() - 1
	n := c
	addedAt := []int{}
	var added []string
	for _, ln := range d.added {
		if positional && !baseline[ln+offset] {
			continue
		}
		addedAt = append(addedAt, ln+offset)
		added = append(added, lines[ln-1])
	}
	n.AddedLines = nil
	if positional {
		n.AddedLines = addedAt
	}
	n.AddedText = strings.Join(added, "\n")
	n.RemovedText = strings.Join(d.removed, "\n")
	n.RemovedAt = nil
	for _, at := range d.removedAt {
		n.RemovedAt = append(n.RemovedAt, at+offset)
	}
	if len(addedAt) == 0 && len(d.removed) == 0 {
		return c, false
	}
	return n, true
}

func linesNotIn(
	text string,
	prior string,
) string {
	have := map[string]int{}
	for _, ln := range strings.Split(prior, "\n") {
		have[ln]++
	}
	var out []string
	for _, ln := range strings.Split(text, "\n") {
		if have[ln] > 0 {
			have[ln]--
			continue
		}
		out = append(out, ln)
	}
	return strings.Join(out, "\n")
}

func splitLines(s string) []string {
	return strings.Split(strings.TrimSuffix(s, "\n"), "\n")
}

type lineDiff struct {
	added     []int
	removed   []string
	removedAt []int
}

const maxDiffEdits = 2000

func diffLines(
	a []string,
	b []string,
) (lineDiff, bool) {
	pre := 0
	for pre < len(a) && pre < len(b) && a[pre] == b[pre] {
		pre++
	}
	suf := 0
	for suf < len(a)-pre && suf < len(b)-pre && a[len(a)-1-suf] == b[len(b)-1-suf] {
		suf++
	}
	ma, mb := a[pre:len(a)-suf], b[pre:len(b)-suf]
	n, m := len(ma), len(mb)
	limit := n + m
	if limit > maxDiffEdits {
		limit = maxDiffEdits
	}
	off := limit + 1
	v := make([]int, 2*limit+3)
	var trace [][]int
	found := -1
	for d := 0; d <= limit && found < 0; d++ {
		for k := -d; k <= d; k += 2 {
			var x int
			if k == -d || (k != d && v[off+k-1] < v[off+k+1]) {
				x = v[off+k+1]
			} else {
				x = v[off+k-1] + 1
			}
			y := x - k
			for x < n && y < m && ma[x] == mb[y] {
				x++
				y++
			}
			v[off+k] = x
			if x >= n && y >= m {
				found = d
				break
			}
		}
		trace = append(trace, append([]int(nil), v[off-d:off+d+1]...))
	}
	if found < 0 {
		return lineDiff{}, false
	}
	at := func(d, k int) int { return trace[d][k+d] }
	var res lineDiff
	x, y := n, m
	for d := found; d > 0; d-- {
		k := x - y
		var pk int
		if k == -d || (k != d && at(d-1, k-1) < at(d-1, k+1)) {
			pk = k + 1
		} else {
			pk = k - 1
		}
		px := at(d-1, pk)
		py := px - pk
		for x > px && y > py {
			x--
			y--
		}
		if pk == k+1 {
			res.added = append(res.added, pre+py+1)
		} else {
			res.removed = append(res.removed, ma[px])
			res.removedAt = append(res.removedAt, pre+py+1)
		}
		x, y = px, py
	}
	reverseInts(res.added)
	reverseInts(res.removedAt)
	for i, j := 0, len(res.removed)-1; i < j; i, j = i+1, j-1 {
		res.removed[i], res.removed[j] = res.removed[j], res.removed[i]
	}
	return res, true
}

func reverseInts(s []int) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}

func newSinceBlock(
	findings []wire.Finding,
	p outcome.Pending,
) []wire.Finding {
	flagged := map[string]bool{}
	for _, f := range p.Findings {
		flagged[f.Rule+"\x00"+fileFromLocation(f.Location)] = true
	}
	var out []wire.Finding
	for _, f := range findings {
		if !flagged[f.Rule+"\x00"+fileFromLocation(f.Location)] {
			out = append(out, f)
		}
	}
	return out
}

func reviewFixTurn(
	r Reviewer,
	cwd string,
	p outcome.Pending,
	changes []transcript.Change,
	meta wire.TurnMeta,
	log *slog.Logger,
) []wire.Finding {
	if p.ReviewID == "" || len(p.Before) == 0 {
		return nil
	}
	reviewable := gate.Run(fixTurnChanges(p.Before, changes))
	if len(reviewable) == 0 {
		log.Info("fix turn wrote nothing new to review", "review_id", p.ReviewID)
		return nil
	}
	meta.RewakeOf = p.ReviewID
	meta.Prompt = ""
	meta.InputTokens, meta.CacheCreationTokens, meta.CacheReadTokens, meta.OutputTokens = 0, 0, 0, 0
	meta.DurationMs = 0
	meta.Speed = ""
	log.Info("reviewing code written after the re-wake", "review_id", p.ReviewID, "reviewable", len(reviewable))
	res, err := r.Review(cwd, reviewable, meta, "")
	if err != nil {
		log.Info("fix-turn review failed (best-effort, ignoring)", "review_id", p.ReviewID, "err", err.Error())
		return nil
	}
	findings := res.Findings
	if findings == nil && res.Pending != nil {
		findings = res.Pending.Findings
	}
	fresh := newSinceBlock(findings, p)
	log.Info("fix-turn review done", "review_id", p.ReviewID, "findings", len(findings), "new", len(fresh))
	return fresh
}
