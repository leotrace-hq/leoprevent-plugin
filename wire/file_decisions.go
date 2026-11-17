package wire

import (
	"encoding/json"
	"path"
	"strings"
	"unicode"

	"github.com/leotrace-hq/leoprevent-plugin/pathgate"
)

const (
	// MaxFileDecisionBytes bounds the JSON-encoded files array, including escaping,
	// separators and brackets. Counts are bounded separately by known keys and values.
	MaxFileDecisionBytes   = 256 * 1024
	legacyMaxFileDecisions = 200
)

// FileDecisions describes observed decisions, not every file in a repository.
// Counts include rows omitted by the bound. A file can appear at multiple stages.
// Paths are workspace-relative; protected or unconfined paths are never retained.
type FileDecisions struct {
	Version          int            `json:"version"`
	Counts           map[string]int `json:"counts"`
	Files            []FileDecision `json:"files"`
	Omitted          int            `json:"omitted"`
	EnryVendorCounts map[string]int `json:"enry_vendor_counts,omitempty"`

	// Collector-owned caches. Clone rebuilds these before collecting more examples.
	fileBytes int
	fileSizes []int
	groups    map[decisionGroup]int
}
type FileDecision struct {
	Stage  string `json:"stage"`
	Path   string `json:"path,omitempty"`
	Reason string `json:"reason"`
}

type decisionGroup struct{ stage, reason string }

func NewFileDecisions() *FileDecisions {
	return &FileDecisions{Version: 2, Counts: map[string]int{}, Files: []FileDecision{}}
}

// SafeDecisionPath deliberately keeps no basename when confinement is unknown.
func SafeDecisionPath(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	if p == "" || len(p) > 512 || strings.HasPrefix(p, "/") || strings.Contains(p, ":") || path.Clean(p) != p || p == ".." || strings.HasPrefix(p, "../") || pathgate.IsSecretPath(p) || strings.IndexFunc(p, unicode.IsControl) >= 0 {
		return ""
	}
	return p
}
func decisionKey(stage, reason string) bool {
	switch stage {
	case "discovery", "relevance", "context":
	default:
		return false
	}
	switch reason {
	case "sent", "secret", "outside_root", "unreadable", "symlink_or_stat", "binary", "deleted_unavailable", "imported_history", "head_moved_not_agent", "vendored", "editor_backup", "tool_data", "migration", "lockfile", "test", "inert_extension", "generated", "passive_svg", "generated_or_binary", "comments_only", "context_budget", "context_sliced", "context_unavailable":
		return true
	}
	return false
}
func (d *FileDecisions) Add(stage, p, reason string) {
	d.AddDecision(FileDecision{Stage: stage, Path: p, Reason: reason})
}

// AddVendored counts the matched public rule without storing it on a file example.
// Retained paths can be replayed against the recorded plugin version instead.
func (d *FileDecisions) AddVendored(stage, p, rule string) {
	d.add(FileDecision{Stage: stage, Path: p, Reason: "vendored"}, rule)
}

// AddDecision counts every decision and retains examples under the byte budget.
func (d *FileDecisions) AddDecision(f FileDecision) {
	d.add(f, "")
}

func (d *FileDecisions) add(f FileDecision, enryRule string) {
	if d == nil || !decisionKey(f.Stage, f.Reason) {
		return
	}
	if d.Version == 1 {
		d.Version = 2 // Extending a legacy report uses the current retention contract.
	}
	if d.Counts == nil {
		d.Counts = map[string]int{}
	}
	d.Counts[f.Stage+":"+f.Reason]++
	if f.Reason == "secret" || f.Reason == "outside_root" {
		f.Path = ""
	}
	f.Path = SafeDecisionPath(f.Path)
	if f.Reason == "vendored" && pathgate.IsEnryVendorRule(enryRule) {
		if d.EnryVendorCounts == nil {
			d.EnryVendorCounts = map[string]int{}
		}
		d.EnryVendorCounts[enryRule]++
	}
	d.initSamples()
	size := decisionBytes(f)
	separator := 0
	if len(d.Files) > 0 {
		separator = 1
	}
	if d.fileBytes+size+separator <= MaxFileDecisionBytes {
		d.appendExample(f, size)
		return
	}
	d.retainExample(f, size)
}

func decisionBytes(f FileDecision) int {
	b, _ := json.Marshal(f) // Only string fields; JSON encoding cannot fail.
	return len(b)
}

func (d *FileDecisions) initSamples() {
	if d.groups != nil && len(d.fileSizes) == len(d.Files) {
		return
	}
	d.fileBytes = 2 // Array brackets.
	d.fileSizes = make([]int, len(d.Files))
	d.groups = map[decisionGroup]int{}
	for i, f := range d.Files {
		d.fileSizes[i] = decisionBytes(f)
		d.fileBytes += d.fileSizes[i] + 1
		d.groups[decisionGroup{f.Stage, f.Reason}]++
	}
	if len(d.Files) > 0 {
		d.fileBytes-- // No trailing comma.
	}
}

func (d *FileDecisions) appendExample(f FileDecision, size int) {
	if len(d.Files) > 0 {
		d.fileBytes++
	}
	d.Files = append(d.Files, f)
	d.fileSizes = append(d.fileSizes, size)
	d.fileBytes += size
	d.groups[decisionGroup{f.Stage, f.Reason}]++
}

// donor prefers passed files, then the newest surplus example of the largest skip
// group. Common incoming reasons need only inspect group counts, not every row.
func (d *FileDecisions) donor(incoming decisionGroup, counts map[decisionGroup]int, removed []bool) int {
	hasSent, most := false, counts[incoming]+1
	for g, n := range counts {
		if g.reason == "sent" && n > 0 {
			hasSent = true
		}
		if n > most {
			most = n
		}
	}
	if !hasSent && most == counts[incoming]+1 {
		return -1
	}
	for i := len(d.Files) - 1; i >= 0; i-- {
		if removed != nil && removed[i] {
			continue
		}
		f := d.Files[i]
		if (hasSent && f.Reason == "sent") || (!hasSent && counts[decisionGroup{f.Stage, f.Reason}] == most) {
			return i
		}
	}
	return -1
}

func (d *FileDecisions) retainExample(f FileDecision, size int) {
	incoming := decisionGroup{f.Stage, f.Reason}
	i := -1
	if f.Reason != "sent" {
		i = d.donor(incoming, d.groups, nil)
	}
	if i < 0 {
		d.Omitted++
		return
	}
	// Plan all evictions before changing the report. A long incoming path can need
	// several shorter donors; an unsuccessful plan must not lose existing examples.
	counts := make(map[decisionGroup]int, len(d.groups))
	for g, n := range d.groups {
		counts[g] = n
	}
	removed := make([]bool, len(d.Files))
	freed, n := 0, 0
	need := d.fileBytes + size + 1 - MaxFileDecisionBytes
	for freed < need && i >= 0 {
		removed[i] = true
		freed += d.fileSizes[i] + 1
		old := d.Files[i]
		counts[decisionGroup{old.Stage, old.Reason}]--
		n++
		if freed < need {
			i = d.donor(incoming, counts, removed)
		}
	}
	if freed < need {
		d.Omitted++
		return
	}

	kept := 0
	d.fileBytes = 2
	for j, old := range d.Files {
		if removed[j] {
			continue
		}
		d.Files[kept], d.fileSizes[kept] = old, d.fileSizes[j]
		d.fileBytes += d.fileSizes[kept] + 1
		kept++
	}
	clear(d.Files[kept:])
	d.Files, d.fileSizes = d.Files[:kept], d.fileSizes[:kept]
	if kept > 0 {
		d.fileBytes--
	}
	d.groups = counts
	d.Omitted += n
	d.appendExample(f, size) // Appending preserves arrival order and early examples.
}

func (d *FileDecisions) Clone() *FileDecisions {
	if d == nil {
		return NewFileDecisions()
	}
	c := NewFileDecisions()
	c.Version = d.Version
	c.Omitted = d.Omitted
	for k, v := range d.Counts {
		c.Counts[k] = v
	}
	if d.EnryVendorCounts != nil {
		c.EnryVendorCounts = map[string]int{}
		for k, v := range d.EnryVendorCounts {
			c.EnryVendorCounts[k] = v
		}
	}
	c.Files = append(c.Files, d.Files...)
	return c
}

// Invalid instrumentation is discarded, never allowed to fail a review.
func ValidFileDecisions(d *FileDecisions) *FileDecisions {
	if d == nil {
		return nil
	}
	if d.Version != 1 && d.Version != 2 {
		return nil
	}
	if d.Omitted < 0 || len(d.Counts) > 80 {
		return nil
	}
	if d.Version == 1 && len(d.Files) > legacyMaxFileDecisions {
		return nil
	}
	total := 0
	remaining := map[string]int{}
	for k, n := range d.Counts {
		stage, reason, ok := strings.Cut(k, ":")
		if !ok || !decisionKey(stage, reason) || n < 0 || n > 100000 {
			return nil
		}
		total += n
		remaining[k] = n
	}
	if total != len(d.Files)+d.Omitted {
		return nil
	}
	// A newer plugin may know vendor patterns this server does not. Ignore that
	// optional attribution without losing the core decisions, or mutating the input.
	// Filtering to the allowlist also bounds rule keys by the compiled pattern set.
	d = withoutUnknownEnryCounts(d)
	vendorTotal := d.Counts["discovery:vendored"] + d.Counts["relevance:vendored"] + d.Counts["context:vendored"]
	ruleTotal := 0
	for _, n := range d.EnryVendorCounts {
		if n <= 0 || n > vendorTotal {
			return nil
		}
		ruleTotal += n
	}
	if ruleTotal > vendorTotal {
		return nil
	}
	fileBytes := 2
	for i, f := range d.Files {
		k := f.Stage + ":" + f.Reason
		if !decisionKey(f.Stage, f.Reason) || remaining[k] == 0 || (f.Path != "" && (SafeDecisionPath(f.Path) != f.Path || f.Reason == "secret" || f.Reason == "outside_root")) {
			return nil
		}
		if d.Version == 2 {
			fileBytes += decisionBytes(f)
			if i > 0 {
				fileBytes++
			}
			if fileBytes > MaxFileDecisionBytes {
				return nil
			}
		}
		remaining[k]--
	}
	return d
}

func withoutUnknownEnryCounts(d *FileDecisions) *FileDecisions {
	clean := *d
	changed := false
	for rule := range d.EnryVendorCounts {
		if pathgate.IsEnryVendorRule(rule) {
			continue
		}
		clean.EnryVendorCounts = map[string]int{}
		for rule, n := range d.EnryVendorCounts {
			if pathgate.IsEnryVendorRule(rule) {
				clean.EnryVendorCounts[rule] = n
			}
		}
		changed = true
		break
	}
	if changed {
		return &clean
	}
	return d
}
