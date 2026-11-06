package wire

import (
	"path"
	"strings"
	"unicode"

	"github.com/leotrace-hq/leoprevent-plugin/pathgate"
)

const MaxFileDecisions = 200

// FileDecisions describes observed decisions, not every file in a repository.
// Counts include rows omitted by the bound. A file can appear at multiple stages.
// Paths are workspace-relative; protected or unconfined paths are never retained.
type FileDecisions struct {
	Version int            `json:"version"`
	Counts  map[string]int `json:"counts"`
	Files   []FileDecision `json:"files"`
	Omitted int            `json:"omitted"`
}
type FileDecision struct {
	Stage  string `json:"stage"`
	Path   string `json:"path,omitempty"`
	Reason string `json:"reason"`
}

func NewFileDecisions() *FileDecisions {
	return &FileDecisions{Version: 1, Counts: map[string]int{}, Files: []FileDecision{}}
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
	case "sent", "secret", "outside_root", "unreadable", "symlink_or_stat", "binary", "deleted_unavailable", "imported_history", "vendored", "editor_backup", "tool_data", "migration", "lockfile", "test", "inert_extension", "generated", "passive_svg", "generated_or_binary", "comments_only", "context_budget", "context_sliced", "context_unavailable":
		return true
	}
	return false
}
func (d *FileDecisions) Add(stage, p, reason string) {
	if d == nil || !decisionKey(stage, reason) {
		return
	}
	if d.Counts == nil {
		d.Counts = map[string]int{}
	}
	d.Counts[stage+":"+reason]++
	if len(d.Files) == MaxFileDecisions {
		d.Omitted++
		// Keep identifiable exclusions ahead of routine passed files under the bound.
		if reason != "sent" {
			for i, f := range d.Files {
				if f.Reason == "sent" {
					if reason == "secret" || reason == "outside_root" {
						p = ""
					}
					d.Files[i] = FileDecision{Stage: stage, Path: SafeDecisionPath(p), Reason: reason}
					break
				}
			}
		}
		return
	}
	if reason == "secret" || reason == "outside_root" {
		p = ""
	}
	d.Files = append(d.Files, FileDecision{Stage: stage, Path: SafeDecisionPath(p), Reason: reason})
}
func (d *FileDecisions) Clone() *FileDecisions {
	if d == nil {
		return NewFileDecisions()
	}
	c := NewFileDecisions()
	c.Omitted = d.Omitted
	for k, v := range d.Counts {
		c.Counts[k] = v
	}
	c.Files = append(c.Files, d.Files...)
	return c
}

// Invalid instrumentation is discarded, never allowed to fail a review.
func ValidFileDecisions(d *FileDecisions) *FileDecisions {
	if d == nil || d.Version != 1 || len(d.Files) > MaxFileDecisions || d.Omitted < 0 || len(d.Counts) > 80 {
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
	for _, f := range d.Files {
		k := f.Stage + ":" + f.Reason
		if !decisionKey(f.Stage, f.Reason) || remaining[k] == 0 || (f.Path != "" && (SafeDecisionPath(f.Path) != f.Path || f.Reason == "secret" || f.Reason == "outside_root")) {
			return nil
		}
		remaining[k]--
	}
	return d
}
