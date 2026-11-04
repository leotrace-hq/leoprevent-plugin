package depcheck

import (
	"fmt"
	"strings"

	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

// The scan's brief mode (LEO-776, decided 3 Nov 2026). A project with many dependency files to
// fix got one full notice and one offer per file at the end of the session's first turn: 36
// notices on a benchmark results repository, most repeating each other (copies of the same apps),
// and 36 questions, all before the developer could carry on. From briefFiles files with a notice,
// the developer sees a few lines of counts instead (malware named by package, how many are
// critical and high, how many files have a fix) and the agent asks one question. No other package
// and no file is named: the full report and each file's instructions are in the agent's wake,
// behind "If they say yes:", so the agent shows the developer the detail only once they choose to
// fix them, here or in a new session. A folder with no repository is brief too (LEO-778), its
// must-fix instructions offered instead.
//
// ⚠️ PLACEHOLDER WORDING, WRITTEN HERE, like the scan's summary line: it becomes a
// server-overridable template with the rest of the Stop's wording (LEO-620). The brief offer
// takes each file's instructions from the server's offer by cutting at offerYes, the second place
// the plugin reads server wording (labelled is the first); an offer without it is kept whole.

// briefFiles is how many files with a notice turn the scan's notice brief.
const briefFiles = 5

// offerYes is where the server's offer turns from the question to what to do on a yes.
const offerYes = "\n\nIf they say yes:\n"

// brief is the scan's notice in brief mode: lead, then a line each for malware (every package
// named, never summarised away), how many of the rest are critical and high, and, when offerFiles
// files are offered, how many have a fix and where the full list is, then unchecked, if any.
func (r results) brief(lead string, offerFiles int, unchecked string) (text, markdown string) {
	malware := r.briefMalware()
	var lines, mds []string
	if len(malware) > 0 {
		var t, m []string
		for _, p := range malware {
			t, m = append(t, p.malwareName(false)), append(m, p.malwareName(true))
		}
		head := fmt.Sprintf("Declared malware (%d): ", len(malware))
		lines, mds = append(lines, head+strings.Join(t, "; ")), append(mds, head+strings.Join(m, "; "))
	}
	if line := r.severities(len(malware) > 0); line != "" {
		lines, mds = append(lines, line), append(mds, line)
	}
	if offerFiles > 0 {
		fix := fmt.Sprintf("%d %s a fix on the same major version", offerFiles, plural(offerFiles, "file has", "files have"))
		const full = "The full list for each file is shown when you choose to fix them."
		lines, mds = append(lines, fix, full), append(mds, fix, full)
	}
	if unchecked != "" {
		lines, mds = append(lines, unchecked), append(mds, unchecked)
	}
	text, markdown = lead, lead
	for i := range lines {
		text += "\n- " + lines[i]
		markdown += "\n- " + mds[i]
	}
	return text, markdown
}

// severities counts the flagged packages that aren't malware, once per file as the summary line
// does: "12 critical, 96 high". A package is critical when any of its advisories is.
func (r results) severities(besideMalware bool) string {
	critical, high := 0, 0
	for _, f := range r.flagged {
		for _, c := range f.packages {
			if malicious(c) {
				continue
			}
			isCritical := false
			if c.Security != nil {
				for _, a := range c.Security.Advisories {
					isCritical = isCritical || a.Severity == "critical"
				}
			}
			if isCritical {
				critical++
			} else {
				high++
			}
		}
	}
	var parts []string
	if critical > 0 {
		parts = append(parts, fmt.Sprintf("%d critical", critical))
	}
	if high > 0 {
		parts = append(parts, fmt.Sprintf("%d high", high))
	}
	if len(parts) == 0 {
		return ""
	}
	line := strings.Join(parts, ", ")
	if besideMalware {
		line += " besides the malware"
	}
	return line
}

// offerFiles is how many files briefOffer offers to fix.
func (r results) offerFiles(noGit bool) int {
	if noGit {
		return len(r.agent)
	}
	return len(r.offers)
}

// briefOffer is the one offer that stands in for every file's in brief mode: one question, then,
// behind offerYes, the full report to show first and each file's own instructions. "" when no file
// has an offer.
//
// In a folder with no repository (noGit, LEO-778) there is no offer: the server puts every package
// to the agent to fix (messages.agent), since nothing can be marked as changed. In brief mode those
// instructions are offered instead, whole, so the developer chooses there too. That includes what
// the turn itself added, which can't be told apart; a later Stop's check still puts a file the
// agent changes to it (gitlessCheck).
func (r results) briefOffer(noGit bool) string {
	files, goForm, already := r.offers, r.goOffer, "These weren't added this session"
	if noGit {
		files, goForm, already = r.agent, r.goAgent, "This folder isn't a git repository, so LeoPrevent can't tell which were added this session"
	}
	if len(files) == 0 {
		return ""
	}
	n := r.offerFiles(noGit)
	question := fmt.Sprintf("Fix the dependencies in these %d files that have a fix on the same major version?", n)
	if noGit {
		question += " This folder isn't a git repository, so LeoPrevent can't tell which of these were already here."
	}
	if goForm {
		question += " Fixing may raise the Go version in go.mod and update other modules."
	}
	var steps []string
	for _, o := range files {
		if _, yes, ok := strings.Cut(o, offerYes); ok {
			o = yes
		}
		steps = append(steps, o)
	}
	_, report := r.compose("")
	return "🛡️ LeoPrevent · dependency scan: this project already has dependencies with high or critical vulnerabilities in " +
		fmt.Sprintf("%d dependency %s", n, plural(n, "file", "files")) +
		". " + already + ", so don't change them unless the developer agrees. LeoPrevent's notice shows the developer a brief summary only. Ask once, in one short question at the end of your reply: \"" + question +
		"\" Change nothing unless they say yes. In the reply after they answer, whatever they choose, end with this line on its own: \"" + wire.OfferAnsweredLine + "\"" +
		offerYes + "First show the developer LeoPrevent's full report below, each file's notice exactly as it is, then fix each file as its instructions after the report say.\n\n" +
		"LeoPrevent's full report:\n\n" + report + "\n\nEach file's instructions:\n\n" + strings.Join(steps, "\n\n")
}

// briefPackage is one malicious package across the files that list it.
type briefPackage struct {
	display  string // its name as the notice shows it (Go's short name)
	goForm   bool
	versions []string
	files    []string
	remove   bool     // every version
	ids      []string // the advisories that declare it
}

// briefMalware gathers the malicious packages across files, in the order they're first listed.
func (r results) briefMalware() []*briefPackage {
	var malware []*briefPackage
	byKey := map[string]*briefPackage{}
	for _, f := range r.flagged {
		goForm := f.ecosystem == "Go"
		for _, c := range f.packages {
			if !malicious(c) {
				continue
			}
			key := f.ecosystem + "\x00" + c.Name
			p, ok := byKey[key]
			if !ok {
				display := c.Name
				if goForm {
					display = goName(c.Name)
				}
				p = &briefPackage{display: display, goForm: goForm}
				byKey[key] = p
				malware = append(malware, p)
			}
			p.versions = addOnce(p.versions, c.Version)
			p.files = addOnce(p.files, f.path)
			for _, a := range c.Security.Advisories {
				if a.Malicious && len(a.IDs) > 0 {
					p.ids = addOnce(p.ids, a.IDs[0])
				}
			}
			p.remove = p.remove || c.Security.Remove
		}
	}
	return malware
}

// malwareName names a malicious package with its versions, the advisories that declare it and
// how many files list it: "chalk 5.6.1 (MAL-2025-46969) in 3 files", "evil, every version (MAL-…)
// in 1 file". Which files is in the full report.
func (p *briefPackage) malwareName(md bool) string {
	esc := func(s string) string { return s }
	if md {
		esc = escapeMarkdown
	}
	s := esc(p.display)
	switch {
	case p.remove:
		s += ", every version"
	case !p.goForm:
		s += " " + esc(strings.Join(p.versions, ", "))
	}
	if len(p.ids) > 0 {
		s += " (" + esc(strings.Join(p.ids, ", ")) + ")"
	}
	return s + fmt.Sprintf(" in %d %s", len(p.files), plural(len(p.files), "file", "files"))
}

// goName is a Go module's short name, as the server's notice names it (server/internal/sca
// goName): the code host and owner dropped (github.com/gofiber/fiber/v2 is "fiber/v2"),
// golang.org/x kept, since it is the identity, and any other host dropped.
func goName(path string) string {
	parts := strings.Split(path, "/")
	switch {
	case len(parts) >= 3 && (parts[0] == "github.com" || parts[0] == "gitlab.com" || parts[0] == "bitbucket.org"):
		return strings.Join(parts[2:], "/")
	case strings.HasPrefix(path, "golang.org/x/"):
		return path
	case len(parts) >= 2:
		return strings.Join(parts[1:], "/")
	}
	return path
}

func addOnce(list []string, s string) []string {
	for _, v := range list {
		if v == s {
			return list
		}
	}
	return append(list, s)
}
