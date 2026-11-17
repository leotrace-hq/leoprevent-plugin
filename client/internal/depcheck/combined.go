package depcheck

import (
	"fmt"
	"sort"
	"strings"

	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

// One offer for several files (LEO-832, decided 9 Nov 2026, D70). /leoprevent:sca, and a
// mid-session Stop that covers several files, can have fix offers from several files. Joined
// whole, each brought its own question and its own answered line, so the developer could be asked
// two or three "Fix the 2 dependencies…?" questions in one reply, and the agent carried the same
// rules once per file. From a server that sends each offer in parts (wire
// DependencyMessages.AgentOfferChanges and AgentOfferRules), the plugin makes them one: one
// question for every file, one answered line, each distinct rule once, then each file's changes
// under its name. One answer quietens everything offered, as before (D60). A file's offer without
// its parts (an older server) keeps them all whole, so nothing is dropped.

// offerPart is one file's fix offer in parts: its changes, the rules they follow, and how many
// packages it covers.
type offerPart struct {
	label, changes string
	rules          []string
	packages       int
}

// partsComplete reports whether every file's offer came in parts, so they can be made one.
func (r results) partsComplete() bool { return len(r.parts) > 0 && len(r.parts) == len(r.offers) }

// combinedOffer is the one offer for two or more files' fix offers, or "" when there are fewer or
// they didn't all come in parts.
func (r results) combinedOffer() string {
	if len(r.offers) < 2 || !r.partsComplete() {
		return ""
	}
	files := r.byFile()
	if len(files) < 2 {
		// One file sent in several requests (more packages than one request takes): its offers are
		// still joined as they are, as before.
		return ""
	}
	packages := 0
	for _, p := range files {
		packages += p.packages
	}
	question := fmt.Sprintf("Fix the %d dependencies in these %d files that have a fix on the same major version?", packages, len(files))
	if r.goOffer {
		question += " Fixing may raise the Go version in go.mod and update other modules."
	}
	return "🛡️ LeoPrevent · dependency scan: this project already has dependencies with high or critical vulnerabilities in " +
		fmt.Sprintf("%d dependency files", len(files)) +
		". These weren't added this session, so don't change them unless the developer agrees. Ask once, in one short question at the end of your reply: \"" + question +
		"\" Change nothing unless they say yes. In the reply after they answer, whatever they choose, end with this line on its own: \"" + wire.OfferAnsweredLine + "\"" +
		offerYes + r.partsBody()
}

// byFile is the parts one per file, in name order: a file sent in several requests (more packages
// than one request takes) has its changes, rules and packages gathered under its one name.
func (r results) byFile() []offerPart {
	var files []offerPart
	at := map[string]int{}
	for _, p := range r.parts {
		i, ok := at[p.label]
		if !ok {
			at[p.label] = len(files)
			files = append(files, offerPart{label: p.label})
			i = len(files) - 1
		}
		f := &files[i]
		if f.changes != "" {
			f.changes += "\n"
		}
		f.changes += p.changes
		f.rules = mergeRules([][]string{f.rules, p.rules})
		f.packages += p.packages
	}
	sort.SliceStable(files, func(i, j int) bool { return files[i].label < files[j].label })
	return files
}

// partsBody is each distinct rule once, then each file's changes under its name, files in name
// order.
func (r results) partsBody() string {
	var lists [][]string
	var files []string
	for _, p := range r.byFile() {
		lists = append(lists, p.rules)
		files = append(files, p.label+":\n"+p.changes)
	}
	return strings.Join(mergeRules(lists), "\n") + "\n\n" + strings.Join(files, "\n\n")
}

// mergeRules is every distinct rule in lists once, keeping each list's order: a rule one list
// lacks goes before the next rule it shares with the others, so the rule every file ends with
// (the priority line) stays last.
func mergeRules(lists [][]string) []string {
	var merged []string
	have := map[string]bool{}
	for _, l := range lists {
		for i, rule := range l {
			if have[rule] {
				continue
			}
			have[rule] = true
			at := len(merged)
			for _, next := range l[i+1:] {
				if have[next] {
					for k, m := range merged {
						if m == next {
							at = k
							break
						}
					}
					break
				}
			}
			merged = append(merged[:at], append([]string{rule}, merged[at:]...)...)
		}
	}
	return merged
}
