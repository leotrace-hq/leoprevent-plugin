package depcheck

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

// briefServer answers as the server does for the packages it's told about: each listed as needing
// a fix at its severity (malware when malicious names it), a notice naming the file's packages,
// and an offer for the rest, the server's question, then offerYes and that file's instructions.
type briefServer struct {
	severity  map[string]string
	malicious map[string]bool
	// aikido marks a malicious package as declared by Aikido alone, with Aikido's own id.
	aikido map[string]bool
	// noGit answers as for a folder with no repository: the instructions are put to the agent
	// (messages.agent), with no offer.
	noGit bool
}

func (s briefServer) CheckDependencies(req wire.DependenciesRequest) (wire.DependenciesResponse, error) {
	resp := wire.DependenciesResponse{Ecosystem: req.Ecosystem}
	var named, fixable []string
	for _, p := range req.Packages {
		sev, ok := s.severity[p.Name]
		if !ok {
			continue
		}
		resp.Issues++
		adv := wire.DependencyAdvisory{IDs: []string{"GHSA-" + p.Name}, Severity: sev}
		if s.malicious[p.Name] {
			adv = wire.DependencyAdvisory{IDs: []string{"MAL-" + p.Name}, Severity: "critical", Malicious: true}
			if s.aikido[p.Name] {
				adv = wire.DependencyAdvisory{IDs: []string{"AIKIDO-MAL-" + p.Name}, Severity: "critical", Malicious: true,
					Basis: wire.DependencyScannerBasis + "Aikido"}
			}
			resp.Malicious++
		} else {
			fixable = append(fixable, p.Name)
		}
		resp.Packages = append(resp.Packages, wire.DependencyCheck{Name: p.Name, Version: p.Version,
			Security: &wire.DependencySecurity{NeedsFix: true, Advisories: []wire.DependencyAdvisory{adv}}})
		named = append(named, p.Name)
	}
	if len(named) == 0 {
		return resp, nil
	}
	resp.Verdict = wire.VerdictTriggered
	msg := fmt.Sprintf("🛡️ LeoPrevent · dependency scan (%d packages)\n- %s", len(named), strings.Join(named, ", "))
	resp.Messages.Developer = &msg
	if len(fixable) > 0 && s.noGit {
		agent := "🛡️ LeoPrevent · dependency check: this folder isn't under git. Move " + strings.Join(fixable, ", ") + " in " + req.Path + "."
		resp.Messages.Agent = &agent
	} else if len(fixable) > 0 {
		offer := "🛡️ LeoPrevent · dependency scan: … Ask once, in one short question at the end of your reply: \"Fix the " +
			fmt.Sprint(len(fixable)) + " dependencies?\"" + offerYes + "Move " + strings.Join(fixable, ", ") + " in " + req.Path + "."
		resp.Messages.AgentOffer = &offer
	}
	return resp, nil
}

// scanFiles writes n lockfiles, a0/…, each from pkgs (which may name a file's own extra packages by
// its index), and the workspace that scans them.
func scanFiles(t *testing.T, n int, pkgs func(i int) map[string]string) (string, Workspace) {
	t.Helper()
	contents := map[string]string{}
	for i := 0; i < n; i++ {
		contents[fmt.Sprintf("a%d/package-lock.json", i)] = lock(pkgs(i))
	}
	root, _ := repo(t, contents, nil)
	var w Workspace
	for i := 0; i < n; i++ {
		rel := fmt.Sprintf("a%d/package-lock.json", i)
		w.Files = append(w.Files, ScanFile{Label: rel, Path: filepath.Join(root, rel), Root: root})
	}
	return root, w
}

// Under briefFiles files with a notice, the scan is as it was: each file's notice and offer. From
// briefFiles, a brief notice and one offer.
func TestTheScanTurnsBriefFromFiveFiles(t *testing.T) {
	srv := briefServer{severity: map[string]string{"lodash": "high"}}
	same := func(int) map[string]string { return map[string]string{"lodash": "4.17.15"} }

	root, w := scanFiles(t, briefFiles-1, same)
	text, _, _, offer := Scan(w, nil, root, nil, srv, quiet)
	if strings.Count(text, "dependency scan (1 packages)") != briefFiles-1 || strings.Count(offer, "Ask once") != briefFiles-1 {
		t.Errorf("4 files: each file's notice and offer\n%s\n---\n%s", text, offer)
	}

	root, w = scanFiles(t, briefFiles, same)
	text, _, _, offer = Scan(w, nil, root, nil, srv, quiet)
	want := "🛡️ LeoPrevent · dependency scan of this project: 5 packages with high or critical issues in 5 dependency files\n" +
		"- 5 high\n" +
		"- 5 files have a fix on the same major version\n" +
		"- The full list for each file is shown when you choose to fix them."
	if text != want {
		t.Errorf("5 files, brief:\n%s\nwant\n%s", text, want)
	}
	if strings.Count(offer, "Ask once") != 1 || !strings.Contains(offer, `"Fix the dependencies in these 5 files that have a fix on the same major version?"`) {
		t.Errorf("one question:\n%s", offer)
	}
	if strings.Contains(offer, `"Fix the 1 dependencies?"`) {
		t.Errorf("a file's own question is left out:\n%s", offer)
	}
	_, yes, ok := strings.Cut(offer, offerYes)
	if !ok || !strings.HasPrefix(yes, "First show the developer LeoPrevent's full report") {
		t.Fatalf("the full report comes after the yes, so the agent shows it only then:\n%s", offer)
	}
	for i := 0; i < briefFiles; i++ {
		f := fmt.Sprintf("a%d/package-lock.json", i)
		if !strings.Contains(yes, "dependency scan (1 packages) · "+f+"\n- lodash") || !strings.Contains(yes, "Move lodash in "+f+".") {
			t.Errorf("%s: its notice and its instructions, after the yes:\n%s", f, yes)
		}
	}
	if !strings.Contains(offer, wire.OfferAnsweredLine) {
		t.Errorf("the answered line, so the answer starts the quiet:\n%s", offer)
	}
}

// The brief notice counts the packages by severity, once per file, and names no package and no
// file; a file with nothing to fix on its major isn't counted as having a fix.
func TestTheBriefNoticeCountsAndNamesNothing(t *testing.T) {
	srv := briefServer{severity: map[string]string{"proxy-addr": "critical", "qs": "high", "ws": "high"}}
	root, w := scanFiles(t, 6, func(i int) map[string]string {
		p := map[string]string{"qs": "6.5.2", "ws": fmt.Sprintf("8.%d.0", i)}
		if i < 2 {
			p["proxy-addr"] = "2.0.7"
		}
		return p
	})
	text, md, _, _ := Scan(w, nil, root, nil, srv, quiet)
	want := "🛡️ LeoPrevent · dependency scan of this project: 14 packages with high or critical issues in 6 dependency files\n" +
		"- 2 critical, 12 high\n" +
		"- 6 files have a fix on the same major version\n" +
		"- The full list for each file is shown when you choose to fix them."
	if text != want {
		t.Errorf("counts:\n%s\nwant\n%s", text, want)
	}
	w.Over = 914
	text, _, _, _ = Scan(w, nil, root, nil, srv, quiet)
	if !strings.HasPrefix(text, "🛡️ LeoPrevent · dependency scan of this project: 14 packages with high or critical issues in 6 dependency files\n") ||
		!strings.HasSuffix(text, "shown when you choose to fix them.\n- ⚠️ 914 more dependency files weren't checked: a scan checks at most 50, nearest the project root first. A file is still checked when the agent changes it.") {
		t.Errorf("the unchecked files, last, on a line of their own (LEO-786):\n%s", text)
	}
	for _, named := range []string{"proxy-addr", "qs", "package-lock.json"} {
		if strings.Contains(text, named) || strings.Contains(md, named) {
			t.Errorf("%s is named in the brief notice:\n%s", named, md)
		}
	}
}

// Malware is never summarised away: every malicious package is named with its advisories and how
// many files list it, before anything else, and isn't counted again with the rest.
func TestTheBriefNoticeNamesMalware(t *testing.T) {
	srv := briefServer{severity: map[string]string{"lodash": "high", "chalk": "critical"}, malicious: map[string]bool{"chalk": true}}
	root, w := scanFiles(t, 5, func(i int) map[string]string {
		p := map[string]string{"lodash": "4.17.15"}
		if i > 0 {
			p["chalk"] = "5.6.1"
		}
		return p
	})
	text, _, _, _ := Scan(w, nil, root, nil, srv, quiet)
	want := "\n- Declared malware (1): chalk 5.6.1 (MAL-chalk) in 4 files\n- 5 high besides the malware\n"
	if !strings.Contains(text, want) {
		t.Errorf("malware:\n%s\nwant\n%s", text, want)
	}
}

// Malware only Aikido declares is named by who reported it, not by Aikido's id, which means no more
// to the developer than a GHSA id (LEO-820).
func TestTheBriefNoticeNamesAikidosMalwareByAikido(t *testing.T) {
	srv := briefServer{severity: map[string]string{"lodash": "high", "chalk": "critical"},
		malicious: map[string]bool{"chalk": true}, aikido: map[string]bool{"chalk": true}}
	root, w := scanFiles(t, 5, func(i int) map[string]string {
		return map[string]string{"lodash": "4.17.15", "chalk": "5.6.1"}
	})
	text, markdown, _, _ := Scan(w, nil, root, nil, srv, quiet)
	want := "\n- Declared malware (1): chalk 5.6.1 (reported by Aikido) in 5 files\n"
	if !strings.Contains(text, want) || strings.Contains(text+markdown, "AIKIDO-") {
		t.Errorf("malware:\n%s\nwant\n%s", text, want)
	}
}

// A folder with no repository is brief too (LEO-778). Its packages are put to the agent to fix
// (messages.agent, there's no offer), so in brief mode they're offered instead, in one question
// that says the folder isn't under git, and nothing is put to the agent outright. Under briefFiles
// they're put to it as before.
func TestAWalkedFolderOffersWhatItWouldHavePut(t *testing.T) {
	srv := briefServer{severity: map[string]string{"lodash": "high"}, noGit: true}
	same := func(int) map[string]string { return map[string]string{"lodash": "4.17.15"} }

	root, w := scanFiles(t, briefFiles-1, same)
	w.Walked = true
	_, _, agent, offer := Scan(w, nil, root, nil, srv, quiet)
	if offer != "" || strings.Count(agent, "Move lodash") != briefFiles-1 {
		t.Errorf("4 files: put to the agent as before\nagent %s\noffer %s", agent, offer)
	}

	root, w = scanFiles(t, briefFiles, same)
	w.Walked = true
	text, _, agent, offer := Scan(w, nil, root, nil, srv, quiet)
	if agent != "" {
		t.Errorf("nothing is put to the agent outright:\n%s", agent)
	}
	if !strings.Contains(text, "- 5 high\n- 5 files have a fix on the same major version\n") || !strings.HasSuffix(strings.SplitN(text, "\n", 2)[0], gitlessWarning) {
		t.Errorf("brief, the summary line still warning there's no git:\n%s", text)
	}
	if !strings.Contains(offer, "This folder isn't a git repository, so LeoPrevent can't tell which were added this session") ||
		!strings.Contains(offer, `same major version? This folder isn't a git repository, so LeoPrevent can't tell which of these were already here."`) {
		t.Errorf("the question says there's no git:\n%s", offer)
	}
	_, yes, _ := strings.Cut(offer, offerYes)
	for i := 0; i < briefFiles; i++ {
		if f := fmt.Sprintf("a%d/package-lock.json", i); !strings.Contains(yes, "Move lodash in "+f+".") {
			t.Errorf("%s's instructions, whole, after the yes:\n%s", f, yes)
		}
	}
}

func TestGoNameMatchesTheServers(t *testing.T) {
	for in, want := range map[string]string{
		"github.com/gofiber/fiber/v2": "fiber/v2", "golang.org/x/crypto": "golang.org/x/crypto",
		"google.golang.org/grpc": "grpc", "stdlib": "stdlib",
	} {
		if got := goName(in); got != want {
			t.Errorf("goName(%q) = %q, want %q", in, got, want)
		}
	}
}
