package wire

import "time"

// POST /dependencies (cloud tier, LEO-509, decision D57): an ecosystem and a list of packages with
// their versions in; per package, its known advisories and the lowest version that clears the
// serious ones out. Package names and versions only, never code. The server answers from its own
// copy of the advisory feeds and passes nothing on.

// DependenciesRequest is one ecosystem's packages to check.
type DependenciesRequest struct {
	// Ecosystem in OSV's spelling: "npm" or "Go".
	Ecosystem string              `json:"ecosystem"`
	Packages  []DependencyVersion `json:"packages"`
}

// DependencyVersion is one package at the version in use.
type DependencyVersion struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	// Line is where the dependency is declared, when the caller knows it, echoed back so a message
	// can point at it. 0 when unknown.
	Line int `json:"line,omitempty"`
	// DependencyContext is how the project uses it. Left out, a dependency is read as direct and
	// runtime: the strictest check, so a caller that can't tell never gets a lighter one.
	DependencyContext
}

// DependencyContext is how a project uses a dependency and how this turn changed it. The server
// decides from it how a finding is worded and which findings need fixing.
type DependencyContext struct {
	// Indirect: pulled in by another package rather than asked for by the project (npm: not a
	// dependency of the project or a workspace; Go: "// indirect").
	Indirect bool `json:"indirect,omitempty"`
	// Dev: only needed for development, never installed for production (npm's "dev": true). Go
	// has no such section, so a Go module is never Dev.
	Dev bool `json:"dev,omitempty"`
	// Change is how the turn changed it: DependencyAdded, DependencyChanged or
	// DependencyUnchanged; "" when the caller had nothing to compare with.
	Change string `json:"change,omitempty"`
	// Previous is the version at the start of the turn, when Change is DependencyChanged and the
	// version moved. A change of context alone (now runtime, now direct) leaves it empty.
	Previous string `json:"previous,omitempty"`
}

// How a turn changed a dependency.
const (
	// DependencyAdded: not in the file at the start of the turn.
	DependencyAdded = "added"
	// DependencyChanged: its version, or how the project uses it, differs from the start of the
	// turn.
	DependencyChanged = "changed"
	// DependencyUnchanged: as it was at the start of the turn (sent when the whole file is
	// checked).
	DependencyUnchanged = "unchanged"
)

// Security statuses, most serious first.
const (
	// DependencyMalicious: an advisory says the package, or this release of it, is an attack.
	DependencyMalicious = "malicious"
	// DependencyVulnerable: at least one rated advisory affects this version.
	DependencyVulnerable = "vulnerable"
	// DependencyUnsure: an advisory for the package couldn't be evaluated (its ranges don't
	// read as versions), so this version may or may not be affected. Never read as clean.
	DependencyUnsure = "unsure"
	// DependencyUnratedOnly: only advisories with no severity rating affect this version.
	DependencyUnratedOnly = "unrated_only"
	// DependencyClean: no known advisory affects this version.
	DependencyClean = "clean"
)

// DependenciesResponse answers a DependenciesRequest.
type DependenciesResponse struct {
	Ecosystem string `json:"ecosystem"`
	// Verdict is the whole answer in /review's terms: VerdictTriggered when any package needs
	// fixing, VerdictClean otherwise. Read it rather than the wording: a clean verdict can still
	// come with Unchecked packages, so clean means "nothing found", never "everything checked".
	Verdict string `json:"verdict"`
	// Unchecked counts the packages that weren't fully checked: their version isn't one in the
	// ecosystem's scheme, or an advisory for them couldn't be evaluated (each package's
	// security.unsure names which). A check with any is partial, and should be shown as such.
	Unchecked int `json:"unchecked,omitempty"`
	// Issues counts the issues needing a fix across all the packages: the advisories (grouped by
	// alias) that set needs_fix under the server's policy, so a developer dependency's high
	// vulnerability isn't counted and its malware is. Malicious counts those that are malware.
	// A caller adding up several responses (one per dependency file) uses these rather than
	// re-deciding severity itself.
	Issues    int               `json:"issues,omitempty"`
	Malicious int               `json:"malicious,omitempty"`
	Packages  []DependencyCheck `json:"packages"`
	// Messages is the wording, written on the server so it can change without a plugin release.
	Messages DependencyMessages `json:"messages"`
	// Feeds is how current each feed's copy was when the check ran: its newest modified time,
	// keyed by feed and ecosystem ("osv:npm"). A finding can then be dated against the data.
	Feeds map[string]time.Time `json:"feeds,omitempty"`
}

// DependencyCheck is one dependency's state: each concern checked about it is its own block, so a
// later one (its licence, its package metadata) is a sibling, added without changing the others.
type DependencyCheck struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Line    int    `json:"line,omitempty"`
	// DependencyContext is echoed from the request.
	DependencyContext
	// Security is the known-vulnerability check, against the server's copy of the advisory feeds.
	Security *DependencySecurity `json:"security,omitempty"`
}

// DependencySecurity is a dependency's known-vulnerability check.
type DependencySecurity struct {
	Status string `json:"status"`
	// Error is why the version couldn't be checked at all (it isn't one in the ecosystem's
	// scheme). Status is then DependencyUnsure.
	Error string `json:"error,omitempty"`
	// Advisories that affect this version, of every severity, one per issue: records describing
	// the same vulnerability (a GHSA, its CVE, a Go-database record) are grouped.
	Advisories []DependencyAdvisory `json:"advisories,omitempty"`
	// Unsure lists advisories for the package that couldn't be evaluated against this version.
	Unsure []string `json:"unsure,omitempty"`
	// NeedsFix is set when an advisory that needs fixing affects this version: a malicious one
	// always; a high or critical one unless the dependency is Dev (a developer dependency's
	// vulnerabilities are listed, but only malware needs fixing).
	NeedsFix bool `json:"needs_fix,omitempty"`
	// Remove is set when the package itself is the attack (a typosquat): no version is safe.
	Remove bool `json:"remove,omitempty"`
	// Avoid lists the releases a malicious advisory names (chalk 5.6.1), when it names versions
	// rather than the whole package.
	Avoid []string `json:"avoid,omitempty"`
	// Clear is the lowest version that no advisory needing a fix affects; set when NeedsFix, nil
	// when none of the advisories names one. It is set for an indirect dependency too, though the
	// developer message doesn't recommend pinning one.
	Clear *ClearVersion `json:"clear,omitempty"`
}

// DependencyAdvisory is one issue affecting a package.
type DependencyAdvisory struct {
	// IDs are the records describing it, as the feed names them.
	IDs []string `json:"ids"`
	// Aliases are its other names (a CVE) that aren't records here.
	Aliases []string `json:"aliases,omitempty"`
	// Severity is "critical", "high", "moderate", "low" or "unrated".
	Severity string `json:"severity"`
	// Basis is what the severity was decided from: "GitHub rating", "ecosystem label",
	// "CVSS v3 7.5", "Ubuntu priority", "alias GHSA-…".
	Basis     string   `json:"basis,omitempty"`
	Malicious bool     `json:"malicious,omitempty"`
	Summary   string   `json:"summary,omitempty"`
	Fixed     []string `json:"fixed,omitempty"`
}

// ClearVersion is a recommended version.
type ClearVersion struct {
	Version string `json:"version"`
	// SameMajor is false when the lowest clear version is on a later major (a breaking upgrade).
	SameMajor bool `json:"same_major"`
	// Verified is false until package metadata can confirm the version was published and isn't
	// deprecated (LEO-518). It is always false today.
	Verified bool `json:"verified"`
}

// DependencyMessages is the wording for each audience. A nil message means nothing to show.
type DependencyMessages struct {
	// Developer is a non-blocking notice, set only when something needs fixing.
	Developer *string `json:"developer"`
	// DeveloperMarkdown is the same notice as markdown, for a surface that renders it (the agent's
	// reply in the Claude desktop app): each advisory ID links to its record. Set whenever
	// Developer is, by a server that has it; a client falls back to Developer.
	DeveloperMarkdown *string `json:"developer_markdown,omitempty"`
	// Agent is remediation guidance for a blocking response. Nil until SCA blocks (D57).
	Agent *string `json:"agent"`
}
