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
	// Path is the dependency file the packages come from, relative to its repository with
	// forward slashes ("web/package-lock.json"), under the repository's name when a turn spans
	// several: the same form as a /review ChangedFile's path. Never absolute, never "..": an
	// absolute path would carry the developer's home folder. Optional; omitted when unknown.
	Path string `json:"path,omitempty"`
	// Meta is who and where the check is for: the identity half of the TurnMeta /review carries
	// (agent, model, repository, developer, platform, client version, environment), never the
	// prompt or token counts. It lets the server record what the check found against the
	// repository, as review events are (the activity log). Optional.
	Meta *TurnMeta `json:"meta,omitempty"`
	// Trigger is what ran the check: DependencyTriggerScan (the session scan),
	// DependencyTriggerTurn (a turn changed the file) or DependencyTriggerRecheck (the Stop after
	// the agent was woken for the check, looking again at the same turn). Optional.
	Trigger string `json:"trigger,omitempty"`
	// ScanID is the same on every request of one session scan, which sends one request per
	// dependency file. Optional.
	ScanID string `json:"scan_id,omitempty"`
	// Asked is the packages ("name@version") already put to the agent this session from this
	// file. The server leaves them out of Messages.Agent, so the agent is asked about each at most
	// once per session (LEO-620). Optional; at most MaxDependencyPackages, each at most a name and
	// a version long.
	Asked []string `json:"asked,omitempty"`
	// Baseline is DependencyBaselineNone when the client had nothing to compare the file with:
	// the folder isn't a git repository, so no package can be marked as added or changed (LEO-659).
	// The server then puts every package that needs fixing to the agent, whatever its change,
	// and still records each with the change it was sent with. Optional.
	Baseline string `json:"baseline,omitempty"`
}

// DependencyBaselineNone is DependenciesRequest.Baseline for a folder with no git repository.
const DependencyBaselineNone = "none"

// DependenciesRequest.Trigger values.
const (
	DependencyTriggerScan = "scan"
	DependencyTriggerTurn = "turn"
	// DependencyTriggerRecheck is the same turn's files checked again after the agent was woken
	// to fix them (LEO-620). It answers as a turn's check does, but it isn't recorded (the first
	// Stop's record already holds what the turn brought in) and it puts nothing to the agent.
	DependencyTriggerRecheck = "recheck"
)

// DependencyVersion is one package at the version in use.
type DependencyVersion struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	// Line is where the dependency is declared, when the caller knows it, echoed back so a message
	// can point at it. 0 when unknown.
	Line int `json:"line,omitempty"`
	// Locations are where this version is installed or declared in the file, one per copy the
	// entry stands for: npm's install folders ("node_modules/old-lib/node_modules/lodash", which
	// also names the package that brings a copy in), Go's "go.mod:12". At most
	// MaxDependencyLocations; MoreLocations counts the rest. Optional.
	Locations     []string `json:"locations,omitempty"`
	MoreLocations int      `json:"more_locations,omitempty"`
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
	// Agent is what a turn's check puts to the agent (LEO-620): the direct dependencies the turn
	// added or changed to move to a fixed version, and the indirect ones to update or pin if
	// they're still there. Only what the turn added or changed, so on the session scan it covers
	// the turn's own changes and never what was already there. Nil when nothing is put to it. The
	// client decides whether to wake the agent with it.
	Agent *string `json:"agent"`
	// AgentPackages is the packages ("name@version") Agent puts to the agent, so the client can
	// send them back as Asked once it has. Empty when Agent is nil.
	AgentPackages []string `json:"agent_packages,omitempty"`
	// AgentOffer is the session scan's offer, in a git repository (LEO-673): the packages that were
	// already there and need fixing, with a fix on the same major, for the agent to ask the
	// developer once whether to fix, and what to do if they say yes. Nil on any other request, and
	// when there's nothing to offer. The client adds it to the first Stop's wake.
	AgentOffer *string `json:"agent_offer,omitempty"`
	// AgentOfferPackages is the packages ("name@version") AgentOffer covers, so the client can send
	// them back as Asked once it has made the offer.
	AgentOfferPackages []string `json:"agent_offer_packages,omitempty"`
}
