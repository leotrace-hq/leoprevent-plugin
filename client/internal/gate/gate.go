// Package gate is the always-on, tier-agnostic relevance gate that runs before
// any review. It is a DENYLIST, not an allowlist: it suppresses only changes it
// can prove are inert (pure prose, or diffs whose every non-blank added line is
// a comment) and lets EVERYTHING else through to the reviewer.
//
// This is a deliberate inversion of the old keyword pre-check. A keyword
// allowlist fails toward "skip" — a vocabulary miss silently drops a real diff,
// the vuln ships, and the developer sees a clean "done" with false assurance.
// That false negative is the dangerous failure for a security tool. The inert
// gate fails toward "review": the worst case is sending a harmless diff to the
// reviewer, which costs a little latency/egress and then comes back silent
// (selection ≠ detection — the judge only speaks on a real finding). We bias
// toward over-sending on purpose.
//
// Safety property: comment detection is START-ANCHORED (a line must START with
// the language's comment marker to count as inert), so a trailing comment on a
// real code line (`x = get(url)  # fetch`) is NOT inert and reaches the reviewer.
package gate

import (
	"log/slog"
	"path/filepath"
	"strings"

	"github.com/go-enry/go-enry/v2"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
	"github.com/leotrace-hq/leoprevent-plugin/pathgate"
)

// nonExecutable are file types we never review: pure prose, lockfiles, and
// COMPILED / BINARY build artifacts (.pyc, .class, .so, …). The latter aren't
// human-authored source — they're generated, often huge/binary, and reviewing
// them is pure noise/cost. Kept deliberately unambiguous; we do NOT list config
// formats (.yaml/.json/.xml/.toml) here because config can be security-relevant
// (CORS, TLS, debug flags, actuator exposure).
var nonExecutable = map[string]bool{
	// prose / docs
	".md":       true,
	".markdown": true,
	".txt":      true,
	".rst":      true,
	".adoc":     true,
	// lockfiles
	".lock": true,
	// compiled / bytecode artifacts
	".pyc":   true,
	".pyo":   true,
	".pyd":   true,
	".class": true,
	".o":     true,
	".obj":   true,
	".a":     true,
	".so":    true,
	".dylib": true,
	".dll":   true,
	".exe":   true,
	".bin":   true,
	".wasm":  true,
	".jar":   true,
	".war":   true,
	// minified / source-map build output (not hand-authored)
	".map": true,
	// locale / translation data — strings, not logic
	".po":    true,
	".pot":   true,
	".mo":    true,
	".arb":   true,
	".xliff": true,
	".xlf":   true,
	// stylesheets — presentation, not logic. CSS is not a nil security surface (an
	// `@import` or a `url()` can reach out, and a selector can exfiltrate an attribute
	// value), but the corpus carries no rule that targets a stylesheet, so today the
	// only outcome of sending one is cost: measured at 13.5% of one customer's egressed
	// bytes, a single 808 KB home.css among them, against zero rules that could fire.
	// REVISIT WHEN the corpus gains a stylesheet pattern — at that point these
	// extensions come back out, and .css/.scss want an entry in rulespec.extLanguage
	// too (absent today, so a stylesheet is offered the whole catalogue).
	".css":     true,
	".scss":    true,
	".sass":    true,
	".less":    true,
	".styl":    true,
	".stylus":  true,
	".pcss":    true,
	".postcss": true,
	// tabular / geographic data — coordinate and record dumps, not logic. A single
	// committed .geojson boundary file measured 129 KB, half the whole payload budget.
	".csv":     true,
	".tsv":     true,
	".geojson": true,
	// logs / run output — generated, often huge, never hand-authored source
	".log": true,
	".err": true,
	".out": true,
	// diffs / patches — a generated representation of a change, not source itself
	".diff":  true,
	".patch": true,
	// line-delimited data / event streams. NB plain .json/.yaml/.xml stay ABSENT
	// (reviewable) because config can be security-relevant; .jsonl/.ndjson are
	// append-only data/logs, not config.
	".jsonl":  true,
	".ndjson": true,
	// binary assets: fonts, raster images, media — never hand-authored source.
	// NB .svg is deliberately ABSENT: it is text and can carry active content
	// (<script>, onload= → stored XSS), so it stays reviewable. The noise is removed
	// instead by svgWithoutActiveContent below — a content check, not a size one.
	".woff":   true,
	".woff2":  true,
	".ttf":    true,
	".eot":    true,
	".otf":    true,
	".png":    true,
	".jpg":    true,
	".jpeg":   true,
	".gif":    true,
	".bmp":    true,
	".ico":    true,
	".webp":   true,
	".avif":   true,
	".pdf":    true,
	".mp4":    true,
	".mp3":    true,
	".wav":    true,
	".mov":    true,
	".avi":    true,
	".mkv":    true,
	".webm":   true,
	".flac":   true,
	".ogg":    true,
	".opus":   true,
	".aac":    true,
	".m4a":    true,
	".heic":   true,
	".heif":   true,
	".psd":    true,
	".ai":     true,
	".sketch": true,
	".fig":    true,
	".icns":   true,

	// archives — containers, never hand-authored source.
	".zip": true,
	".tar": true,
	".gz":  true,
	".tgz": true,
	".bz2": true,
	".xz":  true,
	".zst": true,
	".7z":  true,
	".rar": true,

	// binary data / model / db dumps — opaque blobs, not source.
	".parquet": true,
	".avro":    true,
	".orc":     true,
	".pkl":     true,
	".pickle":  true,
	".npy":     true,
	".npz":     true,
	".h5":      true,
	".hdf5":    true,
	".sqlite":  true,
	".sqlite3": true,
	".db":      true,
	".rdb":     true,
	".dat":     true,

	// compiled / packaged artifacts (ext fast-path; IsBinary also catches these
	// when content is present, but this covers empty/streamed payloads too).
	".node":  true,
	".rlib":  true,
	".rmeta": true,
	".pdb":   true,
	".lib":   true,
	".whl":   true,
	".gem":   true,
	".nupkg": true,
	".beam":  true,
	".ear":   true,
	".nar":   true,

	// backup / temp / patch-reject artifacts — the real file is reviewed instead,
	// so these copies are redundant noise. (.rej/.orig come from failed patch/merge.)
	".bak":  true,
	".orig": true,
	".rej":  true,
	".tmp":  true,
	".temp": true,

	// IDE / editor project metadata.
	".iml": true,
}

// maxHandAuthoredLineLen bounds the longest line we expect in human-written source.
// Minified bundles and committed generated/library blobs (e.g. a MathJax font-data
// file, whose payload sits on a single ~5.5k-char defineImageData(...) line) pack data
// onto pathologically long lines, where hand-authored code almost never exceeds a few
// hundred. One line at/over this length marks the file generated → dropped. The high
// threshold keeps it high-precision (fail toward review): real source never trips it.
const maxHandAuthoredLineLen = 2000

// commentMarkers maps a source extension to the line-comment prefixes for that
// language. A diff is inert only if EVERY non-blank added line starts with one
// of these. Extensions absent from this map (and from nonExecutable) are always
// reviewed — including HTML/XML, where block comments (<!-- -->) make
// line-anchored detection unsafe, so we never treat them as inert.
var commentMarkers = map[string][]string{
	// '#' line comments
	".py":   {"#"},
	".rb":   {"#"},
	".sh":   {"#"},
	".bash": {"#"},
	".zsh":  {"#"},
	".yaml": {"#"},
	".yml":  {"#"},
	".tf":   {"#"},
	".toml": {"#"},
	".ini":  {"#"},
	// NOTE: .env is deliberately NOT here — it holds secrets/config (keys, debug and
	// auth flags), never "just comments", and is dropped from egress entirely upstream
	// (gate.IsSecretPath); listing it as comment-inert would be wrong on both counts.
	".pl":  {"#"},
	".ex":  {"#"},
	".exs": {"#"},
	".ps1": {"#"},
	// '//' line comments
	".js":     {"//"},
	".mjs":    {"//"},
	".cjs":    {"//"},
	".ts":     {"//"},
	".jsx":    {"//"},
	".tsx":    {"//"},
	".go":     {"//"},
	".java":   {"//"},
	".kt":     {"//"},
	".scala":  {"//"},
	".groovy": {"//"},
	".c":      {"//"},
	".cc":     {"//"},
	".cpp":    {"//"},
	".h":      {"//"},
	".hpp":    {"//"},
	".cs":     {"//"},
	".fs":     {"//"},
	".rs":     {"//"},
	".swift":  {"//"},
	".m":      {"//"},
	".mm":     {"//"},
	".dart":   {"//"},
	".vue":    {"//"},
	".svelte": {"//"},
	// '--' line comments
	".sql": {"--"},
	".lua": {"--"},
	// PHP accepts both '//' and '#'
	".php": {"//", "#"},
}

// looksGenerated reports whether the change's CONTENT is machine-generated/minified
// independent of name or extension: a single pathologically long line (see
// maxHandAuthoredLineLen). It scans the full file when present — that is what the
// cloud judge + selector see and what bloats the prompt (a giant committed asset like
// a MathJax font blob) — else the added text. Allocation-free, early-returns on the
// first long line.
func looksGenerated(c transcript.Change) bool {
	body := c.FullContent
	if body == "" {
		body = c.AddedText
	}
	for len(body) > 0 {
		i := strings.IndexByte(body, '\n')
		if i < 0 {
			return len(body) >= maxHandAuthoredLineLen
		}
		if i >= maxHandAuthoredLineLen {
			return true
		}
		body = body[i+1:]
	}
	return false
}

// svgActiveMarkers are the substrings that make an SVG executable rather than
// decorative: an embedded script, an inline event handler, a javascript: or data:
// URL, an HTML island via <foreignObject>, or an external reference pulled in by
// <use>/<image>. Lowercased comparison; `on` handlers are matched as `on…=` below.
var svgActiveMarkers = []string{
	"<script", "<foreignobject", "<handler", "<set", "<animate",
	"javascript:", "data:text/html", "<!entity", "<use", "xlink:href", "href=",
}

// svgWithoutActiveContent reports whether an SVG provably carries no executable
// content and is therefore decoration, not a security surface.
//
// This REPLACES an assumption the gate used to make: that a giant generated SVG is
// caught by the long-line heuristic because its path data sits on one line. Measured
// against customer corpora, that holds for 2 of 10 large SVGs. Design tools pretty-
// print — a 196 KB leo-globe.svg has a longest line of 107 characters, and 48-85 KB
// icon exports run 900-1800 — so the size sailed through while the premise looked
// sound in the comment.
//
// Fails toward review in every direction: any marker, any doubt, and the file is sent.
// Only the added text is available on a diff, which mirrors how the comment-inert path
// already reasons — a change that introduces no active content is not a new surface.
func svgWithoutActiveContent(c transcript.Change) bool {
	body := c.FullContent
	if body == "" {
		body = c.AddedText
	}
	if body == "" {
		return false // nothing to prove inertness with
	}
	lower := strings.ToLower(body)
	for _, m := range svgActiveMarkers {
		if strings.Contains(lower, m) {
			return false
		}
	}
	// Inline event handlers: `on<name>=`, allowing whitespace before the `=`.
	for i := 0; i+2 < len(lower); i++ {
		if lower[i] != 'o' || lower[i+1] != 'n' {
			continue
		}
		if i > 0 && isASCIILetter(lower[i-1]) {
			continue // inside a longer word (version=, button=)
		}
		j := i + 2
		for j < len(lower) && isASCIILetter(lower[j]) {
			j++
		}
		if j == i+2 {
			continue // bare "on", no handler name
		}
		for j < len(lower) && (lower[j] == ' ' || lower[j] == '\t' || lower[j] == '\n' || lower[j] == '\r') {
			j++
		}
		if j < len(lower) && lower[j] == '=' {
			return false
		}
	}
	return true
}

func isASCIILetter(b byte) bool { return ('a' <= b && b <= 'z') || ('A' <= b && b <= 'Z') }

// inert reports whether a single change is provably harmless and can skip review.
// It returns true ONLY for pure-prose files and for source diffs whose every
// non-blank added line is a comment. When in doubt it returns false (review).
func inert(c transcript.Change) bool {
	// Dependency installs / build output are never the dev's own change — drop
	// regardless of extension or content (covers a tracked node_modules and the
	// gitignore-blind transcript fallback).
	if v, byEnry := pathgate.VendoredReason(c.FilePath); v {
		if byEnry {
			// A go-enry heuristic drop (not the explicit hand-list). Usually correct
			// (real vendored tree), but it can misfire on a first-party source file in
			// a cache/env-named dir or with a library-name basename — which would then
			// go UNREVIEWED. Leave a breadcrumb in the client log so such a false
			// negative is discoverable (behavior is unchanged: the file is still dropped).
			slog.Warn("gate: file dropped as vendored by go-enry heuristic (not the explicit hand-list) — if this is first-party source it goes UNREVIEWED", "path", c.FilePath)
		}
		return true
	}

	base := pathgate.BaseLower(c.FilePath)
	// Editor backup copies (emacs/gedit `file~`, and `.#file` / `#file#` locks) — the
	// live file is reviewed instead, so these are redundant. Checked on the raw base
	// (a trailing `~` survives lowercasing).
	if pathgate.IsEditorBackup(c.FilePath) {
		return true
	}
	// Machine-generated dependency locks not caught by the .lock extension below.
	if pathgate.IsLockfile(c.FilePath) {
		return true
	}

	// Test files (unit / integration / e2e) — the dev's own code, but NOT a shipped
	// security surface, and dense with hardcoded test creds + localhost URLs that read
	// as false-positive bait. Path-based, via go-enry's Linguist test matchers (same
	// source as IsVendor/IsGenerated below): *_test.go, *.test.tsx, *.e2e.test.ts,
	// test_*.py, *_spec.rb, *Test.java, … all match. NB this is coarse (all tests, no
	// e2e-vs-unit split) and misses a few conventions enry doesn't track (e.g. Cypress
	// .cy.js) — those still get reviewed, which is the safe direction.
	if pathgate.IsTestPath(c.FilePath) {
		return true
	}

	ext := strings.ToLower(filepath.Ext(c.FilePath))

	if nonExecutable[ext] {
		return true
	}

	// Codegen / minified output (suffix), then a content signal for generated/minified
	// blobs whose name looks hand-authored (e.g. a committed library .js with a single
	// multi-kilobyte data line). Both run BEFORE the comment-marker logic so a minified
	// .js is dropped on content, not mis-scanned line-by-line.
	if pathgate.IsGeneratedName(base) || looksGenerated(c) {
		return true
	}

	// An SVG with no active content. SVG stays reviewable because it can carry a
	// script; when it demonstrably carries none, there is nothing for the judge to
	// find and the file is a large asset like any other .png.
	if ext == ".svg" && svgWithoutActiveContent(c) {
		return true
	}

	// Content-based backstop via go-enry (GitHub Linguist's Go port): generated-code
	// and binary detection, so the hand suffix lists don't grow per codegen tool or
	// binary format. (Path-based third-party detection is handled by vendored() above
	// via enry.IsVendor.) Deliberately EXCLUDED here:
	//   - enry.IsImage: would skip .svg, kept reviewable for SVG-XSS.
	//   - enry.IsConfiguration: config is security-relevant (CORS/TLS/debug flags).
	content := []byte(c.FullContent)
	if len(content) == 0 {
		content = []byte(c.AddedText)
	}
	if enry.IsGenerated(c.FilePath, content) || enry.IsBinary(content) {
		return true
	}

	markers, known := commentMarkers[ext]
	if !known {
		// Unknown extension (or no extension, or HTML/XML) → never assume inert.
		return false
	}

	// Inert iff there is at least one non-blank added line AND every one of them
	// starts with a comment marker. The "at least one" guard matters: an EMPTY
	// AddedText must NOT be deemed inert by vacuous truth — that would be a silent
	// skip of a file we couldn't read added lines for (e.g. a diff that resolved to
	// nothing because of a path/cwd mismatch upstream), which is exactly the
	// false-negative this denylist exists to avoid. No added lines → fail toward
	// review.
	sawLine := false
	for _, line := range strings.Split(c.AddedText, "\n") {
		t := strings.TrimSpace(line)
		if t == "" {
			continue
		}
		sawLine = true
		if !hasAnyPrefix(t, markers) {
			return false
		}
	}
	return sawLine
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// Run returns the subset of changed files that warrant review — i.e. everything
// not provably inert. The gate is a denylist: it fails toward review.
func Run(changes []transcript.Change) []transcript.Change {
	var reviewable []transcript.Change
	for _, c := range changes {
		if !inert(c) {
			reviewable = append(reviewable, c)
		}
	}
	return reviewable
}

// IsSecretPath is pathgate's, re-exported so every call site and test in this package is
// unchanged. It moved because the SERVER needs the same answer: the webhook lane reads a
// customer's changed files from the GitHub API with no checkout, and "never read a secret
// file" cannot be a property of the client alone. Two copies of this list is how a new
// secret shape comes to be refused on one path and egressed on the other.
var IsSecretPath = pathgate.IsSecretPath
