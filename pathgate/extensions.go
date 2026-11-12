// Inert extensions: file types the review never reads, by NAME alone.
//
// Moved here from client/internal/gate (LEO-528) so the pull-request lane shares it:
// until then the lane dropped tests, lockfiles and vendored trees through InertReason but
// still fetched and judged prose and stylesheets diff-only, measured at 17 MB of added
// markdown in one month against a corpus with no rule that can fire on prose.

package pathgate

import (
	"path/filepath"
	"strings"
)

// inertExtensions are file types we never review: pure prose, lockfiles, and
// COMPILED / BINARY build artifacts (.pyc, .class, .so, …). The latter aren't
// human-authored source — they're generated, often huge/binary, and reviewing
// them is pure noise/cost. Kept deliberately unambiguous; we do NOT list config
// formats (.yaml/.json/.xml/.toml) here because config can be security-relevant
// (CORS, TLS, debug flags, actuator exposure).
var inertExtensions = map[string]bool{
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

	".swp":          true,
	".swo":          true,
	".swn":          true,
	".pid":          true,
	".tsbuildinfo":  true,
	".lcov":         true,
	".heapsnapshot": true,
	".cpuprofile":   true,
	".hprof":        true,
	".pprof":        true,
	".prof":         true,
	".dmp":          true,
	".mdmp":         true,
}

// IsInertExtension reports a file the review never reads, by extension: prose, locks,
// compiled or packaged artifacts, stylesheets, data dumps, logs, media and the rest of
// inertExtensions. Separator-agnostic and case-insensitive.
func IsInertExtension(p string) bool {
	return inertExtensions[strings.ToLower(filepath.Ext(p))]
}
