package imports

import (
	"sort"
	"strings"
)

// Selective function pulling: an imported helper is egressed as the SPANS the
// changed code actually needs, not the whole file.
//
// Whole-file context was the first shape of imported context, and it is wasteful
// in the way that costs twice: the payload goes to BOTH server models (Haiku
// select, then Sonnet judge), so every byte of an unreferenced function body is
// paid for twice per review, in tokens and in time-to-first-token. A helper module
// is typically one referenced function among a dozen, so most of what we send is
// code nothing in the diff can reach.
//
// The rule is deliberately INVERTED from "pull the function": we KEEP everything
// and DROP only the BODIES of functions the changed code cannot reach. Imports,
// module-level constants, class/type declarations, decorators and every signature
// stay. That direction is what makes a parser miss safe — an undetected span is
// simply kept, so degradation costs bytes, never context. The alternative
// ("extract the matched function") would make every parser gap a silent context
// loss, i.e. a missed vuln with a clean verdict, which is the one failure this
// pipeline never accepts.
//
// Reachability is intra-file transitive: a span is kept when the added code
// references its name, or when a kept span's body does (bounded rounds). A dropped
// body leaves its signature line behind, so the judge can see what was elided and
// the line numbers of everything after it are unaffected — the excerpt carries each
// retained line's REAL file line number (wire.ContextFile.Lines), exactly as a
// changed file's diff extract does, so a cited file:line stays true and the gaps
// are visible as jumps.

// maxReachRounds bounds the intra-file transitive closure. Three hops past the
// call in the diff is well beyond any helper chain worth pulling, and the bound
// keeps a pathological file from quadratic scanning on the dev's path.
const maxReachRounds = 3

// An excerpt has to earn its gaps. Reading a file with elisions is marginally
// harder for the judge than reading it whole, and any reachability analysis can be
// wrong — a risk that does not shrink with the file, while the saving does. So a
// slice must clear both a meaningful FRACTION of the file and an absolute floor of
// a few lines; a small helper travels whole, where the saving would be rounding
// error against the changed code it accompanies.
const (
	minSliceSaving = 0.15
	minSliceBytes  = 160
)

// span is one function/method in a source file, 1-based and inclusive.
//
// docStart..start-1 is the doc comment written immediately above the declaration,
// start..headEnd is the header (decorators, the signature, any continuation lines
// up to the opening brace or colon), and headEnd+1..end is the body. The SIGNATURE
// always travels. The doc and the body travel together: they describe the same
// code, so a function the change cannot reach carries neither, while one it can
// reach carries both. docStart == start when there is no doc comment.
//
// Dropping the doc with the body is worth calling out because it is the larger
// half on a documented codebase: this repo's own dashboard module is 614 KB, of
// which 192 KB is comment blocks sitting ABOVE functions rather than inside them.
// Keeping every one of those to accompany a signature whose body was elided is
// paying the maintainer's prose for code the diff cannot call.
type span struct {
	name     string
	docStart int
	start    int
	headEnd  int
	end      int
}

// sliceFile returns the excerpt of content the changed code can actually reach,
// with each retained line's real 1-based file line number.
//
// ok=false means "send the whole file": no spans were detected, nothing matched,
// or the excerpt saves too little to be worth the gaps. Every failure path lands
// here, so a parser that does not understand a file costs bytes and never context.
func sliceFile(relpath, content string, refs map[string]bool, maxBytes int, named bool) (excerpt string, nums []int, ok bool) {
	if strings.TrimSpace(content) == "" {
		return "", nil, false
	}
	lines := strings.Split(strings.TrimRight(content, "\n"), "\n")
	spans := funcSpans(langOf(relpath), lines)
	if len(spans) == 0 {
		return "", nil, false
	}

	depth := reachable(spans, lines, refs)
	if !anyKept(depth) && named {
		// A NAMED pull: the import gate established that a symbol defined in this
		// file was written in the added code. If no span looks reachable, the slicer
		// is the thing that is wrong, not the gate — so send everything rather than
		// turn a parser gap into a missing sink.
		//
		// An UNNAMED pull gets no such benefit and falls through to the skeleton
		// below. Nothing claimed a symbol here: a Go import named the package and
		// took every file in it, a `export * from` re-export had no binding to gate
		// on. Sending those whole was the largest single cost in this resolver
		// (three quarters of the fallback, measured) and it rested on a premise no
		// import had made.
		return "", nil, false
	}
	depth = fitBudget(spans, lines, depth, maxBytes)

	excerpt, nums = build(lines, spans, depth)
	saved := len(content) - len(excerpt)
	if len(excerpt) > maxBytes || saved < minSliceBytes || float64(saved) < float64(len(content))*minSliceSaving {
		return "", nil, false
	}
	return excerpt, nums, true
}

// build renders the excerpt: every line except the bodies of spans depth marks
// unreachable, with each retained line's real 1-based file number.
func build(lines []string, spans []span, depth []int) (string, []int) {
	drop := make([]bool, len(lines))
	for i, sp := range spans {
		if depth[i] >= 0 {
			continue
		}
		for ln := sp.docStart; ln < sp.start && ln <= len(lines); ln++ {
			drop[ln-1] = true
		}
		for ln := sp.headEnd + 1; ln <= sp.end && ln <= len(lines); ln++ {
			drop[ln-1] = true
		}
	}
	var b strings.Builder
	var nums []int
	for i, ln := range lines {
		if drop[i] {
			continue
		}
		b.WriteString(ln)
		b.WriteByte('\n')
		nums = append(nums, i+1)
	}
	return strings.TrimRight(b.String(), "\n"), nums
}

// fitBudget drops reachable spans until the excerpt fits maxBytes, FURTHEST FIRST:
// the deepest transitive hops go before the functions the diff names directly, and
// within a hop the largest body goes first so the fewest elisions buy the most room.
//
// This is what a file too big for the per-file cap should degrade to. Falling back
// to the whole file means capBytes, i.e. the first maxBytes of it — and on a large
// module that is simply wherever the file happens to start. Measured on this repo:
// a change importing the dashboard's root component sent lines 1-1854 of a
// 9,925-line file, containing not one of the components the change referenced. The
// same budget spent on reachable spans carries the code the judge was given the
// file for, and the elisions stay visible as gaps in the line numbers either way.
//
// Directly-named spans (depth 0) go LAST and only when nothing else is left. A file
// whose module-level code plus one called function already overflows the cap has no
// good rendering, but the excerpt is still the better one: it carries every
// signature and all module-level code from ACROSS the file, where the whole-file
// fallback carries whatever the first maxBytes happen to cover. On the dashboard
// module measured above that is the difference between the file's real structure
// and its first 18%. If the module-level content alone overflows, sliceFile falls
// back to the whole file — there is nothing left to trade.
func fitBudget(spans []span, lines []string, depth []int, maxBytes int) []int {
	size := func(sp span) int {
		n := 0
		for ln := sp.docStart; ln < sp.start && ln <= len(lines); ln++ {
			n += len(lines[ln-1]) + 1
		}
		for ln := sp.headEnd + 1; ln <= sp.end && ln <= len(lines); ln++ {
			n += len(lines[ln-1]) + 1
		}
		return n
	}
	total := 0
	for i, ln := range lines {
		_ = i
		total += len(ln) + 1
	}
	for i := range spans {
		if depth[i] < 0 {
			total -= size(spans[i])
		}
	}
	if total <= maxBytes {
		return depth
	}
	order := make([]int, 0, len(spans))
	for i := range spans {
		if depth[i] >= 0 {
			order = append(order, i)
		}
	}
	sort.Slice(order, func(a, b int) bool {
		x, y := order[a], order[b]
		if depth[x] != depth[y] {
			return depth[x] > depth[y]
		}
		return size(spans[x]) > size(spans[y])
	})
	for _, i := range order {
		if total <= maxBytes {
			break
		}
		total -= size(spans[i])
		depth[i] = -1
	}
	return depth
}

func anyKept(depth []int) bool {
	for _, d := range depth {
		if d >= 0 {
			return true
		}
	}
	return false
}

// reachable returns each span's hop distance from the added code: 0 when the diff
// names it, 1 when a directly-named body names it, and so on to maxReachRounds;
// -1 when nothing reaches it. A span with no parseable name is treated as directly
// reached — we cannot show it is unreachable, so we do not drop it.
//
// The distance is not only a keep/drop flag: fitBudget spends a constrained budget
// nearest-first with it.
func reachable(spans []span, lines []string, refs map[string]bool) []int {
	depth := make([]int, len(spans))
	frontier := make([]int, 0, len(spans))
	for i, sp := range spans {
		depth[i] = -1
		if sp.name == "" || refs[sp.name] {
			depth[i] = 0
			frontier = append(frontier, i)
		}
	}
	for round := 1; round <= maxReachRounds && len(frontier) > 0; round++ {
		inner := map[string]bool{}
		for _, i := range frontier {
			for _, id := range identRe.FindAllString(bodyText(lines, spans[i]), -1) {
				inner[id] = true
			}
		}
		frontier = frontier[:0]
		for i, sp := range spans {
			if depth[i] >= 0 || sp.name == "" || !inner[sp.name] {
				continue
			}
			depth[i] = round
			frontier = append(frontier, i)
		}
	}
	return depth
}

func bodyText(lines []string, sp span) string {
	lo, hi := sp.start-1, sp.end
	if lo < 0 {
		lo = 0
	}
	if hi > len(lines) {
		hi = len(lines)
	}
	if lo >= hi {
		return ""
	}
	return strings.Join(lines[lo:hi], "\n")
}

// funcSpans dispatches to the per-language span finder. An unknown language yields
// none, which sends the whole file.
func funcSpans(l lang, lines []string) []span {
	switch l {
	case langPython:
		return pySpans(lines)
	case langJS, langJava, langGo, langCSharp:
		return braceSpans(l, lines)
	}
	return nil
}
