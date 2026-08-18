package imports

import (
	"testing"
	"time"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
)

// The slicer runs ON THE DEVELOPER'S STOP-HOOK PATH, so its own cost is part of the
// latency it is meant to reduce. It reads no extra files (the helper is already
// being read to be sent) and does no model work, but it does scan every line of
// every resolved helper, so the claim needs a number rather than an assurance.
//
//	go test -run TestSliceCostsNothingOnTheHookPath -v ./client/internal/imports/
func TestSliceCostsNothingOnTheHookPath(t *testing.T) {
	root := measureRoot(t)
	turns, _ := measureTurns(t, root, measureCorpus(t, root))
	if len(turns) == 0 {
		t.Skip("no turn in this repo resolves imported context")
	}

	timeArm := func(slice bool) time.Duration {
		sliceBodies = slice
		best := time.Hour
		for run := 0; run < 3; run++ { // best of 3: this box is shared, and we want the floor
			t0 := time.Now()
			for _, ch := range turns {
				Resolve(root, []transcript.Change{ch})
			}
			if d := time.Since(t0); d < best {
				best = d
			}
		}
		return best
	}
	off := timeArm(false)
	on := timeArm(true)
	sliceBodies = true

	perTurnOff := off / time.Duration(len(turns))
	perTurnOn := on / time.Duration(len(turns))
	t.Logf("resolve over %d turns: whole-file %v (%v/turn) -> sliced %v (%v/turn), slicing adds %v/turn",
		len(turns), off.Round(time.Millisecond), perTurnOff.Round(time.Microsecond),
		on.Round(time.Millisecond), perTurnOn.Round(time.Microsecond),
		(perTurnOn - perTurnOff).Round(time.Microsecond))

	// A budget, not a benchmark: the point is that this is nowhere near the network
	// call it saves. Generous enough not to flake on a shared runner, tight enough to
	// catch an accidental quadratic.
	if perTurnOn > 50*time.Millisecond {
		t.Errorf("slicing costs %v per turn on the hook path — too much for a saving measured in model time", perTurnOn)
	}
}
