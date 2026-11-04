package wire

import (
	"fmt"
	"strings"
	"testing"
)

func numbered(n int) string {
	var b strings.Builder
	for i := 1; i <= n; i++ {
		fmt.Fprintf(&b, "line %04d\n", i)
	}
	return b.String()
}

func TestSliceAroundLeavesASmallFileWhole(t *testing.T) {
	// Arrange
	full := numbered(10)

	// Act
	body, start := SliceAround(full, []int{5}, 1<<20)

	// Assert
	if body != full || start != 1 {
		t.Fatalf("got start %d, body changed %v", start, body != full)
	}
}

func TestSliceAroundCentresOnTheChangeInWholeLines(t *testing.T) {
	// Arrange
	full := numbered(1000)

	// Act
	body, start := SliceAround(full, []int{600}, 1000)

	// Assert
	lines := strings.Split(strings.TrimSuffix(body, TruncatedMarker), "\n")
	lines = lines[:len(lines)-1]
	if len(lines) != 100 {
		t.Fatalf("kept %d lines, want 100", len(lines))
	}
	if start != 550 {
		t.Errorf("start = %d, want 550 (the change centred)", start)
	}
	for i, ln := range lines {
		if want := fmt.Sprintf("line %04d", start+i); ln != want {
			t.Fatalf("row %d = %q, want %q", i, ln, want)
		}
	}
	if !strings.HasSuffix(body, "\n"+TruncatedMarker) {
		t.Errorf("a cut end must carry the marker: %q", body[len(body)-30:])
	}
}

func TestSliceAroundSpendsTheUnusedSideOnTheOther(t *testing.T) {
	// Arrange
	full := numbered(1000)

	// Act
	body, start := SliceAround(full, []int{995}, 1000)

	// Assert
	if start != 901 {
		t.Errorf("start = %d, want 901", start)
	}
	if strings.Contains(body, "truncated") {
		t.Error("the end of the file was kept, so no end marker")
	}
	if !strings.HasSuffix(body, "line 1000\n") {
		t.Errorf("last line missing: %q", body[len(body)-20:])
	}
}

func TestSliceAroundCoversEveryAnchorWhenTheSpanFits(t *testing.T) {
	// Arrange
	full := numbered(1000)

	// Act
	body, start := SliceAround(full, []int{700, 300, 1001}, 1000)

	// Assert
	if start != 250 {
		t.Errorf("start = %d, want 250: a span wider than the budget centres on its first line", start)
	}
	if !strings.Contains(body, "line 0300\n") {
		t.Error("first anchor missing")
	}

	// Act
	body, start = SliceAround(full, []int{560, 520, 541}, 1000)

	// Assert
	if !strings.Contains(body, "line 0520\n") || !strings.Contains(body, "line 0560\n") || start > 520 {
		t.Errorf("span 520..560 not covered from start %d", start)
	}
}

func TestSliceAroundWithNoAnchorsKeepsTheTop(t *testing.T) {
	// Arrange
	full := numbered(1000)

	// Act
	body, start := SliceAround(full, nil, 1000)

	// Assert
	if start != 1 || !strings.HasPrefix(body, "line 0001\n") || !strings.HasSuffix(body, "line 0100\n"+TruncatedMarker) {
		t.Errorf("start %d, body edges %q / %q", start, body[:10], body[len(body)-30:])
	}
}

func TestSliceAroundClampsARemovalPastTheEnd(t *testing.T) {
	// Arrange
	full := numbered(1000)

	// Act
	body, start := SliceAround(full, []int{1001}, 1000)

	// Assert
	if start != 901 || !strings.HasSuffix(body, "line 1000\n") {
		t.Errorf("start %d", start)
	}
}

func TestSliceAroundFallsBackOnALineOverTheBudget(t *testing.T) {
	// Arrange
	full := "short\n" + strings.Repeat("é", 2000) + "\nshort\n"

	// Act
	body, start := SliceAround(full, []int{2}, 1001)

	// Assert
	if start != 1 || !strings.HasSuffix(body, TruncatedMarker) || !strings.HasPrefix(body, "short\n") {
		t.Errorf("start %d", start)
	}
	if strings.ContainsRune(body, '�') || !strings.HasPrefix(strings.TrimSuffix(body, "\n"+TruncatedMarker), "short\n") {
		t.Error("cut split a rune")
	}
}

func TestStartLineReadsAbsentAsOne(t *testing.T) {
	// Arrange
	cases := map[int]int{0: 1, -3: 1, 1: 1, 42: 42}

	for in, want := range cases {
		// Act
		got := ChangedFile{BodyStartLine: in}.StartLine()

		// Assert
		if got != want {
			t.Errorf("StartLine(%d) = %d, want %d", in, got, want)
		}
	}
}
