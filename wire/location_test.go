package wire

import "testing"

// TestParseLocation pins the one Go parser for a finding location, including the edge
// cases on which the per-package copies it replaced used to disagree.
func TestParseLocation(t *testing.T) {
	cases := []struct {
		loc  string
		want Location
	}{
		{"app/main.py:42", Location{"app/main.py", 42}},
		{"  app/main.py:42  ", Location{"app/main.py", 42}},
		{"app/main.py: 42", Location{"app/main.py", 42}},
		{"main.py", Location{"main.py", 0}},
		{"", Location{"", 0}},
		// A symbol citation is its own path, not a truncated one.
		{"app.py:fetch", Location{"app.py:fetch", 0}},
		// Line 0 and negatives are not lines.
		{"app.py:0", Location{"app.py:0", 0}},
		{"app.py:-3", Location{"app.py:-3", 0}},
		// A leading colon has no path to cite a line in.
		{":5", Location{":5", 0}},
		{"app.py:", Location{"app.py:", 0}},
		// The LAST colon splits, so a drive letter keeps its head.
		{`C:\src\a.py:7`, Location{`C:\src\a.py`, 7}},
		{`C:\src\a.py`, Location{`C:\src\a.py`, 0}},
	}
	for _, c := range cases {
		got := ParseLocation(c.loc)
		if got != c.want {
			t.Errorf("ParseLocation(%q) = %+v, want %+v", c.loc, got, c.want)
		}
		if got.HasLine() != (c.want.Line > 0) {
			t.Errorf("ParseLocation(%q).HasLine() = %v", c.loc, got.HasLine())
		}
	}
}
