package sweep

import (
	"strings"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

func TestMaskedLinesNeverCarryTheSecret(t *testing.T) {
	// Arrange
	cases := []struct {
		line   string
		secret string
	}{
		{`const apiKey = "sk_live_51HxYz9AbCdEfGhIjKlMn";`, "sk_live_51HxYz9AbCdEfGhIjKlMn"},
		{`AWS_SECRET_ACCESS_KEY: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`, "wJalrXUtnFEMI"},
		{`password: hunter2`, "hunter2"},
		{`password = hunter`, "hunter"},
		{`db_url = 'postgres://admin:s3cretPw@db.internal:5432/app'`, "s3cretPw"},
		{`token := ` + "`ghp_16C7e42F292c6912E7710c838347Ae178B4a`", "ghp_16C7e42F292c6912E7710c838347Ae178B4a"},
		{`login(user, "correcthorse")`, "correcthorse"},
		{`# the old key was abcd1234efgh5678`, "abcd1234efgh5678"},
		{`call(AKIAIOSFODNN7EXAMPLE)`, "AKIAIOSFODNN7EXAMPLE"},
		{`    MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj`, "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj"},
		{`secret = "unterminated hunter2`, "hunter2"},
		{`{"api_key": "abc123def456"}`, "abc123def456"},
		{`    letmein`, "letmein"},
		{`key = "a\"quoted\"secret"`, "secret"},
		{`if password == "letmein":`, "letmein"},
		{`    case "hunter":`, "hunter"},
		{`case "hunter": return true`, "hunter"},
		{`password: hunter.two`, "hunter.two"},
		{`login(hunter.twofold)`, "hunter.twofold"},
		{`if token != "opensesame": raise Denied`, "opensesame"},
	}

	for _, c := range cases {
		// Act
		got := maskLine(c.line, true)

		// Assert
		if strings.Contains(got, c.secret) {
			t.Errorf("maskLine(%q) = %q, still carries %q", c.line, got, c.secret)
		}
	}
}

func TestMaskedLinesKeepWhatTellsAFalsePositiveApart(t *testing.T) {
	// Arrange
	cases := []struct {
		line string
		want []string
	}{
		{`const key = process.env.STRIPE_KEY;`, []string{"const key = process.env.STRIPE_KEY;"}},
		{`password: ${DB_PASSWORD}`, []string{"password: ${DB_PASSWORD}"}},
		{`token = os.Getenv("API_TOKEN")`, []string{"token = os.Getenv(", "[masked: 9 chars, upper+symbols"}},
		{`{"api_key": "your-api-key-here"}`, []string{`"api_key": "[masked: 17 chars`, "looks like a placeholder"}},
		{`secret = ""`, []string{`secret = ""`}},
		{`password = "xxxxxxxx"`, []string{"looks like a placeholder"}},
		{`# example credentials, not real`, []string{"# [comment masked: 29 chars, mentions example]"}},
	}

	for _, c := range cases {
		// Act
		got := maskLine(c.line, true)

		// Assert
		for _, w := range c.want {
			if !strings.Contains(got, w) {
				t.Errorf("maskLine(%q) = %q, want it to contain %q", c.line, got, w)
			}
		}
	}
}

func TestExcerptSendsOnlyTheFlaggedLinesAndTheirNeighboursMasked(t *testing.T) {
	// Arrange
	var lines []string
	for i := 1; i <= 20; i++ {
		lines = append(lines, "line"+strings.Repeat("x", i))
	}
	lines[9] = `key = "s3cr3tValue0123456789"`
	lines[15] = `token = "anotherSecret98765"`
	content := strings.Join(lines, "\n")

	// Act
	got, start := Excerpt(content, []wire.SweepSpan{{Start: 10, End: 10}, {Start: 16, End: 16}})

	// Assert
	if start != 8 {
		t.Fatalf("start = %d, want 8", start)
	}
	out := strings.Split(got, "\n")
	if len(out) != 11 {
		t.Fatalf("excerpt has %d lines, want 11 (lines 8 to 18): %q", len(out), got)
	}
	if out[5] != "" || out[6] != lines[13] {
		t.Fatalf("line 13 is not near a secret and must be blank, line 14 is: %q", out)
	}
	if strings.Contains(got, "s3cr3tValue") || strings.Contains(got, "anotherSecret") {
		t.Fatalf("excerpt leaks: %q", got)
	}
}

func TestExcerptOfLinesNoLongerInTheFileIsEmpty(t *testing.T) {
	// Arrange
	content := "a\nb\n"

	// Act
	got, start := Excerpt(content, []wire.SweepSpan{{Start: 40, End: 40}})

	// Assert
	if got != "" || start != 0 {
		t.Fatalf("Excerpt = %q, %d", got, start)
	}
}
