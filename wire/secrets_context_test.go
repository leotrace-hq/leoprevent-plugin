package wire

import (
	"strings"
	"testing"
)

func TestSecretContextBounds(t *testing.T) {
	base := func() SecretDetection {
		return SecretDetection{Happened: SecretSentOut, CheckPoint: SecretBeforeTool, Method: SecretHighEntropy,
			Fingerprint: strings.Repeat("a", 64)}
	}
	ok := base()
	ok.Preview, ok.Length, ok.AssignedTo = "sk_live_q7Vb…e4Ti", 48, "apiKey"
	ok.Tool, ok.Program, ok.Hosts = "Bash", "git push", []string{"github.com", "10.0.0.5"}
	ok.Path, ok.Line = "src/config.js", 3
	ok.Purpose = "Check token length, charset, and checksum locally"
	ok.Subagent = "Explore"
	ok.Expiry, ok.ExpiresOn = SecretExpiresWithinHour, "2026-11-19"
	if err := ValidateSecretDetection(ok); err != nil {
		t.Fatalf("a full context is refused: %v", err)
	}
	for name, mutate := range map[string]func(*SecretDetection){
		"too little left hidden":         func(d *SecretDetection) { d.Preview, d.Length = "q7Vb…e4Ti", 29 },
		"no length to check against":     func(d *SecretDetection) { d.Preview, d.Length = "q7Vb…e4Ti", 0 },
		"more than four at the end":      func(d *SecretDetection) { d.Preview, d.Length = "q7Vb…Ce4Ti", 60 },
		"no ellipsis":                    func(d *SecretDetection) { d.Preview, d.Length = "q7Vb2Lm9", 60 },
		"a prefix too long":              func(d *SecretDetection) { d.Preview, d.Length = strings.Repeat("x", 25)+"…e4Ti", 80 },
		"hosts on a reached_model":       func(d *SecretDetection) { d.Happened, d.Hosts = SecretReachedModel, []string{"github.com"} },
		"a URL as a host":                func(d *SecretDetection) { d.Hosts = []string{"https://github.com/x"} },
		"credentials in a host":          func(d *SecretDetection) { d.Hosts = []string{"user:pw@github.com"} },
		"six hosts":                      func(d *SecretDetection) { d.Hosts = []string{"a.io", "b.io", "c.io", "d.io", "e.io", "f.io"} },
		"an absolute path":               func(d *SecretDetection) { d.Path = "/Users/ada/app/.env" },
		"a line with no path":            func(d *SecretDetection) { d.Path = "" },
		"a value as a name":              func(d *SecretDetection) { d.AssignedTo = "KEY=abc" },
		"a command as a program":         func(d *SecretDetection) { d.Program = "curl -d @.env" },
		"a local destination with hosts": func(d *SecretDetection) { d.LocalDestination = true },
		"a local destination not sent out": func(d *SecretDetection) {
			d.Happened, d.Hosts, d.LocalDestination = SecretReachedModel, nil, true
		},
		"a sentence as a subagent":   func(d *SecretDetection) { d.Subagent = "Explore the repo" },
		"a token in a purpose":       func(d *SecretDetection) { d.Purpose = "Check q7Vb2Lm9Xc4Rt8Zw1Pk6Hs3Nd5Gf0Jy2" },
		"a purpose too long":         func(d *SecretDetection) { d.Purpose = strings.Repeat("check it ", 14) },
		"a newline in a purpose":     func(d *SecretDetection) { d.Purpose = "Check\nit" },
		"an expiry time":             func(d *SecretDetection) { d.Expiry = "2026-11-19T11:00:00Z" },
		"a time in expires_on":       func(d *SecretDetection) { d.ExpiresOn = "2026-11-19T11:00:00Z" },
		"expires_on before 1970":     func(d *SecretDetection) { d.ExpiresOn = "1969-12-31" },
		"expires_on not a date":      func(d *SecretDetection) { d.ExpiresOn = "2026-02-30" },
		"by_developer before a tool": func(d *SecretDetection) { d.ByDeveloper = true },
	} {
		d := ok
		mutate(&d)
		if ValidateSecretDetection(d) == nil {
			t.Errorf("%s: accepted %+v", name, d)
		}
	}
}

func TestSecretLocalDestination(t *testing.T) {
	d := SecretDetection{Happened: SecretSentOut, CheckPoint: SecretBeforeTool, Method: SecretHighEntropy,
		Fingerprint: strings.Repeat("a", 64), Program: "git push", LocalDestination: true}
	if err := ValidateSecretDetection(d); err != nil {
		t.Fatalf("a push to a local folder is refused: %v", err)
	}
}

func TestSecretByDeveloper(t *testing.T) {
	d := SecretDetection{Happened: SecretReachedModel, CheckPoint: SecretAtTurnEnd, Method: SecretKnownExact,
		Source: SecretSourceEnvFile, Name: "SESSION_SECRET", Fingerprint: strings.Repeat("a", 64), Program: "cat", ByDeveloper: true}
	if err := ValidateSecretDetection(d); err != nil {
		t.Fatalf("a developer's own command at turn end is refused: %v", err)
	}
}
