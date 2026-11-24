package pathgate

import "testing"

func TestIsEnvFile(t *testing.T) {
	for p, want := range map[string]bool{
		".env": true, "a/b/.env.local": true, `c:\repo\prod.env`: true, ".env.example": true,
		"env": false, ".envrc": false, "environment.txt": false, "a/.env/config": false, "main.go": false,
	} {
		if got := IsEnvFile(p); got != want {
			t.Errorf("IsEnvFile(%q) = %v, want %v", p, got, want)
		}
		if want && !IsSecretPath(p) {
			t.Errorf("IsSecretPath(%q) = false for an env file", p)
		}
	}
}
