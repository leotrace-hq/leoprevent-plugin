// Package pathgate answers which paths must never be read or sent for review.
//
// It is shared rather than client-internal because BOTH review paths need the same
// answer: the Stop hook reads a working tree, and the pull-request webhook lane reads a
// customer's changed files from the GitHub API with no checkout at all. A second copy of
// this list is how a newly recognised secret shape comes to be refused on one path and
// egressed on the other, silently and in the direction that matters.
package pathgate

import (
	"path/filepath"
	"strings"
)

// secretBasenames are credential/secret files whose CONTENT is secrets, not code —
// never egressed for review. Matched on the file's base name.
var secretBasenames = map[string]bool{
	"id_rsa": true, "id_dsa": true, "id_ecdsa": true, "id_ed25519": true,
	".netrc": true, ".pgpass": true, ".htpasswd": true, ".npmrc": true,
}

// secretExts are file types that hold key / credential material.
var secretExts = map[string]bool{
	".pem": true, ".key": true, ".pfx": true, ".p12": true, ".keystore": true, ".jks": true,
	// Credential-bearing artifacts — treated as NEVER-EGRESS (dropped before the file
	// is read or sent), not merely inert: leaking a token off the machine is worse than
	// skipping a review. .tfvars/.tfstate carry plaintext Terraform secrets; .har is an
	// HTTP capture that routinely contains auth headers, cookies, and bearer tokens.
	".tfvars": true, ".tfstate": true, ".har": true,
}

// IsSecretPath reports whether a path holds secret/credential material that must NOT
// be egressed for review: private keys, .env files (and .env.<x>), and credential
// stores. The client drops these from the change set BEFORE the inert gate, so a
// secret is never sent to the cloud /review nor read for local selection. The trade
// is deliberate: a secret file is consequently NOT reviewed (we can't review what we
// refuse to read), but leaking a key off the machine is worse than missing a lint on
// a key file. Matched on base name / extension, separator-agnostic.
func IsSecretPath(p string) bool {
	p = strings.ReplaceAll(p, `\`, "/")
	base := p
	if i := strings.LastIndex(p, "/"); i >= 0 {
		base = p[i+1:]
	}
	if secretBasenames[base] {
		return true
	}
	// Three env-file shapes, all secret-bearing: the dotfile (.env), its suffixed
	// variants (.env.production), and the PREFIXED form (prod.env, staging.env,
	// 2.4.8.env) — a common convention that the first two rules miss. Measured in a
	// customer corpus: nine `<name>.env` files egressed for review because only the
	// dotfile shapes were matched. Their content there was benign version pinning, but
	// the name says "environment file", and that is what this function refuses to read.
	if base == ".env" || strings.HasPrefix(base, ".env.") || strings.HasSuffix(base, ".env") {
		return true
	}
	return secretExts[strings.ToLower(filepath.Ext(base))]
}
