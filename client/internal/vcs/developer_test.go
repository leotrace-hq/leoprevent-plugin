package vcs

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/wire"
)

// isolateGitConfig points git at an empty global and system config, so what a test asserts
// about "no configured identity" is a fact about the fixture and not about whoever's machine
// is running it. Without this every case below passes or fails according to the developer's
// own ~/.gitconfig.
func isolateGitConfig(t *testing.T) {
	t.Helper()
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_SYSTEM", os.DevNull)
}

func TestDeveloperFromPrefersAConfiguredIdentity(t *testing.T) {
	isolateGitConfig(t)
	dir, _ := initRepo(t)
	gitRun(t, dir, "config", "user.name", "Ada Lovelace")
	gitRun(t, dir, "config", "user.email", "ada@acme.com")
	// An env author would satisfy `git var` too, so it is set here deliberately: the
	// configured identity must win over anything git would synthesize.
	t.Setenv("GIT_AUTHOR_NAME", "Someone Else")
	t.Setenv("GIT_AUTHOR_EMAIL", "else@acme.com")

	id, src := DeveloperFrom(dir)
	if id != "Ada Lovelace <ada@acme.com>" || src != wire.DevSourceConfig {
		t.Errorf("DeveloperFrom = %q/%q, want the CONFIGURED identity and %q", id, src, wire.DevSourceConfig)
	}
}

// ⚠️ THE CASE THE LIVE FAULT WAS. `git config --get` reads CONFIG and reports nothing when
// the keys are unset; `git var GIT_AUTHOR_IDENT` asks git to RESOLVE one, which falls back to
// the OS passwd entry plus user@hostname. A seat ran 123 turns over two weeks with `developer`
// empty on every one of them, because we only ever asked the way that returns "".
func TestDeveloperFromFallsBackToGitsResolvedIdent(t *testing.T) {
	isolateGitConfig(t)
	dir, _ := initRepo(t)
	// Env, not config: `git config --get user.email` still finds nothing, exactly as on the
	// affected machine, while `git var` answers. Set rather than left to the machine's own
	// passwd entry so the assertion is the same everywhere.
	t.Setenv("GIT_AUTHOR_NAME", "Ada Lovelace")
	t.Setenv("GIT_AUTHOR_EMAIL", "ada@acme.com")

	if got := gitConfig(dir, "user.email"); got != "" {
		t.Fatalf("fixture is wrong: user.email = %q, want unset", got)
	}
	id, src := DeveloperFrom(dir)
	if id != "Ada Lovelace <ada@acme.com>" || src != wire.DevSourceIdent {
		t.Errorf("DeveloperFrom = %q/%q, want the resolved ident and %q", id, src, wire.DevSourceIdent)
	}
}

// ⚠️ THE TIMESTAMP MUST NOT SURVIVE, and this is the assertion that catches it. `git var`
// returns `Name <email> <unix-seconds> <tz>`, so shipping the raw string would put a DIFFERENT
// `developer` value on every single turn — one leaderboard row per turn, and a de-dup key that
// never matches itself.
func TestParseAuthorIdentDropsTheTimestamp(t *testing.T) {
	got := parseAuthorIdent("Boy Baukema <bbaukema@Boys-MacBook-Pro.local> 1788266145 +0200\n")
	if want := "Boy Baukema <bbaukema@Boys-MacBook-Pro.local>"; got != want {
		t.Errorf("parseAuthorIdent = %q, want %q", got, want)
	}
}

func TestParseAuthorIdentRejectsAnythingThatIsNotAnIdent(t *testing.T) {
	// git prints this INSTEAD of an ident when it cannot determine one, and it is not an
	// error, so the result has to be parsed rather than trusted.
	for _, in := range []string{
		"Author identity unknown\n",
		"",
		"   ",
		"Ada Lovelace",               // a bare name, no address
		"Ada Lovelace <ada> 1 +0000", // bracketed, but not an address
	} {
		if got := parseAuthorIdent(in); got != "" {
			t.Errorf("parseAuthorIdent(%q) = %q, want empty", in, got)
		}
	}
}

// ⚠️ THE WORKSPACE LAYOUT: cwd is the folder the agent was OPENED on, which holds repositories
// rather than being one, so it carries no repo-local config. Repo lives one directory down and
// `Repo` already corrects for exactly this via soleRepoOrigin.
//
// The repo's config must beat what git would synthesize at the parent, so this deliberately
// does NOT set an env author: with the order wrong the result is the machine's own passwd
// identity (or nothing), never the repo's.
func TestDeveloperFromReadsAChangedRepositorysConfig(t *testing.T) {
	isolateGitConfig(t)
	workspace := t.TempDir()
	repo := filepath.Join(workspace, "payments")
	if err := os.Mkdir(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	gitRun(t, repo, "init", "-q", "-b", "master")
	gitRun(t, repo, "config", "user.name", "Ada Lovelace")
	gitRun(t, repo, "config", "user.email", "ada@acme.com")

	id, src := DeveloperFrom(workspace, repo)
	if id != "Ada Lovelace <ada@acme.com>" || src != wire.DevSourceRepo {
		t.Errorf("DeveloperFrom = %q/%q, want the repo's identity and %q", id, src, wire.DevSourceRepo)
	}
}

// The turn's own directory is never re-read as an "also try": it would report DevSourceRepo for
// an identity that came from cwd, which is the one thing the source field must not get wrong.
func TestDeveloperFromDoesNotRelabelTheTurnsOwnDirectory(t *testing.T) {
	isolateGitConfig(t)
	dir, _ := initRepo(t)
	gitRun(t, dir, "config", "user.email", "ada@acme.com")

	_, src := DeveloperFrom(dir, dir)
	if src != wire.DevSourceConfig {
		t.Errorf("source = %q, want %q", src, wire.DevSourceConfig)
	}
}
