package gate

import (
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
)

// ⚠️ A WORKSPACE CAPTURE PREFIXES EVERY PATH WITH ITS REPOSITORY'S DIRECTORY
// (vcs.repoBaseline.join), so two projects each holding a src/app.py stay apart. Both
// path-based classifiers must keep working under that prefix. Getting this wrong is
// silent and severe in opposite directions: a secret file would start being egressed,
// and a vendored tree would start being reviewed.
func TestSecretPathsStaySecretUnderARepoPrefix(t *testing.T) {
	for _, p := range []string{".env", ".env.production", "config/.env", "keys/id_rsa", "certs/server.pem"} {
		if !IsSecretPath(p) {
			t.Fatalf("fixture wrong: %q is not a secret path to begin with", p)
		}
		if !IsSecretPath("project-a/" + p) {
			t.Errorf("%q stops being a secret path once prefixed with its repo dir", p)
		}
	}
}

func TestInertGateStillDropsVendoredTreesUnderARepoPrefix(t *testing.T) {
	// Segment matching is what makes this work: the prefix adds a leading segment
	// and leaves node_modules/vendor exactly where the matcher looks.
	inertPaths := []string{
		"project-a/node_modules/left-pad/index.js",
		"project-b/vendor/github.com/x/y.go",
		"project-a/__pycache__/mod.cpython-311.pyc",
	}
	var changes []transcript.Change
	for _, p := range inertPaths {
		changes = append(changes, transcript.Change{FilePath: p, AddedText: "x = 1\n"})
	}
	if got := Run(changes); len(got) != 0 {
		t.Errorf("vendored trees must stay inert under a repo prefix, got %d reviewable: %+v", len(got), got)
	}
}

func TestRealCodeIsStillReviewedUnderARepoPrefix(t *testing.T) {
	// The other direction: the prefix must not make ordinary source look inert.
	changes := []transcript.Change{{
		FilePath:  "project-a/src/app.py",
		AddedText: "import requests\nrequests.get(url)\n",
	}}
	if got := Run(changes); len(got) != 1 {
		t.Errorf("prefixed source must still be reviewed, got %d reviewable", len(got))
	}
}
