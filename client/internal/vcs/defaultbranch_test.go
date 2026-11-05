package vcs

import "testing"

// originHead points refs/remotes/origin/HEAD at origin/<branch>, as a clone leaves it, with no
// remote to fetch from.
func originHead(t *testing.T, dir, branch string) {
	t.Helper()
	gitRun(t, dir, "update-ref", "refs/remotes/origin/"+branch, "HEAD")
	gitRun(t, dir, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/"+branch)
}

func describe(b *bool) string {
	if b == nil {
		return "nil"
	}
	if *b {
		return "true"
	}
	return "false"
}

func TestOnDefaultBranch(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, dir string)
		want  string
	}{
		{"no origin, on master", func(t *testing.T, dir string) {}, "true"},
		{"no origin, on main", func(t *testing.T, dir string) {
			gitRun(t, dir, "branch", "-m", "master", "main")
		}, "true"},
		{"no origin, main preferred over master", func(t *testing.T, dir string) {
			gitRun(t, dir, "branch", "main") // master stays checked out
		}, "false"},
		{"no origin, feature branch beside main", func(t *testing.T, dir string) {
			gitRun(t, dir, "branch", "-m", "master", "main")
			gitRun(t, dir, "checkout", "-q", "-b", "feature")
		}, "false"},
		{"origin/HEAD, on its branch", func(t *testing.T, dir string) {
			originHead(t, dir, "master")
		}, "true"},
		{"origin/HEAD, on a feature branch", func(t *testing.T, dir string) {
			originHead(t, dir, "master")
			gitRun(t, dir, "checkout", "-q", "-b", "feature")
		}, "false"},
		{"origin/HEAD names develop, on develop", func(t *testing.T, dir string) {
			gitRun(t, dir, "branch", "-m", "master", "develop")
			gitRun(t, dir, "branch", "main")
			originHead(t, dir, "develop")
		}, "true"},
		{"origin/HEAD names develop, on main", func(t *testing.T, dir string) {
			gitRun(t, dir, "branch", "develop")
			gitRun(t, dir, "branch", "-m", "master", "main")
			originHead(t, dir, "develop")
		}, "false"},
		{"detached HEAD", func(t *testing.T, dir string) {
			gitRun(t, dir, "checkout", "-q", "--detach")
		}, "nil"},
		{"no origin, neither main nor master", func(t *testing.T, dir string) {
			gitRun(t, dir, "branch", "-m", "master", "trunk")
		}, "nil"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir, _ := initRepo(t)
			tc.setup(t, dir)
			if got := describe(OnDefaultBranch(dir)); got != tc.want {
				t.Errorf("OnDefaultBranch = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestOnDefaultBranchNotARepository(t *testing.T) {
	if got := OnDefaultBranch(t.TempDir()); got != nil {
		t.Errorf("a folder with no repository = %s, want nil", describe(got))
	}
	if got := OnDefaultBranch(""); got != nil {
		t.Errorf("an empty root = %s, want nil", describe(got))
	}
}
