package selector

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
	"github.com/leotrace-hq/leoprevent-plugin/rulespec"
)

func idSet(list []string) map[string]bool {
	out := map[string]bool{}
	for _, id := range list {
		out[id] = true
	}
	return out
}

func change(code string) []transcript.Change {
	return []transcript.Change{{FilePath: "/p/x", AddedText: code}}
}

// TestFamilyBranches exercises one representative snippet per decision-tree
// family and asserts the family's primary rule is selected. A regression here
// means a branch stopped firing; add/repair the signal.
func TestFamilyBranches(t *testing.T) {
	cases := []struct {
		name string
		code string
		want string // a primary rule ID the family must select
	}{
		{"http-client", `resp = requests.get(url)`, "ssrf"},
		{"request-input", `@app.route("/x")` + "\n" + `def x(): q = request.args.get("q")`, "no-input-validation"},
		{"sql", `cursor.execute("SELECT * FROM t WHERE id = " + uid)`, "sql-injection"},
		{"sql-orm-raw", `qs = Model.objects.raw(query)`, "sql-injection"},
		{"nosql", `db.users.find({"$where": q})`, "nosql-injection"},
		{"subprocess", `subprocess.run(cmd, shell=True)`, "os-command-injection"},
		{"php-shell-exec", `$out = shell_exec($cmd);`, "os-command-injection"},
		{"html-output", `el.innerHTML = data`, "xss-backend"},
		{"redirect", `return redirect(target)`, "open-redirect"},
		{"deserialization", `obj = pickle.loads(data)`, "unsafe-deserialization"},
		{"ml-deserialization", `model = torch.load(checkpoint_path)`, "unsafe-deserialization"},
		{"eval", `result = eval(expr)`, "eval-injection"},
		{"template", `Template.from_string(src).render()`, "ssti"},
		{"reflection", `val = getattr(obj, name)`, "unsafe-reflection"},
		{"file-ops", `open(os.path.join(base, name))`, "path-traversal"},
		{"crypto", `digest = hashlib.md5(data)`, "weak-crypto-algorithm"},
		{"random", `pin = random.randint(0, 9999)`, "weak-randomness"},
		{"password-hashing", `pw_hash = bcrypt.hashpw(pw, salt)`, "insecure-password-storage"},
		{"secrets-literal", `api_key = "sk-live-abc123"`, "hardcoded-secrets"},
		{"tls-config", `requests.get(u, verify=False)`, "tls-cert-validation-disabled"},
		{"jwt", `jwt.decode(token, verify=False)`, "jwt-verification"},
		{"auth-session", `def login(u):` + "\n" + `    session["uid"] = u.id`, "idor-object-level-authz"},
		{"cookie", `resp.set_cookie("s", v, samesite="None")`, "csrf-samesite-none"},
		{"cors", `resp.headers["Access-Control-Allow-Origin"] = origin`, "insecure-cors"},
		{"xml", `tree = etree.parse(payload)`, "xxe"},
		{"ldap", `conn.search(ldap_filter)` + "\n" + `import ldap`, "ldap-injection"},
		{"logging", `logger.info("user %s", data)`, "sensitive-data-in-logs"},
		{"error-response", `return str(e), 500`, "verbose-error-messages"},
		{"debug-flag", `app.run(debug=True)`, "debug-mode-enabled"},
		{"object-merge", `Object.assign(target, userInput)`, "prototype-pollution"},
		{"model-binding", `User.update(params)`, "mass-assignment"},
		{"spring-actuator", `management.endpoints.web.exposure.include=*`, "spring-boot-actuator-exposure"},
		{"ci-workflow", `run: echo "${{ github.event.issue.title }}"`, "ci-workflow-injection"},
		{"file-upload", `f = request.files["file"]` + "\n" + `f.save(path)`, "insecure-file-upload"},
		{"browser-storage", `localStorage.setItem("token", jwt)`, "client-storage-of-secrets"},
		{"postmessage", `window.addEventListener("message", handler)`, "postmessage-origin-validation"},
		{"credential-write", `def register(username, pw):` + "\n" + `    users.upsert(username, hashpw(pw))`, "unverified-credential-write"},
		{"host-header", `link = request.host_url + "/reset/" + token`, "host-header-trust"},
		{"proxy-config", `location /docs { alias /var/www/docs/; }`, "proxy-path-handling"},
		{"debug-endpoint", `@app.route("/debug/vars")` + "\n" + `def dv(): return jsonify(dict(os.environ))`, "debug-endpoint-exposure"},
		{"regex-nested-quantifier", `re.fullmatch(r"(\w+)+", request.args["v"])`, "redos-catastrophic-backtracking"},
		{"pii-export", `rows = engaged_users(current_user)` + "\n" + `return csv([(u.email, u.full_name) for u in rows])`, "excessive-pii-exposure"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := idSet(SelectIDs(change(tc.code)))
			if !got[tc.want] {
				t.Errorf("family %q: expected %q selected, got %v", tc.name, tc.want, got)
			}
		})
	}
}

// --- acceptance cases ---

func TestSSRFDiffSelectsSSRF(t *testing.T) {
	got := idSet(SelectIDs(change(`@app.route("/refresh")
def refresh():
    url = request.args["url"]
    resp = requests.get(url)
    return resp.text
`)))
	if !got["ssrf"] {
		t.Errorf("expected ssrf, got %v", got)
	}
	if len(got) > MaxRules {
		t.Errorf("cap exceeded: %d", len(got))
	}
}

func TestSQLConcatDiffSelectsSQLInjection(t *testing.T) {
	got := idSet(SelectIDs(change(`def get_user(user_id):
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)
    return cursor.fetchone()
`)))
	if !got["sql-injection"] {
		t.Errorf("expected sql-injection, got %v", got)
	}
}

func TestReflectedInputDiffSelectsXSS(t *testing.T) {
	got := idSet(SelectIDs(change(`@app.route("/welcome")
def welcome():
    name = request.args.get("name", "stranger")
    return f"Welcome, {name}!"
`)))
	if !got["xss-backend"] || !got["no-input-validation"] {
		t.Errorf("expected xss-backend + no-input-validation, got %v", got)
	}
}

func TestNeutralDiffSelectsNothing(t *testing.T) {
	if got := SelectIDs(change("def compute_total(items):\n    return sum_values(items)\n")); len(got) != 0 {
		t.Errorf("expected nothing for neutral diff, got %v", got)
	}
}

func TestWordBoundaryPreventsSubstringFalsePositive(t *testing.T) {
	got := idSet(SelectIDs(change("def fetch_url_content(url):\n    return requests.get(url).text\n")))
	if got["log-as-trusted-input"] {
		t.Error("log-as-trusted-input must not fire on fetch_url_content (substring false positive)")
	}
	if !got["ssrf"] {
		t.Errorf("expected ssrf for requests.get, got %v", got)
	}
}

func TestEmptyChanges(t *testing.T) {
	if got := SelectIDs(nil); len(got) != 0 {
		t.Errorf("expected nothing for empty changes, got %v", got)
	}
}

func TestCapAndRanking(t *testing.T) {
	got := SelectIDs(change(`
resp = requests.get(url, verify=False)
cursor.execute("SELECT * FROM t WHERE id = " + uid)
subprocess.run(cmd, shell=True)
obj = pickle.loads(data)
el.innerHTML = data
digest = hashlib.md5(data)
`))
	if len(got) > MaxRules {
		t.Fatalf("cap exceeded: %d (%v)", len(got), got)
	}
	set := idSet(got)
	if !set["sql-injection"] || !set["os-command-injection"] {
		t.Errorf("expected high-weight primaries selected, got %v", got)
	}
}

// TestTreeReferencesRealRules: every rule ID in the decision tree exists in the
// corpus. The client no longer embeds rules, so the test reads corpus/ from disk
// (a build-time input). A typo would silently select nothing for that branch.
func TestTreeReferencesRealRules(t *testing.T) {
	exists := corpusIDs(t)
	for _, f := range families {
		for _, id := range append(append([]string{}, f.primary...), f.secondary...) {
			if !exists[id] {
				t.Errorf("decision tree references unknown rule ID %q", id)
			}
		}
	}
}

func corpusIDs(t *testing.T) map[string]bool {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	// This parity check needs the FULL real corpus (the tree references the whole rule
	// set), but the corpus is NOT part of this module — the rules corpus is fetched by
	// the server from its own repo. This module must stay self-contained (it is the
	// open-sourceable half), so the test only LOCATES an existing corpus directory and
	// SKIPS when there isn't one; it never fetches. Resolution order: an explicit
	// LEOPREVENT_CORPUS_DIR, then the server's clone cache, then a repo-root checkout.
	root := filepath.Join(filepath.Dir(file), "..", "..", "..", "..")
	dir := findCorpus(os.Getenv("LEOPREVENT_CORPUS_DIR"),
		filepath.Join(root, "server", "agent-rules"),
		filepath.Join(root, "agent-rules"))
	if dir == "" {
		t.Skip("no rules corpus on disk — set LEOPREVENT_CORPUS_DIR or run the server once to populate its cache")
	}
	patterns, err := os.ReadFile(filepath.Join(dir, "patterns.yaml"))
	if err != nil {
		t.Fatalf("read patterns: %v", err)
	}
	assumptions, err := os.ReadFile(filepath.Join(dir, "assumptions.yaml"))
	if err != nil {
		t.Fatalf("read assumptions: %v", err)
	}
	rules, err := rulespec.ParseRules(patterns, assumptions)
	if err != nil {
		t.Fatalf("parse rules: %v", err)
	}
	out := map[string]bool{}
	for _, r := range rules {
		out[r.ID] = true
	}
	return out
}

// findCorpus returns the first candidate directory that actually holds a corpus
// (patterns.yaml present), or "" when none do. Empty candidates are ignored so an
// unset LEOPREVENT_CORPUS_DIR simply falls through. Each candidate is tried both
// directly and with a "corpus/" suffix, since a clone of the rules corpus holds
// the rules under corpus/ while LEOPREVENT_CORPUS_DIR points straight at them.
func findCorpus(candidates ...string) string {
	for _, c := range candidates {
		if c == "" {
			continue
		}
		for _, d := range []string{c, filepath.Join(c, "corpus")} {
			if _, err := os.Stat(filepath.Join(d, "patterns.yaml")); err == nil {
				return d
			}
		}
	}
	return ""
}
