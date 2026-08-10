// Package selector picks which rules are relevant to the changed code.
//
// Selection is an explicit sink-family DECISION TREE:
// each family maps public code signals (API names, syntax) to the rule IDs that
// could apply when that signal appears. A family that matches scores its primary
// rules at full weight and its secondary (same-neighbourhood) rules lower. Rules
// are ranked by summed score and capped at MaxRules.
//
// This is deterministic and content-free — it reads no rule text, only the
// changed code and a fixed signal→ID table — so it leaks nothing and doubles as
// the on-device selection engine for the local tier. It is
// recall-generous: a family match selects the whole family and the reviewer
// prunes false positives via does_not_apply_when.
//
// Honest ceiling: a tree cannot catch indirect sinks (a sink inside a
// helper the diff only calls but does not show), novel vocabulary (a library
// with no branch here), or semantic-only rules (toctou-race-condition,
// excessive-pii-exposure) that have no distinctive code token — those ride a
// weak structural signal at best. And when more than MaxRules families fire some
// candidates are cut. A miss here is a silent false negative; when one is
// observed, add the signal/branch immediately. Server-side selection (the cloud
// tier) uses Haiku instead, which clears most of this ceiling.
package selector

import (
	"sort"
	"strings"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
)

// MaxRules caps how many candidate rules are passed to the reviewer. It is a
// generous safety bound, not a precision knob: selection is recall-oriented and
// the judge prunes, so we'd rather over-send than silently drop a real candidate
// (the same bias as the inert gate). applies_to language filtering (applied once
// rule content is in hand) usually keeps the set well under this.
const MaxRules = 10

// family maps a set of code signals to the rules that may apply when any signal
// is present in the changed code. Primary rules score at weight; secondary rules
// (plausible in the same neighbourhood but less central) score at weight-2
// (floored at 1). Scores sum across all matching families.
type family struct {
	signals   []string
	primary   []string
	secondary []string
	weight    int
}

// families is the sink-family decision tree. Every rule ID here must exist in
// the rule corpus (enforced by a parity test); canary-7f2a9x is intentionally
// unmapped (internal test marker, never selected).
var families = []family{
	{
		signals:   []string{"requests.", "urlopen", "urllib", "fetch(", "axios", "httpclient", "http.get", "httpx", "okhttp", "resttemplate", "webclient"},
		primary:   []string{"ssrf"},
		secondary: []string{"open-redirect", "tls-cert-validation-disabled", "cleartext-sensitive-transport", "no-input-validation"},
		weight:    4,
	},
	{
		signals:   []string{"request.args", "request.form", "request.get_json", "request.values", "req.query", "req.body", "req.params", "$_get", "$_post", "$_request", "params[", "getparameter", "@app.route", "@router", "@getmapping", "@postmapping"},
		primary:   []string{"no-input-validation", "xss-backend"},
		secondary: []string{"mass-assignment", "path-traversal"},
		weight:    2,
	},
	{
		signals:   []string{"select ", "insert into", "update ", "delete from", "execute(", "executemany(", "cursor.", "createstatement", "rawquery", "db.query", ".raw(", "sequelize.query(", "knex.raw("},
		primary:   []string{"sql-injection"},
		secondary: []string{"db-trust"},
		weight:    4,
	},
	{
		signals: []string{"$where", "find(", "findone(", "aggregate(", "mongo"},
		primary: []string{"nosql-injection"},
		weight:  4,
	},
	{
		signals: []string{"subprocess", "os.system", "popen", "child_process", "execsync", "spawn(", "shell=true", "shell: true", "processbuilder", "runtime.getruntime", "exec.command", "shell_exec", "passthru", "proc_open", "system(", "%x("},
		primary: []string{"os-command-injection"},
		weight:  4,
	},
	{
		signals:   []string{"<script", "<div", "<html", "innerhtml", "outerhtml", "insertadjacenthtml", "document.write", "dangerouslysetinnerhtml", "v-html", "make_response", "htmlresponse", ".html("},
		primary:   []string{"xss-backend", "xss-frontend"},
		secondary: []string{"missing-subresource-integrity"},
		weight:    3,
	},
	{
		signals:   []string{"redirect(", "sendredirect", "res.redirect", "header(\"location", "location:"},
		primary:   []string{"open-redirect"},
		secondary: []string{"ssrf"},
		weight:    3,
	},
	{
		signals: []string{"pickle.", "yaml.load", "unserialize(", "marshal.load", "readobject", "binaryformatter", "objectinputstream", "jsonpickle", "joblib.load", "torch.load", "read_pickle", "cloudpickle", "dill.load", "allow_pickle", "shelve.open"},
		primary: []string{"unsafe-deserialization"},
		weight:  4,
	},
	{
		signals:   []string{"eval(", "exec(", "new function(", "scriptengine", "vm.run"},
		primary:   []string{"eval-injection"},
		secondary: []string{"ssti", "unsafe-reflection"},
		weight:    4,
	},
	{
		signals:   []string{"render_template_string", "from_string", "createtemplate", "template.new"},
		primary:   []string{"ssti"},
		secondary: []string{"xss-backend"},
		weight:    4,
	},
	{
		signals: []string{"class.forname", "getattr(", "importlib", "__import__", "activator.createinstance", "constantize"},
		primary: []string{"unsafe-reflection"},
		weight:  4,
	},
	{
		signals:   []string{"readfile", "writefile", "path.join", "os.path.join", "send_file", "sendfile", "createreadstream", "../"},
		primary:   []string{"path-traversal"},
		secondary: []string{"toctou-race-condition"},
		weight:    2,
	},
	{
		signals:   []string{"md5", "sha1", "3des", "rc4", "ecb", "createcipher", "cipher.", "hashlib.", "messagedigest"},
		primary:   []string{"weak-crypto-algorithm"},
		secondary: []string{"predictable-iv", "insecure-password-storage"},
		weight:    3,
	},
	{
		signals: []string{"math.random", "random.rand", "rand(", "mt_rand", "randint", "randrange", "random.choice"},
		primary: []string{"weak-randomness"},
		weight:  3,
	},
	{
		signals: []string{"bcrypt", "scrypt", "argon2", "pbkdf2", "password_hash", "passlib", "werkzeug.security"},
		primary: []string{"insecure-password-storage"},
		weight:  3,
	},
	{
		signals:   []string{"password =", "password=", "passwd", "api_key", "apikey", "secret", "private_key", "credential"},
		primary:   []string{"hardcoded-secrets"},
		secondary: []string{"sensitive-data-in-logs"},
		weight:    2,
	},
	{
		signals: []string{"verify=false", "verify: false", "rejectunauthorized", "node_tls_reject_unauthorized", "insecureskipverify", "ssl_verify", "_create_unverified_context", "check_hostname", "checkservertrusted", "trustallcerts", "sslmode=disable", "usessl=false", "http://"},
		primary: []string{"tls-cert-validation-disabled", "cleartext-sensitive-transport"},
		weight:  4,
	},
	{
		signals:   []string{"jwt.", "jsonwebtoken", "jose.", "jwts."},
		primary:   []string{"jwt-verification"},
		secondary: []string{"hardcoded-secrets"},
		weight:    4,
	},
	{
		signals:   []string{"login", "authenticate", "authoriz", "session", "permission", "is_admin", "current_user", "query.get", "find_by_id", "findbypk", "objects.get", "getreferenceById"},
		primary:   []string{"idor-object-level-authz", "missing-function-level-authz"},
		secondary: []string{"csrf-samesite-none", "insecure-password-storage", "excessive-pii-exposure"},
		weight:    1,
	},
	{
		signals:   []string{"set_cookie", "setcookie", "samesite", "document.cookie"},
		primary:   []string{"csrf-samesite-none"},
		secondary: []string{"xss-frontend"},
		weight:    3,
	},
	{
		signals: []string{"access-control-allow", "cors(", "crossorigin"},
		primary: []string{"insecure-cors"},
		weight:  4,
	},
	{
		signals: []string{"documentbuilderfactory", "saxparser", "lxml", "etree.", "simplexml_load", "xmlreader"},
		primary: []string{"xxe"},
		weight:  4,
	},
	{
		signals: []string{"ldap", "dircontext", "searchcontrols"},
		primary: []string{"ldap-injection"},
		weight:  4,
	},
	{
		signals:   []string{"logger.", "logging.", "log.info", "log.error", "log.debug", "console.log"},
		primary:   []string{"sensitive-data-in-logs"},
		secondary: []string{"log-as-trusted-input", "verbose-error-messages"},
		weight:    1,
	},
	{
		signals: []string{"traceback", "printstacktrace", "stack_trace", "str(e)", "e.message", "exc_info"},
		primary: []string{"verbose-error-messages"},
		weight:  2,
	},
	{
		signals:   []string{"debug=true", "debug: true", "debug = true"},
		primary:   []string{"debug-mode-enabled"},
		secondary: []string{"verbose-error-messages"},
		weight:    4,
	},
	{
		signals:   []string{"object.assign", "deepmerge", "__proto__", "lodash.merge"},
		primary:   []string{"prototype-pollution"},
		secondary: []string{"mass-assignment"},
		weight:    3,
	},
	{
		signals: []string{".update(params", ".create(params", "**request.", "populate("},
		primary: []string{"mass-assignment"},
		weight:  3,
	},
	{
		signals: []string{"management.endpoints", "actuator"},
		primary: []string{"spring-boot-actuator-exposure"},
		weight:  4,
	},
	{
		signals: []string{"github.event", "${{ github", "pull_request_target", "actions/checkout"},
		primary: []string{"ci-workflow-injection"},
		weight:  4,
	},
	{
		signals:   []string{"request.files", "multipartfile", "multer", "formidable", "busboy", "secure_filename", "uploadedfile", "multipart/form-data"},
		primary:   []string{"insecure-file-upload"},
		secondary: []string{"path-traversal"},
		weight:    2,
	},
	{
		signals:   []string{"localstorage", "sessionstorage"},
		primary:   []string{"client-storage-of-secrets"},
		secondary: []string{"xss-frontend"},
		weight:    3,
	},
	{
		signals: []string{"postmessage", "addeventlistener(\"message", "addeventlistener('message", ".onmessage"},
		primary: []string{"postmessage-origin-validation"},
		weight:  3,
	},
	{
		// Account-creation / credential-change vocabulary → unconditional credential
		// writes keyed by caller-supplied ids (register/signup account takeover).
		signals:   []string{"register", "signup", "sign_up", "create_account", "create_user", "createuser", "set_password", "reset_password", "change_password", "upsert", "insert or replace", "replace into", "on conflict"},
		primary:   []string{"unverified-credential-write"},
		secondary: []string{"insecure-password-storage", "idor-object-level-authz"},
		weight:    2,
	},
	{
		// Request-host reads (absolute-URL building from Host / X-Forwarded-Host).
		signals:   []string{"request.host", "host_url", "get_host", "build_absolute_uri", "x-forwarded-host", "req.hostname", "headers.host", "getservername", "fromcurrentrequest", "_external=true", "r.host"},
		primary:   []string{"host-header-trust"},
		secondary: []string{"open-redirect"},
		weight:    4,
	},
	{
		// Reverse-proxy / web-server config vocabulary (nginx/Apache/HAProxy) —
		// path-based routing or ACL decisions the upstream may resolve differently.
		signals: []string{"proxy_pass", "proxypass", "location /", "location =", "alias /", "deny all", "$request_uri", "$uri", "rewriterule", "use_backend"},
		primary: []string{"proxy-path-handling"},
		weight:  4,
	},
	{
		// Debug / diagnostic / internal endpoints exposing env, config, host, or
		// resource inventories without an authorization gate.
		signals:   []string{"/debug", "/internal", "/diagnostic", "/actuator", "os.environ", "process.env", "app.config", "url_map", "iter_rules", "getenv", "/__", "management.endpoints"},
		primary:   []string{"debug-endpoint-exposure"},
		secondary: []string{"debug-mode-enabled", "spring-boot-actuator-exposure"},
		weight:    3,
	},
	{
		// Regex evaluated over runtime input → catastrophic backtracking (ReDoS).
		signals: []string{"re.compile", "re.match", "re.search", "re.fullmatch", "re.findall", "regexp.mustcompile", "regexp.compile", "new regexp", "pattern.compile", ".matches(", "str.match"},
		primary: []string{"redos-catastrophic-backtracking"},
		weight:  3,
	},
}

// SelectIDs runs the sink-family decision tree over the changed code and returns
// the top MaxRules candidate rule IDs, ranked by score (desc), ties broken by ID.
func SelectIDs(changes []transcript.Change) []string {
	text := lowerJoin(changes)
	if text == "" {
		return nil
	}

	score := map[string]int{}
	for _, f := range families {
		if !familyMatches(text, f.signals) {
			continue
		}
		for _, id := range f.primary {
			score[id] += f.weight
		}
		secWeight := f.weight - 2
		if secWeight < 1 {
			secWeight = 1
		}
		for _, id := range f.secondary {
			score[id] += secWeight
		}
	}
	if len(score) == 0 {
		return nil
	}

	ids := make([]string, 0, len(score))
	for id := range score {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(a, b int) bool {
		if score[ids[a]] != score[ids[b]] {
			return score[ids[a]] > score[ids[b]]
		}
		return ids[a] < ids[b]
	})
	if len(ids) > MaxRules {
		ids = ids[:MaxRules]
	}
	return ids
}

// familyMatches reports whether any of the family's signals appears in the
// changed code. Signals that are bare identifiers (no punctuation) match only on
// a word boundary, so "secret" does not fire on "secretariat" and "login" does
// not fire on "logging"; signals carrying punctuation/space match as substrings.
func familyMatches(text string, signals []string) bool {
	for _, sig := range signals {
		if isBareWord(sig) {
			if containsWord(text, sig) {
				return true
			}
		} else if strings.Contains(text, sig) {
			return true
		}
	}
	return false
}

// lowerJoin concatenates the lower-cased added text of every change, or returns
// "" if there is no non-whitespace content.
func lowerJoin(changes []transcript.Change) string {
	var b strings.Builder
	for _, c := range changes {
		b.WriteString(strings.ToLower(c.AddedText))
		b.WriteByte('\n')
	}
	text := b.String()
	if strings.TrimSpace(text) == "" {
		return ""
	}
	return text
}

// isBareWord reports whether sig consists solely of identifier characters
// (letters, digits, underscore) — i.e. has no punctuation or space to anchor a
// substring match, so it needs whole-word matching to stay selective.
func isBareWord(sig string) bool {
	if sig == "" {
		return false
	}
	for i := 0; i < len(sig); i++ {
		if !isIdentChar(sig[i]) {
			return false
		}
	}
	return true
}

// containsWord reports whether text contains term as a whole word (not as a
// substring inside a longer identifier).
func containsWord(text, term string) bool {
	for i := 0; i+len(term) <= len(text); i++ {
		if text[i:i+len(term)] != term {
			continue
		}
		before := i == 0 || !isIdentChar(text[i-1])
		after := i+len(term) == len(text) || !isIdentChar(text[i+len(term)])
		if before && after {
			return true
		}
	}
	return false
}

func isIdentChar(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') ||
		(b >= '0' && b <= '9') || b == '_'
}
