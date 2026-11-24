package wire

// POST /secrets (cloud tier, LEO-919, Project Mackem Stage 1): what the secrets watch found in one
// hook run, for the Event Viewer. The plugin decides everything; the server only records it.
//
// ⚠️ NO VALUE EVER CROSSES THE WIRE. A detection names the secret (its variable, its file, or the
// provider's key type) and carries its fingerprint, an HMAC-SHA256 of the value keyed with a salt
// that is generated on the developer's machine and never leaves it. There is no field for the
// value, the matched text or the salt, and the server decodes this body strictly, so a body that
// adds one is refused (400) rather than stored. Don't add one: a fingerprint without its salt can't
// be checked against a guess, and that is the whole of the privacy argument (LEO-910).
//
// The one part of a value that may cross is Preview (decided 2026-11-19): its first and last four
// characters, only when what stays hidden between them is at least 128 bits of randomness, which
// ValidateSecretDetection checks against Length. The context fields (where it was seen, what it
// was assigned to, where a sending call sends) are worked out on the machine and carry no value.

// SecretsRequest is one hook run's detections. Meta is who and where; Session is the agent's
// session id, so the Event Viewer can group a session's detections.
type SecretsRequest struct {
	Meta       *SecretsMeta      `json:"meta,omitempty"`
	Session    string            `json:"session,omitempty"`
	Detections []SecretDetection `json:"detections"`
}

// SecretsMeta is the identity half of TurnMeta, field for field (same JSON names), and nothing
// else: no prompt, no token counts, no paths. Its own type rather than TurnMeta, so a field that
// could carry prose or a path is refused rather than silently accepted. Each field is at most
// MaxSecretLabelLength bytes, since it is copied into every detection's event.
type SecretsMeta struct {
	Agent           string `json:"agent,omitempty"`
	AgentModel      string `json:"agent_model,omitempty"`
	Repo            string `json:"repo,omitempty"`
	Developer       string `json:"developer,omitempty"`
	DeveloperSource string `json:"developer_source,omitempty"`
	OS              string `json:"os,omitempty"`
	Arch            string `json:"arch,omitempty"`
	ClientVersion   string `json:"client_version,omitempty"`
	Environment     string `json:"environment,omitempty"`
	EnvironmentRaw  string `json:"environment_raw,omitempty"`
}

// SecretDetection is one secret seen at one check point. Each is recorded as its own event.
type SecretDetection struct {
	// Happened is what the detection means: SecretReachedModel, SecretSentOut or
	// SecretWouldStop.
	Happened string `json:"happened"`
	// CheckPoint is where in the turn it was seen: SecretAtPrompt, SecretBeforeTool,
	// SecretAfterTool or SecretAtTurnEnd.
	CheckPoint string `json:"check_point"`
	// Method is how it was found, one of the four values LEO-920 defines (they also set its
	// severity): SecretKnownExact, SecretKnownPattern, SecretUnknownPattern, SecretHighEntropy.
	Method string `json:"method"`
	// Source is where a known secret was read on the machine: SecretSourceEnv, SecretSourceEnvFile
	// or SecretSourceCredentialFile. Required for the two known-secret methods, empty for the
	// other two (an unknown key and an entropy match have no source on the machine).
	Source string `json:"source,omitempty"`
	// Name is the environment variable or the key inside a file ("STRIPE_SECRET_KEY"): letters,
	// digits, "_", "." and "-" only, never "NAME=value". Optional; a known secret has at least a
	// Name or a File.
	Name string `json:"name,omitempty"`
	// File is the file a known secret was read from: for a .env file its path relative to the
	// workspace, forward slashes, never absolute and never ".." (an absolute path would carry the
	// developer's home folder, and a ":" is refused); for a credential file its kind, one of
	// SecretCredentialKinds. Optional.
	File string `json:"file,omitempty"`
	// KeyType is the provider pattern's name ("Stripe live secret key") for a pattern match.
	// Required for SecretUnknownPattern, optional for SecretKnownPattern, empty otherwise.
	KeyType string `json:"key_type,omitempty"`
	// Fingerprint is the lowercase hex HMAC-SHA256 of the value with the machine's salt:
	// SecretFingerprintLength characters. It groups repeat detections of the same secret on one
	// machine; it can't be compared across machines.
	Fingerprint string `json:"fingerprint"`

	// The detection's context, all optional (LEO-910, 2026-11-19).
	//
	// Preview is the value's first and last SecretPreviewChars characters around "…", after a
	// known provider prefix shown whole ("sk_live_a9F2…7xQk"). Only for a value shaped like a
	// random token whose hidden middle keeps at least 128 bits, so Length must leave at least
	// SecretPreviewMinHidden characters hidden.
	Preview string `json:"preview,omitempty"`
	// Length is the value's length in characters; 0 when unknown.
	Length int `json:"length,omitempty"`
	// AssignedTo is the name the value was assigned to in the text it was seen in ("apiKey",
	// "Authorization"): as Name, letters, digits, "_", "." and "-" only.
	AssignedTo string `json:"assigned_to,omitempty"`
	// Tool is the agent's tool for a before_tool or after_tool detection ("Read", "Bash",
	// "mcp__github__create_issue").
	Tool string `json:"tool,omitempty"`
	// Program is a shell command's program: the one it starts with, or for a sent_out detection
	// the network client it runs ("curl", "git push", "gh api").
	Program string `json:"program,omitempty"`
	// Purpose is the agent's own one-line description of the tool call, as the agent gave it
	// ("Check token length, charset, and checksum locally"): at most SecretMaxPurpose characters,
	// prose only (ValidSecretPurpose), never a run that could be a value.
	Purpose string `json:"purpose,omitempty"`
	// Subagent is the type of the subagent that made the tool call ("Explore"), as the agent names
	// it: letters, digits, "_", ".", ":" and "-", at most 64. Empty for the main session's calls.
	Subagent string `json:"subagent,omitempty"`
	// Hosts are where a sent_out call sends data, by host name only, at most SecretMaxHosts. Empty
	// when none could be found: "destination not identified".
	Hosts []string `json:"hosts,omitempty"`
	// LocalDestination: a sent_out push went to a folder on the machine's file system (a path or a
	// file:// remote), not a host. The path is never sent. Such a folder may still be a mounted
	// network drive or a synced folder, which the watch can't tell.
	LocalDestination bool `json:"local_destination,omitempty"`
	// Expiry is set only for a token that carries its own expiry (a JWT's exp, a signed URL's
	// expiry parameters) and had already expired, or would within the hour, when it was seen:
	// SecretExpired or SecretExpiresWithinHour (LEO-1025). Worked out on the machine; the time and
	// the token's other claims are never sent. Empty for a token with no expiry, a later one, or one
	// that couldn't be read, which is graded as any other key.
	Expiry string `json:"expiry,omitempty"`
	// ExpiresOn is the expiry date, UTC, as "2027-03-01", of a token that carries its own expiry,
	// whether or not it is short-lived, so the dashboards can say how urgent it is. Only the day:
	// never the time, and never the token's other claims. Empty when the expiry can't be read, as
	// for most keys, whose expiry (if any) is held by the provider, not written in the key.
	ExpiresOn string `json:"expires_on,omitempty"`
	// ByDeveloper: the value was in a command the developer ran themselves in the agent (Claude
	// Code's "!"), or its output, rather than in anything the agent did. Only at SecretAtTurnEnd,
	// since no live hook sees such a command; Program is then the command's program.
	ByDeveloper bool `json:"by_developer,omitempty"`
	// Path is the file the value was seen in, as File: relative to the workspace, or its base
	// name when outside it. Line is the 1-based line in it, 0 when unknown.
	Path string `json:"path,omitempty"`
	Line int    `json:"line,omitempty"`
}

// SecretPreviewChars is how many characters a Preview shows at each end, and
// SecretPreviewMinHidden the fewest it must leave hidden: 128 bits at 6 bits a character, the most
// a base64 character carries.
const (
	SecretPreviewChars     = 4
	SecretPreviewMinHidden = 22
	SecretMaxHosts         = 5
	SecretMaxPurpose       = 120
)

// SecretsResponse answers a SecretsRequest: how many detections were recorded.
type SecretsResponse struct {
	Recorded int `json:"recorded"`
}

// SecretFingerprintLength is a fingerprint's length: hex SHA-256.
const SecretFingerprintLength = 64

// MaxSecretDetections caps one request's detections; the plugin sends a longer queue in batches.
// Each is its own event, so the cap bounds what one request writes.
const MaxSecretDetections = 20

// SecretCredentialKinds are the credential files a detection's File may name when its Source is
// SecretSourceCredentialFile: LEO-912's secretfiles kinds, other than env.
var SecretCredentialKinds = []string{"gh-hosts", "git-credentials", "docker-config"}

// MaxSecretLabelLength caps Session, Name, File, KeyType and each SecretsMeta field.
const MaxSecretLabelLength = 256

// SecretDetection.Happened values.
const (
	// SecretReachedModel: the secret was in text the model read (the prompt, a tool's output).
	SecretReachedModel = "reached_model"
	// SecretSentOut: the secret was in a tool call that sends data off the machine.
	SecretSentOut = "sent_out"
	// SecretWouldStop: Block mode would have stopped it (Stage 2); Monitor records it only.
	SecretWouldStop = "would_stop"
)

// SecretDetection.CheckPoint values: the four hook points the watch checks.
const (
	SecretAtPrompt   = "prompt"
	SecretBeforeTool = "before_tool"
	SecretAfterTool  = "after_tool"
	SecretAtTurnEnd  = "turn_end"
)

// SecretDetection.Method values (LEO-920), most certain first.
const (
	// SecretKnownExact: the value of a secret registered on this machine appeared, directly or
	// encoded.
	SecretKnownExact = "known_exact"
	// SecretKnownPattern: a provider pattern matched, and its fingerprint equals a registered
	// secret's.
	SecretKnownPattern = "known_pattern"
	// SecretUnknownPattern: a provider pattern matched a key not registered on this machine.
	SecretUnknownPattern = "unknown_pattern"
	// SecretHighEntropy: a generic entropy rule matched; no name or type. Report only.
	SecretHighEntropy = "high_entropy"
)

// SecretDetection.Expiry values (LEO-1025).
const (
	SecretExpired           = "expired"
	SecretExpiresWithinHour = "within_hour"
)

// SecretDetection.Source values.
const (
	SecretSourceEnv            = "env"
	SecretSourceEnvFile        = "env_file"
	SecretSourceCredentialFile = "credential_file"
)
