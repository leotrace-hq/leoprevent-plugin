package wire

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// The rules a SecretsRequest must keep, shared by both ends (LEO-915): the server refuses a body
// that breaks one with a 400 and records nothing, and the plugin drops a detection that breaks
// one before sending, so one malformed detection never costs the others theirs. Errors name the
// field, never echo its content.

var (
	secretFingerprint = regexp.MustCompile(`^[0-9a-f]{64}$`)
	secretName        = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
	secretPreviewHead = regexp.MustCompile(`^[A-Za-z0-9_+/=.-]{4,24}$`)
	secretPreviewTail = regexp.MustCompile(`^[A-Za-z0-9_+/=-]{4}$`)
	secretSubagent    = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,64}$`)
	secretTool        = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)
	secretProgram     = regexp.MustCompile(`^[A-Za-z0-9_.+-]{1,64}( push| api)?$`)
	secretPurposeRun  = regexp.MustCompile(`[^\s,;()"'` + "`" + `]{20,}`)
	secretHost        = regexp.MustCompile(`^(?:[a-z0-9-]+\.)+[a-z][a-z0-9-]*$|^\d{1,3}(?:\.\d{1,3}){3}$|^localhost$|^\[[0-9a-f:.]+\]$`)
)

// maxSecretLength and maxSecretLine bound Length and Line.
const (
	maxSecretLength = 1 << 16
	maxSecretLine   = 1 << 24
)

// ValidateSecretsRequest refuses a body that is malformed or carries more than a detection may.
func ValidateSecretsRequest(req SecretsRequest) error {
	if m := req.Meta; m != nil {
		for _, f := range []struct{ name, v string }{
			{"meta.agent", m.Agent}, {"meta.agent_model", m.AgentModel}, {"meta.repo", m.Repo},
			{"meta.developer", m.Developer}, {"meta.developer_source", m.DeveloperSource},
			{"meta.os", m.OS}, {"meta.arch", m.Arch}, {"meta.client_version", m.ClientVersion},
			{"meta.environment", m.Environment}, {"meta.environment_raw", m.EnvironmentRaw},
		} {
			if err := ValidSecretLabel(f.name, f.v); err != nil {
				return err
			}
		}
	}
	if err := ValidSecretLabel("session", req.Session); err != nil {
		return err
	}
	switch n := len(req.Detections); {
	case n == 0:
		return errors.New("detections is required")
	case n > MaxSecretDetections:
		return fmt.Errorf("%d detections, at most %d", n, MaxSecretDetections)
	}
	for i, d := range req.Detections {
		if err := ValidateSecretDetection(d); err != nil {
			return fmt.Errorf("detections[%d]: %w", i, err)
		}
	}
	return nil
}

// ValidateSecretDetection refuses one detection that breaks the rules on SecretDetection.
func ValidateSecretDetection(d SecretDetection) error {
	switch d.Happened {
	case SecretReachedModel, SecretSentOut, SecretWouldStop:
	default:
		return errors.New("happened isn't reached_model, sent_out or would_stop")
	}
	switch d.CheckPoint {
	case SecretAtPrompt, SecretBeforeTool, SecretAfterTool, SecretAtTurnEnd:
	default:
		return errors.New("check_point isn't prompt, before_tool, after_tool or turn_end")
	}
	if !secretFingerprint.MatchString(d.Fingerprint) {
		return fmt.Errorf("fingerprint must be %d lowercase hex characters", SecretFingerprintLength)
	}
	for _, f := range []struct{ name, v string }{{"name", d.Name}, {"file", d.File}, {"key_type", d.KeyType}} {
		if err := ValidSecretLabel(f.name, f.v); err != nil {
			return err
		}
	}
	if d.Name != "" && !secretName.MatchString(d.Name) {
		return errors.New(`name must be letters, digits, "_", "." and "-" only, never "NAME=value"`)
	}
	if err := validSecretFile(d.File); err != nil {
		return err
	}
	if err := validSecretContext(d); err != nil {
		return err
	}
	known := false
	switch d.Method {
	case SecretKnownExact, SecretKnownPattern:
		known = true
	case SecretUnknownPattern:
		if d.KeyType == "" {
			return errors.New("an unknown_pattern detection needs key_type")
		}
	case SecretHighEntropy:
		if d.KeyType != "" {
			return errors.New("a high_entropy detection has no key_type")
		}
	default:
		return errors.New("method isn't known_exact, known_pattern, unknown_pattern or high_entropy")
	}
	if !known {
		if d.Source != "" || d.Name != "" || d.File != "" {
			return fmt.Errorf("a %s detection has no source, name or file: it isn't a secret known on the machine", d.Method)
		}
		return nil
	}
	if d.Method == SecretKnownExact && d.KeyType != "" {
		return errors.New("a known_exact detection has no key_type")
	}
	switch d.Source {
	case SecretSourceEnv, SecretSourceEnvFile, SecretSourceCredentialFile:
	default:
		return errors.New("a known secret's source isn't env, env_file or credential_file")
	}
	if d.Name == "" && d.File == "" {
		return errors.New("a known secret needs a name or a file")
	}
	if d.Source == SecretSourceCredentialFile && d.File != "" && !slices.Contains(SecretCredentialKinds, d.File) {
		return fmt.Errorf("a credential file is one of %s", strings.Join(SecretCredentialKinds, ", "))
	}
	return nil
}

// ValidSecretLabel bounds a free-text identifier and refuses control and format characters (a bidi
// override or a zero-width character could make the Event Viewer show something else).
func ValidSecretLabel(field, v string) error {
	if len(v) > MaxSecretLabelLength {
		return fmt.Errorf("%s is %d bytes, at most %d", field, len(v), MaxSecretLabelLength)
	}
	if !utf8.ValidString(v) {
		return fmt.Errorf("%s isn't valid UTF-8", field)
	}
	for _, r := range v {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return fmt.Errorf("%s has a control or format character", field)
		}
	}
	return nil
}

// validSecretFile refuses a file that isn't relative to the workspace: an absolute path would
// carry the developer's home folder, and the event log never records one.
func validSecretFile(p string) error {
	switch {
	case p == "":
		return nil
	case strings.Contains(p, `\`):
		return errors.New("file must use forward slashes")
	case strings.HasPrefix(p, "/") || strings.HasPrefix(p, "~") || strings.Contains(p, ":"):
		return errors.New(`file must be relative to the workspace, not absolute, and has no ":"`)
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return errors.New(`file must not step outside the workspace with ".."`)
		}
	}
	return nil
}

// validSecretContext refuses context that could carry more than it says: a preview showing more
// than its ends or leaving too little hidden, a host or name holding anything but a name.
func validSecretContext(d SecretDetection) error {
	if d.Length < 0 || d.Length > maxSecretLength {
		return fmt.Errorf("length must be 0 to %d", maxSecretLength)
	}
	if d.Preview != "" {
		head, tail, ok := strings.Cut(d.Preview, "…")
		if !ok || !secretPreviewHead.MatchString(head) || !secretPreviewTail.MatchString(tail) {
			return errors.New(`preview must be a prefix and 4 characters, "…", and the last 4 characters`)
		}
		if d.Length < len(head)+len(tail)+SecretPreviewMinHidden {
			return fmt.Errorf("a preview must leave at least %d characters of the value hidden", SecretPreviewMinHidden)
		}
	}
	for _, f := range []struct{ name, v string }{{"assigned_to", d.AssignedTo}, {"path", d.Path}} {
		if err := ValidSecretLabel(f.name, f.v); err != nil {
			return err
		}
	}
	if d.AssignedTo != "" && !secretName.MatchString(d.AssignedTo) {
		return errors.New(`assigned_to must be letters, digits, "_", "." and "-" only`)
	}
	if d.Tool != "" && !secretTool.MatchString(d.Tool) {
		return errors.New(`tool must be letters, digits, "_", "." and "-" only`)
	}
	if d.Subagent != "" && !secretSubagent.MatchString(d.Subagent) {
		return errors.New(`subagent must be letters, digits, "_", ".", ":" and "-" only`)
	}
	if d.Program != "" && !secretProgram.MatchString(d.Program) {
		return errors.New("program must be a program's name")
	}
	if err := ValidSecretPurpose(d.Purpose); err != nil {
		return err
	}
	if len(d.Hosts) > 0 && d.Happened != SecretSentOut {
		return errors.New("hosts are only for a sent_out detection")
	}
	if d.LocalDestination && (d.Happened != SecretSentOut || len(d.Hosts) > 0) {
		return errors.New("local_destination is only for a sent_out detection with no hosts")
	}
	switch d.Expiry {
	case "", SecretExpired, SecretExpiresWithinHour:
	default:
		return errors.New("expiry isn't expired or within_hour")
	}
	if d.ByDeveloper && d.CheckPoint != SecretAtTurnEnd {
		return errors.New("by_developer is only for a turn_end detection")
	}
	if d.ExpiresOn != "" {
		if t, err := time.Parse(time.DateOnly, d.ExpiresOn); err != nil || t.Year() < 1970 {
			return errors.New("expires_on must be a date, YYYY-MM-DD, from 1970")
		}
	}
	if len(d.Hosts) > SecretMaxHosts {
		return fmt.Errorf("at most %d hosts", SecretMaxHosts)
	}
	for _, h := range d.Hosts {
		if len(h) > 253 || !secretHost.MatchString(h) {
			return errors.New("each host must be a lowercase host name or IP address")
		}
	}
	if err := validSecretFile(d.Path); err != nil {
		return fmt.Errorf("path: %w", err)
	}
	switch {
	case d.Line < 0 || d.Line > maxSecretLine:
		return fmt.Errorf("line must be 0 to %d", maxSecretLine)
	case d.Line > 0 && d.Path == "":
		return errors.New("a line needs a path")
	}
	return nil
}

// ValidSecretPurpose refuses a purpose that is too long or isn't plain prose: a value could hide in
// any run of 20 or more characters without a space, so one such run refuses the whole purpose.
func ValidSecretPurpose(p string) error {
	if p == "" {
		return nil
	}
	if err := ValidSecretLabel("purpose", p); err != nil {
		return err
	}
	if utf8.RuneCountInString(p) > SecretMaxPurpose {
		return fmt.Errorf("purpose is at most %d characters", SecretMaxPurpose)
	}
	if secretPurposeRun.MatchString(p) {
		return errors.New("purpose must be prose: no run of 20 or more characters without a space")
	}
	return nil
}
