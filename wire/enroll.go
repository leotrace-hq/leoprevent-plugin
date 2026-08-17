package wire

// EnrollRequest asks the server to mint this machine's own per-user license key.
//
// ⚠️ NOTHING IN HERE IS AN AUTHORISATION. The credential is the enrolment token in the
// Authorization header, which the server resolves to an ACCOUNT; `Developer` is an assertion the
// server checks against that account's allowlist before it mints anything. A client cannot enrol
// an address its admin has not already authorised, which is what keeps a token every developer in
// the organisation can read from becoming a way to mint credentials in a colleague's name.
//
// The remaining fields are support context, recorded beside the mint and deciding nothing. They
// are the same dimensions a review turn already carries, so enrolment reveals nothing new about
// the machine.
type EnrollRequest struct {
	// Developer is the git identity this machine will attribute turns to, `name <email>` or bare
	// email. The server takes the address from it and ignores the rest.
	Developer string `json:"email"`
	OS        string `json:"os,omitempty"`
	Arch      string `json:"arch,omitempty"`
	// ClientVersion is the plugin build asking to enrol, so a rollout can be traced to a release.
	ClientVersion string `json:"client_version,omitempty"`
	// Device is a non-unique, human-readable hint (a hostname) for a support conversation. It is
	// NOT an identity and nothing keys off it: a person holds ONE license across every machine.
	Device string `json:"device,omitempty"`
}

// EnrollResponse carries the minted key.
//
// ⚠️ THIS IS THE ONLY TIME THE KEY EXISTS OUTSIDE THE CLIENT'S OWN license.json. The server stores
// nothing but its digest, so a client that fails to persist this must enrol again and will receive
// a ROTATED key — which invalidates whatever the previous attempt wrote. Persist it before doing
// anything else with it.
type EnrollResponse struct {
	LicenseKey string `json:"license_key"`
	// LicenseID is the attribution key stamped on every event this machine produces. Not a secret,
	// and worth logging: it is what correlates a developer's turns in a support conversation.
	LicenseID string `json:"license_id"`
	AccountID string `json:"account_id"`
	// Rotated reports that this replaced an existing key rather than issuing a first one, so the
	// client can say so: one license belongs to a PERSON, not a machine, and enrolling a second
	// machine therefore stops the first one authenticating.
	Rotated bool `json:"rotated"`
}
