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
	// Device is a non-unique, human-readable hint (a hostname) for a support conversation.
	Device string `json:"device,omitempty"`
	// DeviceID says WHICH of this person's machines is enrolling, so re-enrolling replaces this
	// machine's own key rather than adding another (LEO-168). Random, persisted beside the key in
	// the per-user license.json, and therefore stable on a laptop and genuinely new in each cloud
	// sandbox — which is correct, because a sandbox IS a new machine.
	//
	// ⚠️ STILL NOT AN AUTHORISATION. `Developer` decides whose row is touched and is checked
	// against the account's allowlist; the worst a forged DeviceID can do is displace another key
	// on the caller's own row. Empty is accepted (an older client), and the server then falls back
	// to matching on (device, os, arch).
	DeviceID string `json:"device_id,omitempty"`
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
	// Rotated reports that this replaced THIS MACHINE'S previous key.
	//
	// ⚠️ IT NO LONGER MEANS "replaced the person's key", and the sentence that used to be here —
	// enrolling a second machine stops the first one authenticating — was the bug, not the design
	// (LEO-168). A person now holds one key per machine, so a NEW device reports false and leaves
	// every other machine working.
	Rotated bool `json:"rotated"`
}
