package config

import (
	"os"
	"path/filepath"
)

// UserWelcomeFile is the marker recording that this machine has been welcomed.
const UserWelcomeFile = "welcomed"

// ClaimWelcome reports whether the welcome message should be printed now, and records that it
// has been. It is true exactly once per machine: the marker is created exclusively, so a repeat
// `set-license` or `login` finds it and stays quiet.
//
// The marker is deliberately independent of the license key, so replacing a key does not
// re-welcome. Any error answers false: a missing welcome costs one message, a repeated one
// costs the developer's trust in the output.
func ClaimWelcome() bool {
	dir, err := userConfigDir()
	if err != nil {
		return false
	}
	path := filepath.Join(dir, "leoprevent", UserWelcomeFile)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return false
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return false
	}
	return f.Close() == nil
}
