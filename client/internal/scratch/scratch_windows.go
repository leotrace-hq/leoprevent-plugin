//go:build windows

package scratch

import "io/fs"

// refusedRoot is where scratch paths point when no root can be trusted: the NUL device in
// device-namespace form, which is absolute (a bare "NUL" would join into a RELATIVE path) and
// cannot hold a directory, so every create under it fails.
const refusedRoot = `\\.\NUL`

// ownedAndPrivate is always true on Windows: the root sits under %LocalAppData% (or %TEMP%,
// which Windows also keeps per user), whose inherited ACL already excludes other users, and Go
// reports synthetic permission bits there that say nothing about the ACL.
func ownedAndPrivate(fs.FileInfo) bool { return true }
