//go:build unix

package scratch

import (
	"io/fs"
	"os"
	"syscall"
)

// refusedRoot is where scratch paths point when no root can be trusted. /dev/null is not a
// directory, so every create, write or MkdirAll under it fails (ENOTDIR), and every read and
// remove finds nothing.
var refusedRoot = os.DevNull

// ownedAndPrivate holds the dir to our euid and to no group or other permission bits. A dir we
// own with looser bits is refused too: it was never created that way by us (MkdirAll's 0o700
// can only be narrowed by umask), so someone changed it, and it may already hold their files.
func ownedAndPrivate(fi fs.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	return int(st.Uid) == os.Geteuid() && fi.Mode().Perm()&0o077 == 0
}
