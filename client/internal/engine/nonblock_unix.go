//go:build unix

package engine

import "syscall"

// openNonblock makes opening a FIFO return at once instead of waiting for a writer
// (fallbackContent). A regular file reads the same either way.
const openNonblock = syscall.O_NONBLOCK
