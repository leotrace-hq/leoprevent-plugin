//go:build !windows

package imports

import "syscall"

// prismaOpenFlags opens a folder of the walk without blocking on a FIFO swapped in
// for it.
const prismaOpenFlags = syscall.O_NONBLOCK
