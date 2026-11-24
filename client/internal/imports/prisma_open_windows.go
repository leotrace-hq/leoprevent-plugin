//go:build windows

package imports

// prismaOpenFlags: Windows has no FIFO to block on.
const prismaOpenFlags = 0
