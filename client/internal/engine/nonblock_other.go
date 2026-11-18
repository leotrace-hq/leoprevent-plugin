//go:build !unix

package engine

// openNonblock is 0 where named pipes are not files a path can be swapped for (Windows
// keeps them under \\.\pipe\), so there is nothing to guard against.
const openNonblock = 0
