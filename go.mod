// The LeoPrevent plugin: the client hook binary and the packages it shares with
// the server. This module is self-contained and open-sourceable — the shipped
// binary is built from this module ALONE, so the published source can be rebuilt
// byte-for-byte. Nothing here may import the private root `leoprevent` module.
//
// The Go version below is load-bearing for that guarantee: the toolchain bakes
// details into the binary, so building with a different Go release produces a
// different (still valid) hash. Build with the version named here, or the
// byte-for-byte comparison will not match. `go mod tidy` strips a `toolchain`
// directive that merely repeats the `go` line, so this is stated rather than pinned.
module github.com/leotrace-hq/leoprevent-plugin

go 1.25.4

require (
	github.com/go-enry/go-enry/v2 v2.9.6
	gopkg.in/yaml.v3 v3.0.1
)

require github.com/go-enry/go-oniguruma v1.2.1 // indirect
