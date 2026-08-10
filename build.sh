#!/usr/bin/env bash
# Build the LeoPrevent CLIENT hook binary (host + cross-compiled) into ./bin.
#
# This script lives INSIDE the plugin module on purpose: the module is
# self-contained and open-sourceable, so this file is also the PUBLIC BUILD
# RECIPE — the exact command anyone can run against the published source to
# reproduce the released binary byte-for-byte and confirm the two belong
# together. It must therefore never reference anything outside this directory.
# (This builds the client only. LeoTrace's server is built separately, by tooling
# that lives outside this module and calls this script.)
#
# The client embeds NO rules — it talks to the server (cloud /review or local
# /rules), configured by the committed leoprevent.json (server_url + tier).
#
# Reproducibility notes, all load-bearing — do not drop them:
#   -trimpath        strip absolute source paths (else your $HOME is in the binary)
#   -buildvcs=false  omit VCS metadata (else a dirty tree changes the hash)
#   -buildid=        drop the build-ID fingerprint
#   -s -w            strip symbol table + DWARF
# Import paths are compiled into the binary, so renaming this module or moving a
# package CHANGES THE HASH. The Go toolchain version matters too: build with the
# version named in go.mod, or expect a different (still valid) binary.
set -euo pipefail
cd "$(dirname "$0")"

# Version stamped into the binary (buildinfo.Version), from ./VERSION — the single
# source of truth. The client compares it against the server's advertised latest to
# drive the update nag. Unset → "dev" (nag stays silent).
VERSION=$(tr -d '[:space:]' < VERSION 2>/dev/null || true)
[ -n "$VERSION" ] || VERSION=dev

LDFLAGS="-s -w -buildid= -X github.com/leotrace-hq/leoprevent-plugin/buildinfo.Version=$VERSION"
BUILDFLAGS="-trimpath -buildvcs=false"
PKG=./client/cmd/leoprevent

echo "==> building client hook binary v$VERSION (bin/leoprevent-plugin)"
go build $BUILDFLAGS -ldflags="$LDFLAGS" -o bin/leoprevent-plugin "$PKG"

echo "==> cross-compiling client"
GOOS=darwin  GOARCH=arm64 go build $BUILDFLAGS -ldflags="$LDFLAGS" -o bin/leoprevent-plugin-darwin-arm64 "$PKG"
GOOS=darwin  GOARCH=amd64 go build $BUILDFLAGS -ldflags="$LDFLAGS" -o bin/leoprevent-plugin-darwin-amd64 "$PKG"
GOOS=linux   GOARCH=amd64 go build $BUILDFLAGS -ldflags="$LDFLAGS" -o bin/leoprevent-plugin-linux-amd64  "$PKG"
# Windows: static .exe (cross-compiled on macOS/Linux; never built on Windows).
# CGO is off by default when cross-compiling, so these are self-contained.
GOOS=windows GOARCH=amd64 go build $BUILDFLAGS -ldflags="$LDFLAGS" -o bin/leoprevent-plugin-windows-amd64.exe "$PKG"
GOOS=windows GOARCH=arm64 go build $BUILDFLAGS -ldflags="$LDFLAGS" -o bin/leoprevent-plugin-windows-arm64.exe "$PKG"

echo "==> client done"
