// Package buildinfo carries the build-time version, stamped from plugin/VERSION
// (the single source of truth) into every binary via
//
//	-ldflags "-X github.com/leotrace-hq/leoprevent-plugin/buildinfo.Version=$(cat plugin/VERSION)"
//
// (see build.sh). It means two things depending on the binary:
//
//   - CLIENT hook binary: THIS build's own version — what the update nag compares
//     against the latest the server advertises.
//   - SERVER: the plugin version at the time the server was built, i.e. the "latest
//     client version" the server tells clients about (overridable at runtime with
//     LEOPREVENT_LATEST_CLIENT_VERSION for a release that bumps the plugin without a
//     server redeploy).
//
// Unstamped local/dev builds report "dev"; the update nag treats a non-semver
// version as "not behind" and stays silent, so `go run`/`go test` never nag.
package buildinfo

// Version is overwritten at link time; "dev" in an unstamped build.
var Version = "dev"
