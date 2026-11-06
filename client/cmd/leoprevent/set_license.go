package main

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/config"
	"github.com/leotrace-hq/leoprevent-plugin/client/internal/review"
)

// runSetLicense is the `leoprevent set-license <key>` subcommand: store the customer
// license key in the per-user config file (config.SaveLicense), which the hook reads
// on every run. The file lives OUTSIDE the plugin dir, so a marketplace/plugin
// auto-update (which re-copies the plugin dir) never clobbers it — this is the
// production way a dev sets their key after installing from the marketplace. It can be
// run from a terminal OR from inside the agent (the plugin's bin/ is on the agent's
// Bash PATH). Human-facing stdout. A key of `-` is read from stdin instead, so a script can
// pass one without putting it in its argv, which any local user can read in the process list.
func runSetLicense(
	args []string,
) int {
	key := ""
	if len(args) == 1 {
		key = args[0]
	}
	if key == "-" {
		// Bounded: a key is well under 1 KiB, and a mistaken pipe must not be read whole.
		data, err := io.ReadAll(io.LimitReader(os.Stdin, 4096))
		if err != nil {
			fmt.Fprintf(os.Stderr, "leoprevent: could not read the license key from stdin: %v\n", err)
			return 1
		}
		key = string(data)
	}
	key = strings.TrimSpace(key)
	if len(args) != 1 || key == "" {
		fmt.Fprintln(os.Stderr, "usage: leoprevent set-license <license-key>  (or - to read it from stdin)")
		return 2
	}
	if !strings.HasPrefix(key, "lp_live_") {
		// Never the key itself: stderr can land in an agent's transcript or a terminal log.
		fmt.Fprintln(os.Stderr, "warning: that doesn't look like a LeoPrevent key (expected lp_live_…); saving anyway")
	}
	// Stored against THIS plugin's channel, so pasting a dev key into the dev plugin cannot
	// unlicense the prod one beside it. A plugin whose own config will not load has no channel
	// to file the key under, so it falls back to the channel-less slot any plugin may use —
	// which is the old behaviour, and better than refusing to save a key at all.
	path, err := saveKey(key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "leoprevent: could not save license key: %v\n", err)
		return 1
	}
	fmt.Print(review.Byline("License saved"))
	fmt.Println("> ")
	fmt.Printf("> License key saved to `%s`. It survives plugin updates. Open a new session to use it.\n", path)
	printWelcome(os.Stdout, loginAgent("", os.Getenv, loginAncestors(runtime.GOOS, os.Getppid(), loginParentProcess)))
	return 0
}

func saveKey(key string) (string, error) {
	cfg, err := config.Load()
	if err != nil {
		return config.SaveLicense(key)
	}
	return config.SaveLicenseFor(key, cfg.ServerURL, cfg.DashboardURL)
}
