package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/config"
)

// runSetLicense is the `leoprevent set-license <key>` subcommand: store the customer
// license key in the per-user config file (config.SaveLicense), which the hook reads
// on every run. The file lives OUTSIDE the plugin dir, so a marketplace/plugin
// auto-update (which re-copies the plugin dir) never clobbers it — this is the
// production way a dev sets their key after installing from the marketplace. It can be
// run from a terminal OR from inside the agent (the plugin's bin/ is on the agent's
// Bash PATH). Human-facing stdout.
func runSetLicense(args []string) int {
	if len(args) != 1 || strings.TrimSpace(args[0]) == "" {
		fmt.Fprintln(os.Stderr, "usage: leoprevent set-license <license-key>")
		return 2
	}
	key := strings.TrimSpace(args[0])
	if !strings.HasPrefix(key, "lp_live_") {
		fmt.Fprintf(os.Stderr, "warning: %q doesn't look like a LeoPrevent key (expected lp_live_…); saving anyway\n", key)
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
	fmt.Printf("License key saved to %s\nIt survives plugin updates. Open a new session to use it.\n", path)
	return 0
}

func saveKey(key string) (string, error) {
	cfg, err := config.Load()
	if err != nil {
		return config.SaveLicense(key)
	}
	return config.SaveLicenseFor(key, cfg.ServerURL, cfg.DashboardURL)
}
