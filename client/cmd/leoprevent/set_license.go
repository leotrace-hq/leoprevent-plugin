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
	path, err := config.SaveLicense(key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "leoprevent: could not save license key: %v\n", err)
		return 1
	}
	fmt.Printf("License key saved to %s\nIt survives plugin updates. Open a new session to use it.\n", path)
	return 0
}
