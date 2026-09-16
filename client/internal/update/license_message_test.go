package update

import (
	"strings"
	"testing"
)

func TestMissingLicenseGuidanceUsesBrowserLogin(
t *testing.T,
) {
	for _, agent := range []string{"claude", "codex", "copilot"} {
		t.Run(agent, func(
		t *testing.T,
		) {
			for name, message := range map[string]string{
				"terminal": LicenseMessage(agent),
				"context":  LicenseContextMessage(agent),
			} {
				for _, required := range []string{"login", "browser", "Connected to LeoPrevent", "--no-browser"} {
					if !strings.Contains(message, required) {
						t.Errorf("%s notice missing %q: %s", name, required, message)
					}
				}
				if strings.Contains(message, "set-license") || strings.Contains(message, "lp_live_") {
					t.Errorf("%s notice directs the user to copy a license key: %s", name, message)
				}
				if agent == "claude" && !strings.Contains(message, "/leoprevent:login") {
					t.Errorf("%s notice missing the Claude login command: %s", name, message)
				}
				if agent != "claude" && !strings.Contains(message, "installed") {
					t.Errorf("%s notice assumes the plugin binary is on PATH: %s", name, message)
				}
			}
		})
	}
}
