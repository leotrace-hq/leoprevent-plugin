---
description: Save your LeoPrevent license key (survives plugin updates)
argument-hint: <lp_live_...>
allowed-tools: Bash(leoprevent-plugin:*)
---
Save the user's LeoPrevent license key by running EXACTLY this with the Bash/terminal tool:

```
leoprevent-plugin set-license $ARGUMENTS
```

If the shell reports **command not found** (agents other than Claude Code don't put the
plugin's bin dir on PATH), run the binary from the plugin's install directory instead:

- VS Code (GitHub Copilot), macOS/Linux:
  `"$HOME/.vscode/agent-plugins/github.com/leotrace-hq/leoprevent-plugin/copilot/leoprevent/bin/leoprevent-plugin" set-license $ARGUMENTS`
- VS Code (GitHub Copilot), Windows:
  `"$env:USERPROFILE\.vscode\agent-plugins\github.com\leotrace-hq\leoprevent-plugin\copilot\leoprevent\bin\leoprevent-plugin.exe" set-license $ARGUMENTS`
- Anywhere else: locate the installed plugin dir and run `bin/leoprevent-plugin` (or
  `bin\leoprevent-plugin.exe` on Windows) from it with the same arguments.

Then report only success (and the path it saved to) or the error. Do NOT echo the key
back to the user. If `$ARGUMENTS` is empty, don't run anything — tell the user the usage:
`/leoprevent:set-license <lp_live_...>` (Claude Code) / `/leoprevent set-license <lp_live_...>` (Copilot).
