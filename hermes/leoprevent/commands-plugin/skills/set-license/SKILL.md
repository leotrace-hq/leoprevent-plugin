---
description: Save your LeoPrevent license key (survives plugin updates)
---
Use the terminal tool for shell commands. The installed LeoPrevent binary is `"${HERMES_HOME:-$HOME/.hermes}/leoprevent/bin/leoprevent-plugin"`. Use that path whenever the instructions below call leoprevent-plugin. `$ARGUMENTS` means the user's instruction alongside this skill invocation, not a shell environment variable.

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

Then report only success or the error. On success, reply with the command's LeoPrevent block as
markdown: the lines starting `> 🛡️ **LeoPrevent** · License saved` and `> License key saved`,
verbatim. Only if the command's output tells you to repeat the whole block, repeat every `> `
line of it verbatim, welcome included; otherwise say nothing more, because the user can already
see it. Do NOT echo the key
back to the user. If `$ARGUMENTS` is empty, don't run anything — tell the user the usage:
`/leoprevent:set-license <lp_live_...>` (Claude Code) / `/leoprevent set-license <lp_live_...>` (Copilot).
