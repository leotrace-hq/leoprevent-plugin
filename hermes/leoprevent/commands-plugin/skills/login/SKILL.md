---
description: Sign in to LeoPrevent in your browser without copying a license key
---
Use the terminal tool for shell commands. The installed LeoPrevent binary is `"${HERMES_HOME:-$HOME/.hermes}/leoprevent/bin/leoprevent-plugin"`. Use that path whenever the instructions below call leoprevent-plugin. `$ARGUMENTS` means the user's instruction alongside this skill invocation, not a shell environment variable.

Run `leoprevent-plugin login --agent=hermes` in the terminal. If it is not on PATH, locate the installed
plugin and run its `bin/leoprevent-plugin login --agent=hermes` (Windows: `bin\leoprevent-plugin.exe login`).
Use `login --no-browser` only when the user requests it or the session is remote/headless.
A local terminal session supports opening the browser normally.

Show the verification URL and code while waiting for approval. Keep the command running
and collect its final result. Never request or print a persistent license key.
After exit code 0, reply with the command's LeoPrevent block as markdown: the line
`> 🛡️ **LeoPrevent** · Connected`, verbatim. Only if the
command's output tells you to repeat the whole block, repeat every `> ` line of it verbatim,
welcome included; otherwise say nothing more, because the user can already see it.
If the command reports an environment override or an app-return failure, include that
specific notice. Do not append a generic setup checklist or claim hooks were verified.
On failure, report the error instead of a success message.
