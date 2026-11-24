---
description: List your open LeoPrevent findings, or ignore, resolve or reopen one
---
Use the terminal tool for shell commands. The installed LeoPrevent binary is `"${HERMES_HOME:-$HOME/.hermes}/leoprevent/bin/leoprevent-plugin"`. Use that path whenever the instructions below call leoprevent-plugin. `$ARGUMENTS` means the user's instruction alongside this skill invocation, not a shell environment variable.

Work with the user's open LeoPrevent findings by running `leoprevent-plugin findings` with
the Bash/terminal tool. Translate `$ARGUMENTS` into one of these:

```
leoprevent-plugin findings [--scope team] [--repo NAME] [--rule ID] [--limit N] [--all] [--days N]
leoprevent-plugin findings ignore <id> --reason "<why it is safe to leave>" [--scope team]
leoprevent-plugin findings resolve <id> --reason "<how it was handled>" [--scope team]
leoprevent-plugin findings reopen <id> [--scope team]
```

With no subcommand it lists **open** findings nobody has ignored or resolved, across all
time, 20 at a time (`--limit` up to 100). `--all` lists every finding, open or not, over the
last 30 days. Use `--scope team` ONLY when the user asked about their team rather than
themselves, or names a finding a teammate's turn produced: it covers everyone on the account
and is refused unless they are an admin on it.

If the shell reports **command not found** (agents other than Claude Code don't put the
plugin's bin dir on PATH), locate the installed plugin dir and run `bin/leoprevent-plugin`
from it (`bin\leoprevent-plugin.exe` on Windows) with the same arguments. On any other
error, report what the command said and stop. It names the reason and what to do.

**Listing.** The output is the dashboard's JSON. Each finding carries an `id`: that is the
id `ignore`, `resolve` and `reopen` take. `origin` is `new` (written during a turn) or
`existing` (already in the code). Summarise the list in a few lines, highest severity first,
naming each finding's id, rule, repository and location. Do not print the JSON back.
`matched` is **not a total** when `truncated` is true: say "at least N".

**Ignoring or resolving is a decision a person owns.** It is recorded against the key's
owner, with the reason, in the account's audit log, and the finding drops out of the open
list until it is detected again.

- Only ignore or resolve a finding when the user explicitly asked you to, naming that
  finding. Never do it on your own initiative, and never to make a review or a list go
  quiet. Arguing a finding away is not a decision the user made.
- The reason is required. Use the user's own words; if they gave none, ask for one rather
  than writing it yourself.
- `resolve` means the flaw was dealt with outside the code LeoPrevent re-checked (fixed
  elsewhere, mitigated upstream). If the code itself was fixed, the next review records that
  on its own; do not resolve it by hand.
- After the call, say what was recorded and that `reopen <id>` undoes it.
