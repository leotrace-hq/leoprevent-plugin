---
description: Show this project's dependency scan and offer to fix what has a safe fix
allowed-tools: Bash(leoprevent-plugin:*)
---
Run LeoPrevent's dependency scan of this project with the Bash/terminal tool:

```
leoprevent-plugin sca --session=${CLAUDE_SESSION_ID}
```

If the shell reports **command not found** (agents other than Claude Code don't put the
plugin's bin dir on PATH), locate the installed plugin dir and run `bin/leoprevent-plugin`
from it (`bin\leoprevent-plugin.exe` on Windows) with the same arguments. On any other
error, report what the command said and stop. It names the reason and what to do.

The user cannot see the command's output. Do what it says:

- If it says LeoPrevent shows its report when this turn ends, reply with only the line it gives
  you and end your turn. Don't describe the scan: LeoPrevent shows the report itself, and asks
  any question, as soon as your turn ends.
- Otherwise it holds LeoPrevent's notice. Write that notice as the text of your message, exactly
  as the output gives it, before you call any other tool. Never summarise, shorten or reword it.
  Then follow LeoPrevent's instructions after it, if there are any. They ask one question at
  most. Change nothing unless the user says yes.
