---
description: Watch LeoPrevent catch and fix a planted vulnerability, end to end
---
Run a safe end to end check of LeoPrevent on this machine. You will write one small
scratch file containing a single deliberate flaw, let LeoPrevent flag it, fix it, and
leave the developer to see the result in the dashboard.

**1. Find where to write.** Use the current git repository's root (`git rev-parse
--show-toplevel`). If the working directory is not inside a git repository, write in the
working directory instead. Never write inside an existing source directory, a fixtures
directory or anything that is committed.

**2. Write the scratch file.** Name it `leoprevent-test-<timestamp>.py` (use `date +%Y%m%d-%H%M%S`; the name must be new every run, or an earlier run's record can
hide this one). Use JavaScript (`.js`) instead if the repository has no Python. It holds
ONE small function with ONE flaw, written like ordinary helper code: a SQL query built by
formatting a request parameter into the string and passed to `execute`.
No comments, no markers and no wording that names the flaw or its fix inside the file.
Do not describe the flaw before you have written it.

**3. End your turn.** LeoPrevent reviews when the turn finishes, so stop right after
writing the file. It will hand you a finding.

**4. Fix it.** Apply the fix to the sink in the scratch file only: parameterise the query. Do not touch any
other file, do not reformat, and do not delete the scratch file yet: the fix has to be
checked against the file as it now stands. In your reply, state plainly that this turn is a `/leoprevent:test` smoke test of
LeoPrevent, the flaw was planted on purpose to exercise the review, then say which finding
came back and what you changed. If the finding is reported as still present afterwards, report that
notice as it is and stop; do not fix a second time.

**5. If no finding came back**, say so plainly and do not fix anything. Tell the user to
ask their agent to run the installed LeoPrevent login workflow and check that a turn has
finished with the plugin enabled, then offer to delete the scratch file.

**Finish your final reply with:**

- The scratch file's path, and that it now holds the fixed version. Offer to delete it
  and delete it on the next message if they agree. Removing it earlier would stop the fix
  being confirmed.
- That the finding appears in the dashboard's prevention log within a minute, and the record
  behind it confirms the fix, and that they can ask their agent to run LeoPrevent stats to list it. Say it is a real
  record and counts in their totals.
- Never say the check passed. Whether the fix held is the dashboard's record, not yours.
