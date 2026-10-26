---
description: Sweep this repository's open Aikido findings and clear the false positives you agree with
argument-hint: '["plan" to only count the findings, "resolve" to record fixes]'
allowed-tools: Bash(leoprevent-plugin:*)
---
This sweeps the open Aikido findings in the current repository. LeoPrevent judges each one,
you check the ones it thinks are false positives, and the ones you agree with are ignored in
Aikido with the reason recorded. Work through it in these steps.

**1. Run the sweep** with the Bash/terminal tool, from inside the repository:

```
leoprevent-plugin aikido-sweep --agent <your agent: claude, codex or copilot>
```

If `$ARGUMENTS` asks only for a count or a plan, add `--plan`: it lists the files holding
open Aikido findings and sends no code. Report the counts and stop.

If `$ARGUMENTS` is `resolve`, skip the sweep: run step 8 alone and report what it says.

Without `--plan` it sends the whole content of every file in this repository that holds an
open Aikido finding to LeoPrevent for judging. Tell the user that before you run it, in one
sentence. Secret files and symlinks are never sent.

If the shell reports **command not found** (agents other than Claude Code don't put the
plugin's bin dir on PATH), locate the installed plugin dir and run `bin/leoprevent-plugin`
from it (`bin\leoprevent-plugin.exe` on Windows) with the same arguments. On any other
error, report what the command said and stop. It names the reason and what to do.

**2. Read the JSON.** `checked` is how many findings were judged. `disputed` are the ones
LeoPrevent thinks are false positives, listed per batch under `batches`. `real` are the ones
it agrees are real flaws: LeoPrevent records them as its own findings, they stay open in
Aikido, and they are listed under `real_findings` with what is wrong (`issue`) and the fix.
`absent` were not found in the code as it is now. `unjudged` and `failed_batches` were not
judged and stay open. `skipped` lists files that were not sent, with the reason. When
`complete` is false, Aikido returned more findings than one read covers, so say the sweep
covered part of the backlog.

**3. Check every disputed finding yourself.** For each one, open the file at its `location`
and decide whether LeoPrevent's reason (in `issue`) holds: is the flagged code really not
exploitable here? Read the surrounding code. Do not edit any code during the sweep.

**4. Answer each batch** by piping your answer into the answer step, one batch at a time:

```
leoprevent-plugin aikido-sweep answer --review <review_id> --agent <your agent> <<'EOF'
<location>: agree, false positive. <one sentence why>
<location>: disagree, this is real. <one sentence why, and the fix>
EOF
```

Give one line per finding in that batch, naming its `location`. Say plainly whether you
agree it is a false positive. If you are not sure, say so rather than agreeing: only a clear
agreement is acted on.

**5. Sort the real findings.** For each entry in `real_findings`, open the code and decide
whether it is a **small fix**: confined to one file, a few lines, and no change to an API, a
data shape or behaviour anyone relies on (adding a check, escaping a value, using the safe
call). Anything larger, or that you are unsure about, **needs a person**. Do not fix any of
them in this session.

**6. Offer a separate session for the small fixes.** If there are any (at most 10; take the
highest severity first) and you have a tool that starts a new session, such as the Claude
desktop app's tool for starting or forking a session, use it to OFFER one, forked from this
conversation so it keeps what you read, and let the user decide. Its task: fix exactly the
listed findings (give each location, issue and fix), change nothing else, say which ones it
could not fix safely, and finish by running `leoprevent-plugin aikido-sweep resolve --agent
<agent>` from the repository so the fixes are recorded. If you have no such tool, print that
same task as a prompt the user can paste into a new session.

**7. Report back** in a few lines: how many findings were checked, how many you agreed were
false positives, how many are real (small fixes offered, and the ones that need a person by
location), and what was skipped. `real_not_tracked` counts real findings in files that had
uncommitted changes during the sweep: a fix to those cannot be recorded by `resolve`, so say so.

**8. Recording fixes** (`resolve`). Run, from inside the repository:

```
leoprevent-plugin aikido-sweep resolve --agent <your agent>
```

It re-checks the real findings from this repository's last sweep whose files have changed
since, and records the ones that are gone as fixed. `fixed` lists them, `still_open` the ones
still present, `unchanged` the ones whose file was not touched, and `not_checked` any the
server could not check this time (run it again later). Report those in a line or two. Explain that the ones you
agreed with are ignored in Aikido automatically when the account has automatic ignore on (the
default), with LeoPrevent's reason recorded and an Undo on the dashboard. If an admin turned
it off, they appear on the dashboard's Aikido page to confirm. Never say a finding was
ignored in Aikido yourself: the command only records your answer.
