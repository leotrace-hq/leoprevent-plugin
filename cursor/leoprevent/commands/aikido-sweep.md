---
description: Sweep this repository's open Aikido findings and clear the false positives you agree with
argument-hint: '["plan" to only count the findings, "next" to sweep the next batch, "resolve" to record fixes]'
allowed-tools: Bash(leoprevent-plugin:*)
---
This sweeps the open Aikido findings in the current repository. LeoPrevent judges each one,
you check the ones it thinks are false positives, and your answers are recorded. Work through
it in these steps.

**Start your reply with this block**, exactly as written, before any tool call, unless
`$ARGUMENTS` asks only for a count or a plan, or is `resolve`:

> 🛡️ **LeoPrevent** · Aikido sweep
> 
> Running the sweep sends the full contents of every file with an open Aikido finding to LeoPrevent for judging. Secret files and symlinks are never sent.

**Notices.** The commands below print a LeoPrevent block above their JSON, a quoted block
opening with the shield. Print each one to the user as soon as the command returns, exactly
as it is (every `> ` line, as markdown), never in your own words. Follow every block with at
least one line of your own before any other block, so two blocks never sit back to back.

**1. Run the sweep** with the Bash/terminal tool, from inside the repository:

```
leoprevent-plugin aikido-sweep --agent <your agent: claude, codex or copilot>
```

If `$ARGUMENTS` asks only for a count or a plan, add `--plan`: it lists the files holding
open Aikido findings and sends no code. Reply with its block, exactly as it is (or the
counts, when it has none), and stop.

If `$ARGUMENTS` is `next`, add `--next`: it sweeps the batch after the last run's.

If `$ARGUMENTS` is `resolve`, skip the sweep: run step 8 alone and report what it says.

If the shell reports **command not found** (agents other than Claude Code don't put the
plugin's bin dir on PATH), locate the installed plugin dir and run `bin/leoprevent-plugin`
from it (`bin\leoprevent-plugin.exe` on Windows) with the same arguments. On any other
error, report what the command said and stop. It names the reason and what to do.

**2. Print the sweep's block at once**, then one line saying you are now checking the disputed
findings. Do this before you read any code.

**Read the JSON.** `checked` is how many findings were judged. `disputed` are the ones
LeoPrevent thinks are false positives, listed per batch under `batches`. `real` are the ones
it agrees are real flaws: LeoPrevent records them as its own findings, they stay open in
Aikido, and they are listed under `real_findings` with what is wrong (`issue`) and the fix.
`already_answered` counts findings you agreed were false positives in an earlier sweep in the
last day: they were left out, and Aikido may not show them as ignored yet. `absent` were not
found in the code as it is now. `unjudged` and `failed_batches` were not
judged and stay open. `skipped` lists files that were not sent, with the reason. When
`complete` is false, Aikido returned more findings than one read covers, so say the sweep
covered part of the backlog. One run judges about 25 findings (whole files, so a file with more
is judged alone); `remaining_findings` and `remaining_files` are the ones left for a later run.

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
them yet.

**6. Report back.** You printed the sweep's block in step 2; do not repeat it. In a few lines,
say how many you agreed were false positives, how many are real
(the small fixes and the ones that need a person, by location), and what was skipped.
`real_not_tracked` counts real findings in files that had uncommitted changes during the sweep:
a fix to those cannot be recorded by `resolve`, so say so.

**7. Ask what to do next.** Only after the report is written, ask the user one question with a question tool if you have one
(such as AskUserQuestion), otherwise in one line, and end your turn. Its options are:

- **Fix the small real flaws**, when there are any (at most 10; the highest severity first).
- **Sweep the next batch**, when `remaining_findings` is above 0.

If only one applies, offer it with a "Stop here" option. If neither applies, ask nothing. Never
start or offer a new session for either, and never act without the user's answer.

On **fix**: fix exactly the small fixes you listed, here, and change nothing else. Say which ones
you could not fix safely. Then run step 8 to record the fixes, and when `remaining_findings` is
above 0, ask again whether to sweep the next batch.

On **next batch**: run the sweep again with `--next` added and work through steps 2 to 7 for
that batch.

**8. Recording fixes** (`resolve`). Run, from inside the repository:

```
leoprevent-plugin aikido-sweep resolve --agent <your agent>
```

It re-checks the real findings from this repository's last sweep whose files have changed
since, and records the ones that are gone as fixed. `fixed` lists them, `still_open` the ones
still present, `unchanged` the ones whose file was not touched, and `not_checked` any the
server could not check this time (run it again later). Print its block first (or those
counts in a line, when it has none), then name the fixed and still open findings by
location. Do not mention ignoring findings in Aikido: the command only records your answer.
