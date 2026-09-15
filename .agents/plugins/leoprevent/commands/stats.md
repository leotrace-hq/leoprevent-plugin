---
description: Summarise what LeoPrevent has caught for you recently
argument-hint: [e.g. "last 7 days", "in leoprevent", "the team"]
allowed-tools: Bash(leoprevent-plugin:*)
---
Read the user's LeoPrevent figures by running this with the Bash/terminal tool:

```
leoprevent-plugin stats
```

Translate `$ARGUMENTS` into flags when it asks for something specific: `--days N` for a
different window (default 30, max 365), `--repo NAME` to narrow the findings to one
repository, `--limit N` for more than the 10 most recent findings (max 100). Use
`--scope team` ONLY when the user asked about their team rather than themselves: it
covers everyone on the account and is refused unless they are an admin on it.

If the shell reports **command not found** (agents other than Claude Code don't put the
plugin's bin dir on PATH), locate the installed plugin dir and run `bin/leoprevent-plugin`
from it (`bin\leoprevent-plugin.exe` on Windows) with the same arguments. On any other
error, report what the command said and stop. It names the reason and what to do.

The output is JSON with two parts: `stats` (the period's figures) and `findings` (the
most recent flaws, newest first). Summarise it in a few lines of prose. Do not print the
JSON back, and do not add figures it does not contain.

**Say what the numbers mean, and do not overclaim:**

- **New** flaws were written during a turn, and LeoPrevent made the agent fix them before
  the turn could finish. **Existing** flaws were already in the code and are reported to
  the developer, not blocked on. Never describe an existing flaw as prevented or blocked,
  and never call one fixed unless `existingFixed` says it was.
- `caught` is every flaw detected, new and existing together. It is a detection count, not
  a prevention count.
- `reviews` is the turns that carried reviewable code; `turns` is every prompt. Rates
  divide by reviews.
- `interventionRate` of `null` means nothing was reviewed in the window, which is not the
  same as 0%. Say so rather than reporting a rate.
- A repository grade of `n/a` means too few reviews to grade, not a bad grade.
- `matched` is **not a total** when `truncated` is true. The read fetches a bounded slice of
  the log (100 rows, or 1000 when `--repo` or a rule narrows it), so an unfiltered `matched`
  of exactly 100 means "at least 100". Say "the N most recent" or "at least N", never "N
  flaws were found", and send them to the dashboard for the real figure. The counts in
  `stats` are unaffected: those come from the full record set, not from this list.

Lead with the period and the headline counts, then the flaws worth acting on: anything
still open, highest severity first. Point at the dashboard for the full log rather than
listing everything. If the window is empty, say the period was quiet; never present an
empty answer as a clean bill of health for code that was never reviewed.
