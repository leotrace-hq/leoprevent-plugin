# LeoPrevent

Security review built into **Claude Code** and **Codex**. When the agent finishes a turn,
LeoPrevent reviews what it just wrote — and if there's a security issue, sends the agent back
to fix it before you see "done."

## Install

**Claude Code**
```
/plugin marketplace add leotrace-hq/leoprevent-plugin
/plugin install leoprevent@leotrace
```
It's a hooks plugin, so it won't show under `/plugins` — confirm it with `/hooks`.

**Codex**
```
codex plugin marketplace add leotrace-hq/leoprevent-plugin
```
Then enable **leoprevent** in the `/plugins` browser.

**Set your license key** — once. In a Claude Code or Codex session, have the agent run:
```
leoprevent-plugin set-license lp_live_your_key_here
```
It's saved to `~/.config/leoprevent/`, so it survives updates.

Now open a new session and work in a git repo as usual.

## Updates

- **Claude Code** updates automatically — you'll get a `/reload-plugins` prompt.
- **Codex**: run `codex plugin marketplace upgrade`.

## Good to know

- If the server is unreachable or your key isn't set, the review is skipped — it never blocks you.
