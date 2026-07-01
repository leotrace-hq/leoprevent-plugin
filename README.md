# LeoPrevent

Security review built into **Claude Code** and **Codex**. When the agent finishes a turn,
LeoPrevent reviews what it just wrote — and if there's a security issue, sends the agent back
to fix it before you see "done."

## Claude Code

Install:
```
/plugin marketplace add leotrace-hq/leoprevent-plugin
/plugin install leoprevent@leotrace
```
It shows up under `/plugin` (Installed plugins) and adds the `/leoprevent:set-license` command; its
review runs as a `Stop` hook, which you can see in `/hooks`.

Set your license key (once):
```
/leoprevent:set-license lp_live_your_key_here
```

Updates are automatic — you'll get a `/reload-plugins` prompt when a new version lands.

## Codex

Install:
```
codex plugin marketplace add leotrace-hq/leoprevent-plugin
```
Then enable **leoprevent** in the `/plugins` browser.

Set your license key (once). Codex has no slash command for this, so you run the plugin's own
binary — **`leoprevent-plugin`** — with your key. Once the plugin is enabled it's on the agent's
`PATH`, so just ask Codex to run:
```
leoprevent-plugin set-license lp_live_your_key_here
```
If you ever need the full path, the binary lives inside the installed plugin at
`~/.codex/plugins/cache/leotrace/leoprevent/<version>/bin/leoprevent-plugin`.

To update: `codex plugin marketplace upgrade`.

## Good to know

- After installing, **open a new session** and work in a **git repo** — that's what the review runs against.
- Your license key is saved to `~/.config/leoprevent/`, outside the plugin, so it **survives updates**.
- If the server is unreachable or your key isn't set, the review is simply skipped — it never blocks you.
