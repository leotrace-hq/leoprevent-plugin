# LeoPrevent

Security review built into **Claude Code**, **Codex**, and **GitHub Copilot**. When the agent finishes a turn,
LeoPrevent reviews what it just wrote — and if there's a security issue, sends the agent back
to fix it before you see "done."

## Claude Code

Install:
```
/plugin marketplace add leotrace-hq/leoprevent-plugin
/plugin install leoprevent@leotrace
/reload-plugins
```
It shows up under `/plugin` (Installed plugins) and adds the `/leoprevent:set-license` command; its
review runs as a `Stop` hook, which you can see in `/hooks`.

Set your license key (once):
```
/leoprevent:set-license lp_live_your_key_here
```

To update: open `/plugin`, refresh the `leotrace` marketplace, then update **leoprevent** to the
latest version. Updates are **not** applied automatically — a fresh install or a plain restart uses
whatever version your local marketplace index last cached, so refresh the marketplace first to be sure
you're on the latest. Your license key survives the update.

_Optional — get updates automatically:_ in `/plugin`, open the **Marketplaces** tab, select
`leotrace`, and enable auto-update. Claude Code then refreshes the marketplace in the background at
session start and prompts `/reload-plugins` when a newer **leoprevent** is available, so you don't have
to refresh by hand. (Off by default for third-party marketplaces like this one.)

## Codex

Install:
```
codex plugin marketplace add leotrace-hq/leoprevent-plugin
```
Then enable **leoprevent** in the `/plugins` browser.

Set your license key (once). Codex has no slash command for this, so you run the plugin's own
binary — **`leoprevent-plugin`** — with your key, using the full path to the installed binary:
```
~/.codex/plugins/cache/leotrace/leoprevent/<version>/bin/leoprevent-plugin set-license lp_live_your_key_here
```
(Replace `<version>` with the installed version, e.g. `0.1.5`.)

To update: `codex plugin marketplace upgrade`.

## GitHub Copilot (VS Code)

> **Beta.** Tested in VS Code agent mode; agent hooks are Preview in VS Code. If a review doesn't fire,
> it fails open (never blocks you).

Install:
```
Command Palette → "Chat: Install Plugin From Source"
→ paste: https://github.com/leotrace-hq/leoprevent-plugin
```
The review runs as a `Stop` hook.

Set your license key (once) — Copilot has no slash command, so run the installed binary directly with
your key (full path to the installed `leoprevent-plugin`):
```
<plugin-dir>/leoprevent/bin/leoprevent-plugin set-license lp_live_your_key_here
```

## Good to know

- After installing, **open a new session** and work in a **git repo** — that's what the review runs against.
- Your license key is saved to your user config dir (`~/Library/Application Support/leoprevent/` on
  macOS, `~/.config/leoprevent/` on Linux, `%AppData%\leoprevent\` on Windows), outside the plugin, so
  it **survives updates**.
- If the server is unreachable or your key isn't set, the review is simply skipped — it never blocks you.
- **Windows:** works with Claude Code (the plugin ships a Windows binary; PowerShell, cmd, and Git
  Bash are all covered). Codex on Windows is not supported yet.
