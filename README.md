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

**Using the Claude Code desktop app (Code tab)?** There's no `/plugin` command there — add the
marketplace through the UI instead:

1. In the message box, open the **`+`** menu → **Add plugins…**. This opens the plugin **Directory**.
2. Click **Add marketplace**, paste `https://github.com/leotrace-hq/leoprevent-plugin`, and click
   **Sync**. (A trust warning appears — expected for a third-party marketplace.)
3. Find **leoprevent** in the Directory and **install** it, then **restart the app** — plugins load at
   startup, so the hook and the `/leoprevent:set-license` command aren't active until you restart.

Set your license key (once):
```
/leoprevent:set-license lp_live_your_key_here
```
(In the desktop app, run this **after** the restart above — before that it reads as an unknown command
because the plugin isn't loaded yet. If your agent won't run it, set the key by hand — see
[Set your license key](#set-your-license-key) below.)

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

Set your license key (once) — see [Set your license key](#set-your-license-key) below.

To update: `codex plugin marketplace upgrade`.

## GitHub Copilot (VS Code)

> Agent hooks are a Preview feature in VS Code. If a review ever doesn't fire, it fails open
> (never blocks you).

Install:
1. Open the Command Palette (`Cmd/Ctrl+Shift+P`) → run **"Chat: Install Plugin from Source"** → paste:
   ```
   https://github.com/leotrace-hq/leoprevent-plugin
   ```
2. **Restart the extension host when prompted** ("Restart Extensions", or reload the window) — the plugin
   only activates after this.
3. Set your license key (once) — in Copilot chat, run:
   ```
   /leoprevent set-license lp_live_your_key_here
   ```
   (Copilot asks for confirmation before running the save command.) Alternatively, create the
   key file by hand — see [Set your license key](#set-your-license-key) below.

The review then runs as a `Stop` hook.

To update: Command Palette → **"Chat: Update Plugins"** (or the documented equivalent
**"Extensions: Check for Extension Updates"**), then reload the window. (Re-running
"Chat: Install Plugin from Source" does **not** update an existing install.)

## Set your license key

Applies to **Codex** (and works as a fallback for Copilot; Claude Code uses `/leoprevent:set-license`
and Copilot `/leoprevent set-license` instead). Your key is a small JSON file in your user config
dir — create it once; it survives plugin updates. Replace `lp_live_your_key_here` with your key.

**macOS:**
```bash
mkdir -p "$HOME/Library/Application Support/leoprevent"
echo '{"license_key":"lp_live_your_key_here"}' > "$HOME/Library/Application Support/leoprevent/license.json"
```

**Ubuntu / Linux:**
```bash
mkdir -p "$HOME/.config/leoprevent"
echo '{"license_key":"lp_live_your_key_here"}' > "$HOME/.config/leoprevent/license.json"
```

**Windows (PowerShell):**
```powershell
New-Item -ItemType Directory -Force "$env:AppData\leoprevent" | Out-Null
'{"license_key":"lp_live_your_key_here"}' | Out-File -Encoding ascii "$env:AppData\leoprevent\license.json"
```

## Good to know

- After installing, **open a new session** and work in a **git repo** — that's what the review runs against.
- Your license key is saved to your user config dir (`~/Library/Application Support/leoprevent/` on
  macOS, `~/.config/leoprevent/` on Linux, `%AppData%\leoprevent\` on Windows), outside the plugin, so
  it **survives updates**.
- If the server is unreachable or your key isn't set, the review is simply skipped — it never blocks you.
- **Windows:** works with Claude Code (the plugin ships a Windows binary; PowerShell, cmd, and Git
  Bash are all covered). Codex on Windows is not supported yet.
