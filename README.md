# LeoPrevent

Security review built into **Claude Code**, **Codex**, and **GitHub Copilot**. When the agent finishes a turn,
LeoPrevent reviews what it just wrote, and if there's a security issue it sends the agent back
to fix it before you see "done."

> **The client is open source** (Apache-2.0), and this repo carries its complete Go source next to the
> binaries it ships. You can read exactly what leaves your machine, and compile it yourself: clone,
> run `./build.sh` (needs only the Go toolchain named in `go.mod`), and the hashes match the shipped
> binaries byte-for-byte. Details: [Verify the binary matches this
> source](#verify-the-binary-matches-this-source).

## Claude Code

LeoPrevent works on all three ways of running Claude Code, but each installs differently, so pick your
section: the **[terminal CLI](#terminal-cli)** (slash commands), the **[desktop app](#desktop-app-code-tab)**
/ Code tab (a UI), or **[on the web](#on-the-web-claudeaicode)** at claude.ai/code (environment config).

### Terminal (CLI)

Install with the `/plugin` slash commands, **one at a time**, since each opens its own prompt:
```
/plugin marketplace add leotrace-hq/leoprevent-plugin
```
```
/plugin install leoprevent@leotrace
```
```
/reload-plugins
```
It shows up under `/plugin` (Installed plugins) and adds the `/leoprevent:set-license` command; its
review runs as a `Stop` hook, which you can see in `/hooks`.

Set your license key (once):
```
/leoprevent:set-license lp_live_your_key_here
```

To update: open `/plugin`, refresh the `leotrace` marketplace, then update **leoprevent** to the
latest version. Updates are **not** applied automatically: a fresh install or a plain restart uses
whatever version your local marketplace index last cached, so refresh the marketplace first to be sure
you're on the latest. Your license key survives the update.

_Optional, to get updates automatically:_ in `/plugin`, open the **Marketplaces** tab, select
`leotrace`, and enable auto-update. Claude Code then refreshes the marketplace in the background at
session start and prompts `/reload-plugins` when a newer **leoprevent** is available, so you don't have
to refresh by hand. (Off by default for third-party marketplaces like this one.)

### Desktop app (Code tab)

There's **no `/plugin` command** in the desktop app, so add the marketplace through the UI instead:

1. In the message box, open the **`+`** menu → **Add plugins…**. This opens the plugin **Directory**.
2. Click the **`+`** in the Directory's top-right toolbar, paste
   `https://github.com/leotrace-hq/leoprevent-plugin`, and add it. (A trust warning appears, which is expected
   for a third-party marketplace.)
3. Open the **Code** tab in the Directory, find **leoprevent**, and **install** it. Then **restart the
   app**: plugins load at startup, so the hook and the `/leoprevent:set-license` command aren't active
   until you restart.

Set your license key (once), **after** the restart above:
```
/leoprevent:set-license lp_live_your_key_here
```
(Before the restart this reads as an unknown command, because the plugin isn't loaded yet. If your
agent won't run it, set the key by hand. See [Set your license key](#set-your-license-key) below.)

To update manually: open **Customize** → **Plugins** → **Browse** → **Code**, open the `leotrace`
three-dots menu, and choose **Check for updates**. Your license key survives the update.

Third-party marketplaces do not update automatically by default. To receive future updates in the
background, enable auto-update from that same `leotrace` menu. Claude checks after a session starts;
an updated plugin is used by the next session. The background check can take up to ten minutes.

### On the web (claude.ai/code)

Cloud sessions have no `/plugin` command and don't inherit CLI/desktop installs, so you set it up
through the environment settings. All three steps live in the **three-dots menu (⋮)** → **Edit
environment**:

1. **Install it from the setup script:** scroll down to **Setup script** and append these lines (keep
   whatever's already there):
   ```bash
   # LeoPrevent security review hook
   CLAUDE_BIN="$(command -v claude || ls -d "$HOME"/.local/bin/claude "$HOME"/.claude/local/claude \
     /usr/local/bin/claude /opt/node*/bin/claude 2>/dev/null | head -1)"
   CLAUDE_BIN="${CLAUDE_BIN:-claude}"
   "$CLAUDE_BIN" plugin marketplace add leotrace-hq/leoprevent-plugin \
     --sparse .claude-plugin .agents/plugins || true
   "$CLAUDE_BIN" plugin install leoprevent@leotrace \
     || echo "leoprevent: install failed, reviews will not run" >&2
   "$CLAUDE_BIN" plugin list || true   # confirms in the setup log that it landed
   ```
   Every line tolerates failure independently, so this is safe to append to a script that uses
   `set -e`.
2. **Set your license key:** add `LEOPREVENT_LICENSE_KEY` as an environment variable.
3. **Allow the server:** under **Network access**, choose **Custom**, tick **"Also include default
   list of common package managers"** (keeps everything Trusted allows), and add `api.leotrace.io`
   to **Allowed domains**. Without this the hook can't reach the server and the review is skipped
   (fail-open).

All three apply to **new** sessions only.

**Verify in a new session:** check the setup log for the `claude plugin list` output, or ask Claude to
run it. It should show `leoprevent@leotrace … enabled`. (Nothing in the script exits non-zero on
failure, deliberately: a bad install must never break the rest of your setup or block your session. The
cost is that a failure is quiet unless you look, so if a review never fires, read the setup log for
`leoprevent: install failed, reviews will not run`, or for `claude: command not found` if the CLI
couldn't be resolved, before assuming the plugin is broken.)

**Which version you get, and how to update.** The setup script runs when the environment's filesystem
cache is built, not on every session, so you're on whatever release was current at that point (the
cache rebuilds roughly weekly). To pull a newer LeoPrevent, change the setup script or the allowed
hosts: either forces a rebuild. Editing an environment variable does not. That's also the fix if an
install ever fails: the failure gets snapshotted too, so it won't clear itself on the next session.

## Codex

Install:
```bash
codex plugin marketplace add leotrace-hq/leoprevent-plugin
codex plugin add leoprevent@leotrace
```

Open a new Codex session after installing, then verify the active installation:

```bash
codex plugin list --marketplace leotrace
```

It should show `leoprevent@leotrace` as installed and enabled.

Set your license key (once). See [Set your license key](#set-your-license-key) below.

To update:

```bash
codex plugin marketplace upgrade leotrace
codex plugin add leoprevent@leotrace
```

The first command refreshes the marketplace snapshot; it does not replace the installed plugin by
itself. The second command installs the latest version from that snapshot. Open a new Codex session
afterward so its hooks load the updated version. Your license key survives the update.

## GitHub Copilot (VS Code)

> Agent hooks are a Preview feature in VS Code. If a review ever doesn't fire, it fails open
> (never blocks you).

Install:
1. Open the Command Palette (`Cmd/Ctrl+Shift+P`) → run **"Chat: Install Plugin from Source"** → paste:
   ```
   https://github.com/leotrace-hq/leoprevent-plugin
   ```
2. **Restart the extension host when prompted** ("Restart Extensions", or reload the window). The plugin
   only activates after this.
3. Set your license key (once). In Copilot chat, run:
   ```
   /leoprevent set-license lp_live_your_key_here
   ```
   (Copilot asks for confirmation before running the save command.) Alternatively, create the
   key file by hand. See [Set your license key](#set-your-license-key) below.

The review then runs as a `Stop` hook.

To update: Command Palette → **"Chat: Update Plugins"** (or the documented equivalent
**"Extensions: Check for Extension Updates"**), then reload the window. (Re-running
"Chat: Install Plugin from Source" does **not** update an existing install.)

## Set your license key

Applies to **Codex** (and works as a fallback for Copilot; Claude Code uses `/leoprevent:set-license`
and Copilot `/leoprevent set-license` instead). Your key is a small JSON file in your user config
dir. Create it once; it survives plugin updates. Replace `lp_live_your_key_here` with your key.

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

- After installing, **open a new session** and work in a **git repo**, which is what the review runs against.
- Your license key is saved to your user config dir (`~/Library/Application Support/leoprevent/` on
  macOS, `~/.config/leoprevent/` on Linux, `%AppData%\leoprevent\` on Windows), outside the plugin, so
  it **survives updates**.
- If the server is unreachable or your key isn't set, the review is simply skipped. It never blocks you.
- **Windows:** works with Claude Code (the plugin ships a Windows binary; PowerShell, cmd, and Git
  Bash are all covered). Codex on Windows is not supported yet.

## Verify the binary matches this source

This repo contains the **complete source** of the client binary it ships, and the build is
**reproducible**, so you don't have to take our word that the two belong together. Rebuild it and
compare:

```bash
./build.sh
shasum -a 256 bin/leoprevent-plugin .agents/plugins/leoprevent/bin/leoprevent-plugin-darwin-arm64
```

The two hashes must be identical (use the `-darwin-amd64` or `-linux-amd64` binary to match your
platform). `build.sh` needs nothing but a Go toolchain; the module is self-contained.

**Build with the Go version named in `go.mod`.** Go bakes toolchain details into the binary, so a
different Go release produces a different (still perfectly valid) hash. If your hashes don't match,
check `go version` first.

What you can confirm from the source: exactly what leaves your machine, when a review is skipped, and
that the client contains no rule content of its own (it asks the server).

## About this repository

This repo is a **published mirror** of the plugin source, regenerated from our internal repo on every
release, and the whole tree is replaced each time. Two consequences worth knowing before you spend time:

- **Pull requests can't be merged here.** A merge would be overwritten by the next release, silently.
  If you have a fix or an idea, email it to **info@leotrace.io** and we'll apply it upstream with
  credit.
- **Issues aren't tracked here.** Bugs go to the same address; security reports follow
  [SECURITY.md](SECURITY.md).

The source is published so you can verify what the client does and that the binary matches, not
because development happens here. Licensed under Apache-2.0 (see [LICENSE](LICENSE)).
