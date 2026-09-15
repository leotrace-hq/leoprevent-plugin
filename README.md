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
It shows up under `/plugin` (Installed plugins) and adds the `/leoprevent:login` command; its
review runs as a `Stop` hook, which you can see in `/hooks`.

Connect with browser login:
```
/leoprevent:login
```
Sign in, confirm the email and account, and choose **Link installation**. Keep the command
running until it says **Connected to LeoPrevent.**

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
   app**: plugins load at startup, so the hook and the `/leoprevent:login` command aren't active
   until you restart.

Connect with browser login **after** the restart above:
```
/leoprevent:login
```
Sign in, confirm the email and account, and choose **Link installation**. Wait for
**Connected to LeoPrevent.** Before restarting, the command may be unknown because the plugin
is not loaded yet. Manual setup remains available under [Set your license key](#set-your-license-key).

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

In the app, add a local project folder before opening hook settings.

**Review and trust the hooks before using the plugin.** In the new CLI session, run `/hooks`
and review and trust each LeoPrevent hook: **UserPromptSubmit**, **PreToolUse**, and **Stop**.
In the app, open **Settings (Cmd+,) → Coding → Hooks → LeoPrevent** and review each hook there.
An installed, enabled plugin (including a green tick) can still have untrusted hooks and perform
no reviews. Do not add `trusted_hash` values by hand; let Codex record trust after your review.

Codex skips new or changed hook definitions until they are trusted again. See
[OpenAI's hook-trust documentation](https://learn.chatgpt.com/docs/hooks#review-and-trust-hooks).


Connect with [browser login](#browser-login). Ask Codex to run the installed plugin's
`bin/leoprevent-plugin login` and keep it running while you approve in your browser.
Wait for **Connected to LeoPrevent.** Manual keys remain available for local-tier licenses.

To update:

```bash
codex plugin marketplace upgrade leotrace
codex plugin add leoprevent@leotrace
```

The first command refreshes the marketplace snapshot; it does not replace the installed plugin by
itself. The second command installs the latest version from that snapshot. Open a new Codex session
afterward so its hooks load the updated version. Use `/hooks` to review and trust any new or changed
LeoPrevent hooks. Your license key survives the update.

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
3. Connect with browser login. Send this to Copilot chat:
   ```text
   Run LeoPrevent login using the installed plugin binary and wait for completion.
   ```
   Copilot should locate the installed plugin and run `bin/leoprevent-plugin login`
   (Windows: `bin\leoprevent-plugin.exe login`); the binary may not be on PATH.
   Sign in, confirm the email and account, and choose **Link installation**. Keep the command
   running until it says **Connected to LeoPrevent.** Manual keys remain available under
   [Set your license key](#set-your-license-key).

The review then runs as a `Stop` hook.

To update: Command Palette → **"Chat: Update Plugins"** (or the documented equivalent
**"Extensions: Check for Extension Updates"**), then reload the window. (Re-running
"Chat: Install Plugin from Source" does **not** update an existing install.)

## See what it has caught

Ask your agent for a summary of your own review activity:

```
/leoprevent:stats
```

It reports the period's figures (turns, reviews, how many flaws were caught and how many were
fixed) and the most recent flaws behind them. Add a window, a repository, or a longer list in
plain English, for example "in the last 7 days" or "in leoprevent"; your agent turns that into
the right flags. Everything it reports is your own activity by default.

The command sends **no code and no prompt**. It sends your license key, a view name and a few
filters, and reads back the same figures your dashboard shows.

Claude Code and Copilot pick this up from the plugin (Copilot spells it `/leoprevent stats`,
with a space). On Codex, which cannot contribute slash commands, run the installed plugin's
`bin/leoprevent-plugin stats` and ask Codex to summarise it.

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

## Pull requests (GitHub Action)

The plugin reviews an agent's work as it happens. This repository is **also a GitHub Action**, which
runs the same review over a **pull request's diff** and posts what it finds as review comments. It
covers the changes the plugin never sees: work from a machine without the plugin installed, code a
person wrote by hand, and a checkout that is not a git repository.

```yaml
name: LeoPrevent
on: pull_request
permissions:
  contents: read
  pull-requests: write        # without this the review runs and posts nothing
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0      # required: the default shallow clone has no base to compare against
      - uses: leotrace-hq/leoprevent-plugin@v0.0.0
        with:
          license-key: ${{ secrets.LEOPREVENT_LICENSE_KEY }}
```

Replace `@v0.0.0` with a release tag or a commit sha. Pinning matters: this repository is replaced
in full on every release, so a floating ref moves under you.

Four things to know:

- **It is advisory.** It never blocks a merge and never fails the job unless you set
  `fail-on-findings: true`. Please don't make it a required check: a false positive that stops a
  merge queue costs your whole team, and comments cost nobody anything.
- **Nothing is attributed to an author.** A branch's added lines can be several people's work over
  several days, so every finding is raised for the reviewers to decide on. Nothing is framed as
  something you introduced, and nothing is fixed for you.
- **It needs a CI license key**, which is not one of your developers' keys. It holds no seat and
  belongs to no person. Ask us for one, and store it as a repository or organisation **secret**.
- **A shallow checkout cannot be reviewed.** `fetch-depth: 0` is the whole fix, and the review will
  tell you so on the pull request if you forget it.

Inputs: `license-key` (required), `base`, `fail-on-findings`, `working-directory`, `github-token`.

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


## Browser login

Run `leoprevent-plugin login` after installation, or run the installed plugin's
`bin/leoprevent-plugin login` directly if it is not on PATH. Windows uses
`bin\leoprevent-plugin.exe login`. Claude Code also exposes `/leoprevent:login`.

For Codex on macOS or Linux, use the full installed path because the binary may not be on PATH:

```bash
~/.codex/plugins/cache/leotrace/leoprevent/<version>/bin/leoprevent-plugin login
```

Replace `<version>` with the installed version; use your configured Codex home if it differs.
Keep the command running until it prints **Connected to LeoPrevent.**

Sign in at the displayed URL, check the email and account,
and choose **Link installation**. For a remote terminal, use `leoprevent-plugin login --no-browser` and
open the URL on another device. No persistent key needs to be copied. Failed login
preserves the saved credential and successful login preserves other installations.

The credential survives plugin updates. Environment-provided `LEOPREVENT_LICENSE_KEY`
still overrides it, and the command warns when this applies. Authentication success
only verifies your credential: approve the hooks and start a new agent session.
Use `doctor` when provided by your installed version to verify protection. The existing
`set-license` path remains available, including for local-tier licenses.

Successful login says **Connected to LeoPrevent.** Local macOS sessions return to the
initiating Claude Desktop, Codex Desktop, VS Code, Terminal, or iTerm2 app when identified.
Remote/headless and other platforms use the text confirmation. For cloud sessions, allow
`prevent.leotrace.io` as well as `api.leotrace.io`, then run login in the coding session.
Repeat login if the remote filesystem is recreated.
