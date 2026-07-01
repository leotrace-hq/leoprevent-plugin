---
description: Save your LeoPrevent license key (survives plugin updates)
argument-hint: <lp_live_...>
allowed-tools: Bash(leoprevent-plugin:*)
---
Save the user's LeoPrevent license key by running EXACTLY this with the Bash tool:

```
leoprevent-plugin set-license $ARGUMENTS
```

Then report only success (and the path it saved to) or the error. Do NOT echo the key
back to the user. If `$ARGUMENTS` is empty, don't run anything — tell the user the usage:
`/leoprevent:set-license <lp_live_...>`.
