# Security Policy

## Reporting a vulnerability

Please report security issues privately to **info@leotrace.io**.

Do not open a public issue for a security report.

Include whatever you have — what you found, how to reproduce it, and the version
(`plugin/VERSION`, or the `client_version` in your plugin log). A short note with a rough
reproduction is more useful to us than a polished report you never send.

We will acknowledge your report and keep you updated on the fix. If you would like credit
for the finding, say so and we will include it.

## Scope

This policy covers the LeoPrevent **client** in this repository: the hook binary that runs
on a developer's machine, decides which changed files to send for review, and talks to the
LeoTrace API.

Especially relevant here:

- anything that causes the client to send data it should not (the client deliberately
  drops secret files and skips symlinks before a review — a bypass of those guards is a
  security issue)
- anything that lets a repository under review influence the client's behaviour
- local privilege or file-handling issues in the hook, the per-session scratch files, or
  the license-key storage

Testing the client on your own machine, against your own repositories, is welcome — that
is what the source is published for.

## Please do not test our hosted services

The LeoTrace API and our dashboards are **out of scope**, and we do not authorize security
testing against them. Please do not scan, probe, fuzz, or attempt to access data that is
not your own.

If you notice something about the service in the course of using the plugin normally, tell
us at the address above — we would much rather hear it than not. That is different from
going looking.

## Not in scope

The client is designed to **fail open**: if the server is unreachable, the license key is
missing, or the review errors, the hook logs and exits without blocking the developer.
That is deliberate — a broken hook must never trap someone mid-turn — so "the review did
not run" is not by itself a vulnerability. A way to *silently* suppress a review that
should have run is one, and we would like to hear about it.
