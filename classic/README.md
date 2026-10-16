# HeartbeatGuard Classic (archived)

**Status: archived and unsupported.** Frozen 2026-10-16 at tag
[`classic-v1.6.0`](https://github.com/Monomoy-Strategies/heartbeat-guard/tree/classic-v1.6.0).

## What this was

HeartbeatGuard Classic was a security monitor for AI agents running on OpenClaw.
It ran 35 checks on the machine an agent lived on: firewall, open ports, SSL
certificates, failed logins, suspicious processes, file tampering, leaked
credentials, risky skill code, and a long list of OpenClaw-specific problems as
each OpenClaw release found them. It had a command-line tool (`heartbeat-guard`),
a daily report, and a small live web dashboard.

The full original README, with the list of all 35 checks, is kept here as
[`README-v1.6.0.md`](README-v1.6.0.md). The release history is in
[`CHANGELOG.md`](CHANGELOG.md).

## Why it is archived

HeartbeatGuard has changed direction. It is now the **Personal Heartbeat**: a
folder of plain-text files on your own computer that holds how you write, how
you work, and what you expect from an AI, so you never re-teach an AI who you
are. Read about it in the [root README](../README.md) or at
[heartbeatguard.com](https://heartbeatguard.com).

The Classic monitor is not part of that. It is kept here so nothing is lost and
so anyone who relied on it can still read and run the code.

## What "archived and unsupported" means

- No new checks, fixes, or releases. The code is as it was.
- Issues and pull requests about Classic will be closed with a pointer to this page.
- The MIT licence still applies. Fork it if you want to carry it on.

## About installing it

**This package was never published to PyPI.** The old README said
`pip install heartbeat-guard`; that line was wrong and never worked. The only
way it was ever installed was as an editable install from a local clone:

```bash
git clone https://github.com/Monomoy-Strategies/heartbeat-guard.git
cd heartbeat-guard/classic
pip install -e .
```

That still works if you need it, but you are on your own. Nothing here is
maintained.

## Thank you

To everyone who ran Classic, reported a problem, or sent a fix: thank you. It
did its job while OpenClaw was new and agents needed a watchdog. The name moves
on to something more personal.

— Monomoy Strategies
