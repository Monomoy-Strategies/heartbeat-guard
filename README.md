# HeartbeatGuard — your Personal Heartbeat

**Every AI wants to hold your life. Hold it yourself.**

Website: [heartbeatguard.com](https://heartbeatguard.com)

## What it is

Your Heartbeat is a folder of plain-text files on your own computer. It holds
how you write, how you like work done, what you like and don't, what you're
good at, what you expect from an AI, and (only if you choose) a few personal
facts an AI can use to get things done for you.

You load a slice of it into any AI you already use: Claude, ChatGPT, Grok,
Gemini, a personal agent. Switch tools and nothing is lost. You never re-teach
an AI who you are.

## Why

Every AI company wants to be the one that remembers you. Their memory lives on
their servers, in their format, and it does not come with you when you leave.

The Heartbeat flips that. You hold it. The AI gets a copy of what it needs,
when you say so. Nothing in the kit ever talks to a server, needs an account,
or makes a network call. Turn off Wi-Fi and it all still works.

## Who it is for

People who use two or more AIs and are tired of starting over. You do not need
to install anything, open a terminal, or edit a config file. If you can unzip a
folder, paste a prompt, and drag files into a folder, you can do this.

## The names you will see

- **Heartbeat** — the folder. Who you are, in seven short files.
- **Guard** — the red, amber and green privacy colour on every file. Green loads
  anywhere. Amber loads only when you say. Red never leaves your machine.
- **Handshake** — the paste-ready block that loads a slice of your Heartbeat
  into one AI.
- **Inbox** — the folder where you drop your own material (emails you sent,
  posts, proposals) so the AI can learn from what you already wrote.
- **Check-up** — the short update you run now and then to keep it current.

## What is in the Starter kit

The free Starter kit is a zip called `My-Heartbeat`. It lands in this repo in
`kit/` at launch. Inside:

- `READ-ME-FIRST.md` — one screen, plain English.
- `Scan-Guide.md` — what to drop in the Inbox and what each thing teaches the AI.
- `Start-My-Heartbeat.txt` — the Start prompt. Paste it into any AI and answer
  about ten questions. It writes your Heartbeat for you, with a receipt on every
  line so you can see where each rule came from.
- `Build-My-Dashboard.txt` — a prompt that has your AI build you a one-file
  dashboard for your Heartbeat. No server, no outside code.
- Seven core files: `Heartbeat.md`, `Voice.md`, `How-I-Work.md`,
  `Likes-and-Dislikes.md`, `Skills.md`, `Expectations.md`, and `red/About-Me.md`.
- `00_Inbox/`, `_slices/` (where Handshakes land), `_archive/` (old versions),
  and `example/` — a complete, filled Heartbeat for a made-up operator so you
  can see what "done" looks like before you start.

Ten minutes from download to a working Heartbeat and your first Handshake.

## Privacy, in plain words

- The kit makes no network calls. Ever.
- heartbeatguard.com never receives your Heartbeat.
- The Start prompt runs inside whichever AI you choose. That AI reads what you
  put in the Inbox, so only put green things there.
- Anything in `red/` stays on your machine. No prompt, Handshake or dashboard
  reads it.

The honest "where this can be attacked" list, and what to do about each point,
is on the Guard page at [heartbeatguard.com/guard](https://heartbeatguard.com/guard).

## The old security tool (Classic)

HeartbeatGuard used to be a security monitor for AI agents. That tool is now
archived and unsupported. The code is frozen at tag
[`classic-v1.6.0`](https://github.com/Monomoy-Strategies/heartbeat-guard/tree/classic-v1.6.0)
and lives in the [`classic/`](classic/) folder with a note on what it was. It
was never published to PyPI.

## Licence

MIT. See [LICENSE](LICENSE).

Built by [Monomoy Strategies](https://heartbeatguard.com).
