# Boxdawn guard

Judges a shell command before an AI agent runs it: **deny**, **ask**, or no decision. It never says allow — no decision leaves the call to the user's own permission settings.

Today it runs as a Claude Code `PreToolUse` hook on Bash and PowerShell calls (`boxdawn_guard/command_hook.py`). PowerShell commands are read by PowerShell's own parser (`packaging/psparse`, Windows only); elsewhere, where the PowerShell tool is opt-in, they get no decision.

Rules: the fixed rules in `boxdawn_guard/command_rules_source.py`, which anyone can read. With a Boxdawn API key set in the plugin's settings (`/plugin configure boxdawn-guard@boxdawn`), the guard fetches signed rules from Boxdawn in the background at session start and uses them in place of the fixed ones. The request carries the key only, no commands. Each bundle is valid for 7 days. A bundle that is missing, expired or fails its signature check means the fixed rules. Without a key the guard opens no network connection.

## Install

In a terminal:

```
claude plugin marketplace add boxdawn/guard
claude plugin install boxdawn-guard@boxdawn
```

The plugin carries builds for Windows x64, macOS (Apple silicon and Intel) and Linux (x64 and ARM64); the first session start puts the one for your machine in the plugin's data folder.

## Block record

With a Boxdawn API key on a paid plan, each deny or ask decision judged on the signed rules is appended as one line to `log/blocks-YYYYMMDD.jsonl` in the plugin's data folder (`boxdawn_guard/block_log.py`). A line holds the tool, the decision, the rule ids and where the target sits (inside the project, outside it, …), never the command or a path. Files older than 30 days are deleted at the next Bash or PowerShell call. The record stays on your machine; the guard sends it nowhere. Without a key, or on the fixed rules, nothing is recorded.

Privacy: [boxdawn.com/privacy](https://boxdawn.com/privacy).

License: [FSL-1.1-ALv2](LICENSE.md).
