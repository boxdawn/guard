# Boxdawn guard

Judges a shell command before an AI agent runs it: **deny**, **ask**, or no decision. It never says allow — no decision leaves the call to the user's own permission settings.

Today it runs as a Claude Code `PreToolUse` hook on Bash and PowerShell calls (`boxdawn_guard/command_hook.py`). PowerShell commands are read by PowerShell's own parser (`packaging/psparse`, Windows only); elsewhere, where the PowerShell tool is opt-in, they get no decision.

Rules: the fixed rules in `boxdawn_guard/command_rules_source.py`, which anyone can read. With a Boxdawn API key set in the plugin's settings (`/plugin configure boxdawn-guard@boxdawn`), the guard fetches signed rules from Boxdawn in the background at session start and uses them in place of the fixed ones. The request carries the key only, no commands. Each bundle is valid for 7 days. A bundle that is missing, expired or fails its signature check means the fixed rules. Without a key the guard opens no network connection.

License: [FSL-1.1-ALv2](LICENSE.md).
