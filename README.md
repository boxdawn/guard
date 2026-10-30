# Boxdawn guard

Judges a shell command before an AI agent runs it: **deny**, **ask**, or no decision. It never says allow — no decision leaves the call to the user's own permission settings.

Today it runs as a Claude Code `PreToolUse` hook on Bash and PowerShell calls (`boxdawn_guard/command_hook.py`). PowerShell commands are read by PowerShell's own parser (`packaging/psparse`, Windows only); elsewhere, where the PowerShell tool is opt-in, they get no decision.

License: [FSL-1.1-ALv2](LICENSE.md).
