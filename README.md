# Boxdawn guard

Judges a shell command before an AI agent runs it: **deny**, **ask**, or no decision. It never says allow — no decision leaves the call to the user's own permission settings.

Today it runs as a Claude Code `PreToolUse` hook on Bash calls (`boxdawn_guard/command_hook.py`).

License: [FSL-1.1-ALv2](LICENSE.md).
