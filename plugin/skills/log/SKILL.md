---
name: log
description: Show the guard's deny and ask decisions on this machine over the last 30 days, grouped by reason.
disable-model-invocation: true
allowed-tools: Bash("${CLAUDE_PLUGIN_DATA}/current/bdxguard.exe" log)
---

Boxdawn guard keeps a record on this machine of each command one of its rules denied or asked about. Show it to the person.

Run this with the Bash tool (or PowerShell, with `&` in front), with the path in double quotes exactly as written, and nothing else on the line:

`"${CLAUDE_PLUGIN_DATA}/current/bdxguard.exe" log`

Show the person what it printed, in their language: first the reasons that came up most and what each one is about, then the latest decisions. If they asked something about it ($ARGUMENTS), answer that from the record. Do not guess which command a line was: the record keeps no command, path or reason text, only when, which tool, the decision, the guard's rule names and where each target sat (inside the project, outside it, ...). Say so if they ask for the command.

Last, show the indented lines under "To share" exactly as printed, in a code block, not translated, and the link printed above them. Say in their language that if a deny or ask got in the way for nothing, they can paste that block into the linked GitHub issue, which is public, and that nothing is sent unless they do. Do not post it or open the link yourself.

If it says nothing was recorded, say so plainly: the record is on by default and is turned off with `judgment_log` in `/plugin`; Read and Grep decisions are not in it.
