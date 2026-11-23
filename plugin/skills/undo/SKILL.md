---
name: undo
description: Show the guard's snapshots of this project and put one back, to bring back files an earlier command deleted or changed.
disable-model-invocation: true
allowed-tools: Bash("${CLAUDE_PLUGIN_DATA}/current/bdxguard.exe" undo list *)
---

Boxdawn guard keeps a snapshot of the project's files before each Bash or PowerShell command. Help the person bring files back from one.

The guard's program is `${CLAUDE_PLUGIN_DATA}/current/bdxguard.exe` (the same name on every system). Run it with the Bash tool (or PowerShell, with `&` in front), with the path in double quotes exactly as written here, and give it the folder Claude Code was started in as the last word, in double quotes. Run nothing else on the same line.

1. List the snapshots:
   `"${CLAUDE_PLUGIN_DATA}/current/bdxguard.exe" undo list "<project folder>"`
   Each numbered row is the project as it was just before the command shown on it. `NO SNAPSHOT` rows are commands that ran without one. Show the person the rows that matter, in their language, and say which one you would pick and why. If they named what they lost ($ARGUMENTS), pick the row just before the command that lost it.
2. Ask the person which number to go back to. Do not restore before they answer.
3. Restore it:
   `"${CLAUDE_PLUGIN_DATA}/current/bdxguard.exe" undo restore <n> "<project folder>"`
   The guard asks the person to approve this line; that is expected. If it is refused instead (a mode that does not ask), do not write the line another way: give the person the line to run themselves, with `!` in front. Report what the command printed, in their language. Going back takes a snapshot of the state just before it, so a restore can itself be undone with the number it prints.

If the list says there are no snapshots, or the program is not there, say so plainly. Snapshots are on by default and are turned off with `undo` in `/plugin`; they cover files inside the project folder only, not its .git folder, node_modules and similar folders, files over 50 MB, databases or anything outside the folder.
