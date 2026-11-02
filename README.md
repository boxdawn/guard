<div align="center">
  <img src="https://avatars.githubusercontent.com/u/317308737?s=160&v=4" width="80" alt="Boxdawn" />
  <h1>Boxdawn guard</h1>
  <p><strong>Stops dangerous commands before Claude Code runs them.</strong></p>
  <p>
    <a href="https://github.com/boxdawn/guard/releases/latest"><img src="https://img.shields.io/github/v/release/boxdawn/guard?label=release" alt="Latest release" /></a>
    <a href="LICENSE.md"><img src="https://img.shields.io/badge/license-FSL--1.1--ALv2-blue" alt="License: FSL-1.1-ALv2" /></a>
    <img src="https://img.shields.io/badge/platforms-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey" alt="Windows, macOS, Linux" />
  </p>
  <p>
    <a href="https://boxdawn.com">Website</a> ·
    <a href="#install">Install</a> ·
    <a href="https://boxdawn.com/privacy">Privacy</a> ·
    <a href="https://github.com/boxdawn/guard/issues">Report a bug</a>
  </p>
</div>

---

Boxdawn guard is a Claude Code plugin that judges every Bash and PowerShell command before it runs. A command that would wipe a directory outside your project, force-push over shared history, drop a database or destroy cloud resources is **denied** or **held for your approval**. Everything else passes to Claude Code's own permission settings, untouched. The guard never says allow.

## Install

```
claude plugin marketplace add boxdawn/guard
claude plugin install boxdawn-guard@boxdawn
```

The plugin carries builds for Windows x64, macOS (Apple silicon and Intel) and Linux (x64 and ARM64). The first session start puts the one for your machine in the plugin's data folder.

## What it does

- **Deny or ask, never allow.** `deny` stops the command with the reason. `ask` shows Claude Code's own "run this?" prompt. No decision leaves the call to your permission settings.
- **Reads the command the way the shell does.** Bash is parsed into a syntax tree (tree-sitter), so quoting, escapes, variables and `bash -c '…'` don't hide the real command. PowerShell is read by PowerShell's own parser on Windows.
- **Knows where the target is.** Deleting a build folder inside your project is ordinary; the same command aimed at your home directory, a system path or a disk device is not.
- **Unattended means stricter.** When nobody can answer a prompt (`bypassPermissions`, `dontAsk`), an `ask` becomes a `deny`.
- **Fails closed.** If the guard itself cannot run, the command is blocked, not waved through.

Covered today: `rm`, `find -delete`, `dd`, `truncate`, `chmod -R`, `sed -i`, redirects onto files outside the project, `git` (force push, `reset --hard`, `clean`, branch delete, history rewrite), database clients (`DROP`, `TRUNCATE`, `DELETE` without `WHERE`), `terraform destroy`, `kubectl delete`, `helm uninstall`, `aws s3 rm/rb` and other cloud deletes, `docker prune`, privilege escalation and code piped into an interpreter. The full list is the fixed rules in [`boxdawn_guard/command_rules_source.py`](boxdawn_guard/command_rules_source.py).

## Rules

The fixed rules ship inside the plugin and anyone can read them. **Without an API key the guard opens no network connection.**

With a Boxdawn API key on a paid plan, set in the plugin's settings (`/plugin configure boxdawn-guard@boxdawn`), the guard fetches signed rules from Boxdawn in the background at session start and uses them in place of the fixed ones. The request carries the key only, never a command. Each bundle is signed (Ed25519) and valid for 7 days; a bundle that is missing, expired or fails its signature check means the fixed rules.

## Block record

On a paid plan, each deny or ask judged on the signed rules is appended as one line to `log/blocks-YYYYMMDD.jsonl` in the plugin's data folder ([`boxdawn_guard/block_log.py`](boxdawn_guard/block_log.py)). A line holds the tool, the decision, the rule ids and where the target sits (inside the project, outside it, …), never the command or a path. Files older than 30 days are deleted at the next Bash or PowerShell call. At session start, right after the signed rules are fetched, the lines are sent to Boxdawn for your team's view and then deleted from your machine ([`boxdawn_guard/block_send.py`](boxdawn_guard/block_send.py)); the request carries the key and those lines only. To keep the record on this machine instead, turn on `keep_blocks_local` in the plugin's settings. Without a key, or on the fixed rules, nothing is recorded or sent.

## Tested

Every release runs real Claude Code sessions against the installed plugin on all five platforms before it is published: ordinary commands run, dangerous ones are denied or held, unattended mode denies, and a session without a key leaves no record. The binary on each platform must give byte-identical decisions to the Python source.

## Privacy

What the guard sends, keeps and deletes: [boxdawn.com/privacy](https://boxdawn.com/privacy).

## License

[FSL-1.1-ALv2](LICENSE.md). Source-available; each version becomes Apache 2.0 two years after its release.

Built by [Boxdawn](https://boxdawn.com).
