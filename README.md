<div align="center">
  <img src="https://avatars.githubusercontent.com/u/317308737?s=160&v=4" width="80" alt="Boxdawn" />
  <h1>Boxdawn guard</h1>
  <p><strong>Checks the Bash and PowerShell commands Claude Code and GitHub Copilot CLI run, before they run: denies or asks with the reason, or leaves no decision.</strong></p>
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

Boxdawn guard is a Claude Code plugin that judges every Bash and PowerShell command before it runs. A command that would wipe a directory outside your project, force-push over shared history, drop a database or destroy cloud resources is **denied** or **held for your approval**. Everything else goes to Claude Code's own permission settings. The guard never says allow. And when a command does delete or break files in your project, you can [bring them back](#bring-back-files).

## Install

```
claude plugin marketplace add boxdawn/guard
claude plugin install boxdawn-guard@boxdawn
```

The plugin carries builds for Windows x64, macOS (Apple silicon and Intel) and Linux (x64 and ARM64). The first session start puts the one for your machine in the plugin's data folder.

Start a new Claude Code session after installing: a session that was already open does not pick up the guard. After uninstalling or reinstalling, restart any session that was open; until then its Bash and PowerShell calls are blocked, because the guard blocks a command whenever it cannot run.

### GitHub Copilot CLI

```
copilot plugin marketplace add boxdawn/guard
copilot plugin install boxdawn-guard@boxdawn
```

The same rules judge the commands Copilot runs with its `powershell` and `bash` tools: deny or ask with the reason, or no decision. Typing into a shell that is already running (`write_powershell`, `write_bash`) always asks. Other tools, Copilot's own file viewing and search among them, get no decision, and a recursive `grep` gets no `--exclude` flags. This edition has no settings and takes no snapshots: it uses the fixed rules, with messages in English, or in Korean on a Korean system (Korean has not been run under Copilot yet).

When the guard fails, Copilot refuses the command. When a hook runs past Copilot's time limit, Copilot lets the command through, so the guard refuses on its own after 10 seconds. Tested with Copilot CLI 1.0.106 on Windows; the macOS and Linux builds are the same as the Claude Code plugin's but have not been run under Copilot.

## Bring back files

In Claude Code, before each Bash or PowerShell command, the guard saves a copy of the files in your project folder, `.env` and other ignored files too, on your machine. When a command deletes or breaks files there, type:

```
/boxdawn-guard:undo
```

Claude lists the copies, one before each command, and puts back the one you pick after you approve it. Putting a copy back saves the current state first, so it can be undone too.

- **On unless you turn it off**: `undo` in `/plugin`. Nothing is sent anywhere.
- **What it costs.** Each command waits for its copy: under a second in the projects we measured (0.3 s in a 57 MB copy, 0.75 s in a 632 MB one), never more than about 4 seconds. A project with tens of thousands of folders takes about 3.5 seconds on every command and its copies are often not ready in time. Copies take disk space in the plugin's data folder: when a session opens a project, its copies older than 7 days are dropped, and its oldest while they take more than 2 GB; at every session start, all copies of a project with no new copy for 30 days are removed, with snapshots on or off.
- **Only the project folder.** Not saved: the project's `.git` folder (commits, branches, stashes), `node_modules` and similar folders, build output your git ignores (`target`, `build`, `dist`, `out`, `bin`, `obj`), repositories inside the project, files over 50 MB, databases, cloud resources and anything outside the folder. A session opened in your home folder, a drive, or Desktop, Documents, Downloads or OneDrive itself takes no copies; a project folder inside them does.
- **A large project starts unprotected.** The first copy is taken when a session starts (82 seconds for the 632 MB project above); a command that runs before it is ready has no copy, and the list says so.
- **For an agent's mistakes, not an agent working against you.** The agent can read the copies, `.env` included, and a command that reaches the plugin's data folder can spoil them.
- **The guard's decisions stay the same.** Only if you turn `undo` on yourself in `/plugin` does a `git reset --hard`, `git checkout -- .`, `git restore .` or `git stash` that only rewrites the project's own files go on without asking, because the copy taken before it can bring the files back.

The setting's description in `/plugin` lists every limit.

## What it does

- **Deny or ask, never allow.** `deny` refuses the command and gives the reason. `ask` shows Claude Code's own "run this?" prompt. No decision is not an approval: the decision goes to your own permission settings, as it would without the guard.
- **Reads the command the way the shell does.** Bash is parsed into a syntax tree (tree-sitter), so quoting, escapes, variables and `bash -c '…'` don't hide the real command. PowerShell is read by PowerShell's own parser on Windows.
- **Knows where the target is.** Deleting a build folder inside your project is ordinary; the same command aimed at your home directory, a system path or a disk device is not.
- **Unattended means stricter.** When nobody can answer a prompt (`bypassPermissions`, `dontAsk`), an `ask` becomes a `deny`.
- **Fails closed.** If the guard itself cannot run, the command is blocked, not waved through. The check on the `Read` and `Grep` tools is the one exception: a broken guard does not stop a session from opening files.

Covered today: `rm`, `find -delete`, `dd`, `truncate`, `chmod -R`, `sed -i`, redirects, `tee`, `install`, `tar -C`, `unzip -d` and `rsync` onto paths outside the project, `rsync --delete` there, `Rename-Item` and .NET file calls (`[IO.File]::Delete`) in PowerShell, `git` (force push, `reset --hard`, `clean`, branch delete, history rewrite, `checkout -- .` and `restore .`, `stash drop`, `rm -r .`), `rm -r` of a `.git` folder or `.claude/worktrees`, database clients (`DROP`, `TRUNCATE`, `DELETE` without `WHERE`, given on the command line or on stdin as in `psql <<< '…'`), tools that reset a database (`prisma migrate reset`, `artisan migrate:fresh`, `supabase db reset`, `alembic downgrade base` and the like), `terraform destroy` and `apply -auto-approve`, `kubectl delete`, `helm uninstall`, `aws s3 rm/rb` and other cloud deletes, `gh repo delete` and `gh api` DELETE, `docker prune`, `compose down -v` and `docker rm -v`, `robocopy /MIR` and `lftp mirror --delete`, `adb` clearing an app's data or deleting on a phone and `fastboot` wiping one, privilege escalation, code piped into an interpreter and a file downloaded and run on the same line (`curl -o i.sh … && bash i.sh`). A command handed to `bash -c` (also `-lc`, `-ec`), `sudo`, `env`, `timeout`, `nohup`, `setsid`, `flock`, `watch`, `script -c`, `tmux new`, `screen`, `wsl` and the like is judged as if typed directly. A command sent with `ssh` or `docker exec` is judged too, and so is a local file handed to it on stdin (`ssh host < x.sh`); what would be denied here asks, because the guard cannot see that machine. In `docker run` with a folder of this computer mounted (`-v`, `--mount`), a path under the mount is judged as that folder. A shell script run with `bash`, `sh` or `./`, or given to a shell on stdin (`bash < x.sh`), is read, and so is a PowerShell script (`.\x.ps1`, `& .\x.ps1`, `pwsh -File x.ps1`); the line asks when the script holds a command that would be denied, and a delete of a path known only when the script runs (`rm -rf "$TMP"`) does not count. A command named through a variable set earlier on the line (`S=/c/tools; $S/python.exe x.py`) is judged as the command it names, and a `for` loop over values written out on the line (`for f in a.txt b.txt; do rm -f "$f"; done`) is judged once for each value. A git alias that runs a shell command (`git config alias.x '!…'`, `git -c alias.x=…`) is judged by that command. The full list is the fixed rules in [`boxdawn_guard/command_rules_source.py`](boxdawn_guard/command_rules_source.py).

**What it does not see.** The guard reads the command line that is about to run, not what happens behind it:

- **What a program does once it runs.** `python wipe.py`, `npm test`, `make clean` and `./gradlew clean` get no decision, whatever the file contains.
- **A command kept in another tool's settings or flags.** A git alias set earlier (`git x`), `make --eval` and `vim -c '!…'` get no decision.

**Links in a named path are followed.** A symlink or Windows junction inside the project that points outside it counts as outside, so `rm -rf link/` is denied. Removing the link itself (`rm -rf link`) gets no decision, because what it points to stays. In PowerShell, `Remove-Item link -Recurse` is denied, and `Remove-Item -Recurse` with `-Include` or `-Exclude` always asks, because it walks through links below the path. A link is read when the command is checked, so one the same command makes is not on disk yet: going through it asks when the guard recognises the link (`ln -s a b`, `New-Item -ItemType Junction`) and is not seen otherwise, including `cmd /c mklink` from Bash, a PowerShell link whose name or type is worked out at run time, and a link renamed or copied by the same command (`mv link x && rm -rf x/sub`). Also not seen: a name with `[` in it, and a link `find -exec` meets below where it starts (the start itself is followed with `-L` and `-H`). In PowerShell, a .NET call on an object (`(Get-Item x).Delete()`), after `using namespace System.IO`, or inside a string (`"$(...)"`) is not seen.

## Secret files

Reading a secret file by name asks; sending one out is denied. That covers `.env` files (not `.env.example` and the like), SSH private keys, `~/.aws/credentials`, `.netrc`, `.pypirc`, `.npmrc`, `.git-credentials`, Docker, Podman, Kubernetes and GitHub CLI credentials, Claude Code's own credentials file, and `.p12` and `.pfx` files, in Bash, PowerShell and the `Read` and `Grep` tools. Looking at the name (`ls`, `test -f`) gets no decision. The names are in [`boxdawn_guard/secret_files.py`](boxdawn_guard/secret_files.py).

This is a check on file names, not a sandbox. What it does not see:

- **A shell search that reaches the file without naming it.** `rg`, `git grep`, `find -exec grep`, `xargs grep`, `sudo grep`, `command grep`, `env grep`, `time grep`, `exec grep`, `nohup grep`, a `grep` whose flags are in a variable and a `grep` inside `bash -c` or `eval` read `.env` with no decision. So does a `grep -r` with `--include`, or one on a line that gets a decision for another reason: those run as written. Links under `grep -R` are followed. Other recursive `grep` commands in Bash get `--exclude` flags after the name, which leave out these names in lower case, `.p12` and `.pfx` in any case, and `.ssh`, `.aws`, `.docker` and `.kube` folders below where the search starts. That also leaves out ordinary files there, and names like `.env.example` and `hosts.yml`. A search that names such a file on the line runs as written, because the flags would leave that file out too. A key file with a suffix such as `id_rsa.bak` is not left out, nor are Podman's `auth.json` and `~/.dockercfg`. A search whose only match was such a file finds nothing and exits with 1. A search that starts in one of those four folders asks. Turn off `keep_secrets_out_of_grep` in the plugin's settings and no flags are added; such a search still asks. BusyBox `grep` gets no flags. Nor does a `grep` that a deny or ask rule in your settings files would catch as written but not with the flags in, such as `Bash(grep -rn:*)`: Claude Code matches its deny and ask rules to the changed command, and the rule would stop working. The files read are the managed settings file, `settings.json` in your Claude folder, and `.claude/settings.json` and `.claude/settings.local.json` in the project. Rules given on the command line (`--settings`), by an SDK caller or by a policy outside these files are not seen, and the reading of a rule is close to Claude Code's, not the same. The `Grep` tool is different too: a search over a folder leaves these names out, in any case, and one that starts in or under `.ssh` or `.aws` asks, or is denied when nobody is there to answer. A network path is not looked up, so a link reached through one is not followed. More than the secrets is left out: `.env.example`, `id_rsa.pub` and source files with such names (`id_rsa.py`, `.env.ts`), all of a `.ssh` folder, what is under a folder named like `.env.d`, and the plain names `config`, `config.json`, `hosts.yml` and `.credentials.json` when the search starts in their folder. Claude Code has that tool by default on Windows. On macOS, Linux and WSL it searches with `grep` unless the tool is turned on.
- A path put together while the code runs.
- A value already in an environment variable, or a secret in a file with an ordinary name.

## Rules

The fixed rules ship inside the plugin and anyone can read them. **Without an API key the guard opens no network connection.**

With a Boxdawn API key on a paid plan, set in the plugin's settings (`/plugin configure boxdawn-guard@boxdawn`), the guard fetches signed rules from Boxdawn in the background at session start and uses them in place of the fixed ones. The request carries the key only, never a command. Each bundle is signed (Ed25519) and valid for 7 days; a bundle that is missing, expired or fails its signature check means the fixed rules.

## Deny and ask record

On a paid plan, each deny or ask judged on the signed rules is appended as one line to `log/blocks-YYYYMMDD.jsonl` in the plugin's data folder ([`boxdawn_guard/block_log.py`](boxdawn_guard/block_log.py)). A line holds the tool, the decision, the rule ids and where the target sits (inside the project, outside it, …), never the command or a path. Files older than 30 days are deleted at the next Bash or PowerShell call. At session start, right after the signed rules are fetched, the lines are sent to Boxdawn and then deleted from your machine ([`boxdawn_guard/block_send.py`](boxdawn_guard/block_send.py)); the request carries the key and those lines only. To keep the record on this machine instead, turn on `keep_blocks_local` in the plugin's settings. Without a key, or on the fixed rules, nothing is recorded or sent. Decisions on the `Read` and `Grep` tools are not recorded.

The guard's messages are in English, or in Korean when Korean is this machine's language (on Windows the display language or the first preferred language; `LC_ALL`, `LC_MESSAGES` or `LANG` elsewhere). Set `language` to English or 한국어 in the plugin's settings to fix one. The decision is the same in both.

## Tested

Every release runs real Claude Code sessions against the installed plugin on all five platforms before it is published: ordinary commands run, dangerous ones are denied or held, unattended mode denies, and a session without a key leaves no record. The binary on each platform must give byte-identical decisions to the Python source.

## Privacy

What the guard sends, keeps and deletes: [boxdawn.com/privacy](https://boxdawn.com/privacy).

## License

[FSL-1.1-ALv2](LICENSE.md). Source-available; each version becomes Apache 2.0 two years after its release.

Built by [Boxdawn](https://boxdawn.com).
