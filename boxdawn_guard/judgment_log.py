"""A record of the guard's deny and ask decisions that stays on this machine.

On every plan unless `judgment_log` is turned off in the plugin's settings.
One JSON line per deny or ask, never for a call let through. As in
`block_log`, every value is from a closed set or a number: the command, its
paths and the reason sentences (which quote the command) have no place in a
line. Nothing here opens a connection, and `block_send` never reads this
folder: it is not the paid plan's record.

Day files under `${CLAUDE_PLUGIN_DATA}/judged/`; files older than KEEP_DAYS go
at the next Bash or PowerShell call, with the record on or off. Writing never
raises: a failed write must not change a decision, and with `onFailure: block`
a crashing hook blocks every command. `bdxguard log` prints it, by reason.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from collections import Counter
from pathlib import Path

from boxdawn_guard.block_log import _BUILD_ID, LEVELS, TOOLS, _build_id, _open_append
from boxdawn_guard.command_guard import CUSTOM_RULE_ID, TARGETS, Verdict, rule_id_ok

LOG_VERSION = 1
LOG_DIR = "judged"
KEEP_DAYS = 30
DAY_FILE = re.compile(r"(\d{8})\.jsonl")
_KEYS = frozenset({"v", "t", "tool", "decision", "escalated", "findings", "build"})
_LAST = 20
ISSUE_URL = "https://github.com/boxdawn/guard/issues/new?template=needless-ask.yml"

# What each rule is about, with no word of any command in it.
RULES = {
    "guard.crashed": "the guard could not read the command",
    "parse.too_deep": "commands nested too deep to read",
    "parse.unreadable": "shell syntax the guard could not read",
    "name.runtime": "the command's name is known only when it runs",
    "code.inline_unknown_language": "inline code in a language the guard has no rules for",
    "code.inline_risky": "inline code that deletes files, runs programs or rewrites data",
    "code.runtime": "code known only when it runs",
    "code.stdin_runtime": "text known only when it runs is fed in as code",
    "privilege.elevated": "a command run with more rights (sudo and the like)",
    "privilege.su_runtime": "su -c with text known only when it runs",
    "eval.runtime": "eval with text known only when it runs",
    "source.script": "a script file run in the same shell",
    "destroy.by_design": "a command that destroys data by design",
    "pipe.into_interpreter": "another command's output run as code",
    "redirect.runtime": "output written to a path known only when it runs",
    "redirect.disk_device": "output written over a disk device",
    "redirect.outside": "output written outside the project",
    "rm.runtime": "rm with a target known only when it runs",
    "rm.outside": "rm reaching outside the project",
    "rm.project_root": "rm removing the whole project folder",
    "rm.history": "rm removing something no build makes again (history, worktrees)",
    "rm.filtered_recurse": "Remove-Item -Recurse with -Include or -Exclude",
    "find.delete_outside": "find -delete outside the project",
    "find.delete": "find -delete removing files in bulk",
    "dd.runtime": "dd with an operand known only when it runs",
    "dd.disk_device": "dd writing over a disk device",
    "dd.outside": "dd writing outside the project",
    "dd.overwrite": "dd overwriting a file",
    "truncate.outside": "truncate emptying a file outside the project",
    "truncate.file": "truncate emptying a file",
    "chmod.recursive_outside": "a recursive permission change outside the project",
    "sed.outside": "sed -i editing a file outside the project",
    "cp.outside": "a copy writing over files outside the project",
    "mv.outside": "mv writing over files outside the project",
    "tar.outside": "tar writing over files outside the project",
    "unzip.outside": "unzip writing over files outside the project",
    "rsync.outside": "rsync taking files away outside the project",
    "rsync.delete": "rsync --delete removing files on another machine",
    "new_item.force_outside": "New-Item -Force replacing something outside the project",
    "dotnet.outside": "a .NET call changing files outside the project",
    "mirror.delete": "robocopy /MIR deleting files",
    "link.same_command": "a path through a link the same command makes",
    "git.runtime": "a git subcommand known only when it runs",
    "git.push_force": "git push --force",
    "git.push_force_with_lease": "git push --force-with-lease",
    "git.push_delete": "git push deleting or mirroring remote refs",
    "git.reset_hard": "git reset --hard",
    "git.clean": "git clean -f",
    "git.branch_delete": "git branch -D",
    "git.rewrite_history": "a git command rewriting history",
    "git.discard_changes": "a git command overwriting uncommitted changes",
    "git.stash_drop": "git stash drop or clear",
    "git.stash": "git stash writing a stash over the files",
    "git.alias": "a git alias set to run a risky command",
    "git.config_command": "git config setting a command for git to run",
    "gh.delete": "gh repo delete",
    "db.destructive": "a destructive database statement",
    "db.runtime": "a database statement known only when it runs",
    "db.file": "database statements run from a file",
    "db.reset": "a database reset or drop",
    "iac.destroy": "infrastructure destroyed (terraform destroy and the like)",
    "iac.auto_approve": "infrastructure changed with -auto-approve",
    "k8s.delete": "kubectl delete",
    "helm.uninstall": "helm uninstall",
    "s3.rm": "aws s3 rm",
    "s3.rb": "aws s3 rb",
    "cloud.delete": "cloud resources deleted",
    "docker.prune": "docker prune removing data",
    "remote.run": "a risky command run in a container or on another machine",
    "fetch.then_run": "something downloaded and run by the same command",
    "script.refused": "a script that runs a command the guard would refuse",
    "secret.read": "a secret file read",
    "secret.send": "a secret file sent out",
    "device.app_data": "adb uninstall removing an app and its data",
    "device.wipe": "fastboot -w wiping a device",
    "device.flash": "fastboot overwriting a device partition",
    "wsl.unregister": "wsl --unregister deleting a distro",
}


def enabled() -> bool:
    """On unless the user turned it off; Claude Code gives a hook no variable for an
    option the user never set (see `undo.enabled`)."""
    return (os.environ.get("CLAUDE_PLUGIN_OPTION_JUDGMENT_LOG") or "").lower() not in ("false", "0", "no")


def entry(verdict: Verdict, *, tool: str, build: str | None, now: float) -> dict | None:
    """The line for this verdict, or None when there is nothing to record or
    any value falls outside its closed set."""
    if verdict.decision not in LEVELS or tool not in TOOLS:
        return None
    findings = []
    for f in verdict.findings:
        if not rule_id_ok(f.rule) or f.level not in LEVELS or not (f.target is None or f.target in TARGETS):
            return None
        findings.append({"rule": f.rule, "level": f.level, "target": f.target})
    return {"v": LOG_VERSION, "t": int(now), "tool": tool, "decision": verdict.decision,
            "escalated": bool(verdict.escalated), "findings": findings, "build": build}


def record(data_dir: str | None, verdict: Verdict | None, *, tool: str, now: float | None = None) -> bool:
    """Append this verdict's line; True when one was written. Never raises."""
    try:
        if not data_dir or verdict is None or not enabled():
            return False
        now = time.time() if now is None else now
        line = entry(verdict, tool=tool, build=_build_id(data_dir), now=now)
        if line is None:
            return False
        folder = Path(data_dir) / LOG_DIR
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / f"{time.strftime('%Y%m%d', time.gmtime(now))}.jsonl"
        raw = (json.dumps(line, separators=(",", ":")) + "\n").encode("ascii")
        fd = _open_append(path)
        try:
            return os.write(fd, raw) == len(raw)
        finally:
            os.close(fd)
    except Exception:  # noqa: BLE001 - see the module docstring
        return False


def prune(data_dir: str | None, *, now: float | None = None) -> None:
    """Delete day files older than KEEP_DAYS. Never raises."""
    try:
        if not data_dir:
            return
        folder = Path(data_dir) / LOG_DIR
        if not folder.is_dir():
            return
        now = time.time() if now is None else now
        cutoff = time.strftime("%Y%m%d", time.gmtime(now - KEEP_DAYS * 86400))
        for p in folder.iterdir():
            m = DAY_FILE.fullmatch(p.name)
            if m and m.group(1) < cutoff:
                p.unlink(missing_ok=True)
    except Exception:  # noqa: BLE001 - see the module docstring
        pass


def _closed(value, allowed) -> bool:
    return isinstance(value, str) and value in allowed


def _line_ok(line) -> bool:
    """Exactly what `entry` writes: a line changed by hand is not shown, so nothing but the
    guard's own values reaches the person (or the model, through the skill)."""
    if not isinstance(line, dict) or set(line) != _KEYS or not isinstance(line["findings"], list)             or not line["findings"]:
        return False
    return (type(line["t"]) is int and 0 <= line["t"] < 2**32 and _closed(line["tool"], TOOLS)
            and _closed(line["decision"], LEVELS) and type(line["escalated"]) is bool
            and all(isinstance(f, dict) and set(f) == {"rule", "level", "target"}
                    and isinstance(f["rule"], str) and rule_id_ok(f["rule"]) and _closed(f["level"], LEVELS)
                    and (f["target"] is None or _closed(f["target"], TARGETS))
                    for f in line["findings"]))


def read(data_dir: str | None, *, now: float | None = None) -> list[dict]:
    """Every good line of the last KEEP_DAYS days, oldest first. Lines that are not the
    guard's own are skipped."""
    since = (time.time() if now is None else now) - KEEP_DAYS * 86400
    folder = Path(data_dir) / LOG_DIR if data_dir else None
    if folder is None or not folder.is_dir():
        return []
    lines = []
    for p in sorted(folder.iterdir()):
        if not DAY_FILE.fullmatch(p.name):
            continue
        try:
            text = p.read_text(encoding="ascii", errors="replace")
        except OSError:
            continue
        for raw in text.splitlines():
            try:
                line = json.loads(raw)
            except (ValueError, RecursionError):
                continue
            if _line_ok(line) and line["t"] >= since:
                lines.append(line)
    return sorted(lines, key=lambda line: line["t"])


def _about(rule: str) -> str:
    if CUSTOM_RULE_ID.fullmatch(rule):
        return "one of your own rules"
    return RULES.get(rule, "")


def _when(t: int) -> str:
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(t))


def show(data_dir: str | None) -> str:
    lines = read(data_dir)
    if not lines:
        return ("Boxdawn guard: no deny or ask decisions recorded on this machine in the last "
                f"{KEEP_DAYS} days (or the record is turned off with `judgment_log` in /plugin).\n")
    counts: Counter = Counter()
    last: dict = {}
    for line in lines:
        for rule, level in {(f["rule"], f["level"]) for f in line["findings"]}:
            counts[(rule, level)] += 1
            last[(rule, level)] = line["t"]
    out = [f"Boxdawn guard: {len(lines)} deny and ask decisions on this machine, last {KEEP_DAYS} days.",
           "No command or path is kept: only when, which tool, the decision and the guard's rules.", "",
           "By reason (a decision with several reasons counts under each):"]
    width = max(len(rule) for rule, _ in counts)
    for (rule, level), n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])):
        out.append(f"  {n:>5}  {level:<4}  {rule:<{width}}  {_about(rule)}  (last {_when(last[(rule, level)])})")
    out += ["", f"Last {min(_LAST, len(lines))}:"]
    for line in lines[-_LAST:]:
        rules = ", ".join(dict.fromkeys(f["rule"] for f in line["findings"])) or "-"
        unattended = "  (nobody there to approve)" if line["escalated"] else ""
        out.append(f"  {_when(line['t'])}  {line['decision']:<4}  {line['tool']:<10}  {rules}{unattended}")
    out += ["", *_share(lines)]
    return "\n".join(out) + "\n"


def _share(lines: list[dict]) -> list[str]:
    """The counts by reason with no time in them and an org's own rules unnamed, for the
    person to paste into an issue if they choose. Nothing is sent from here."""
    counts: Counter = Counter()
    targets: dict = {}
    for line in lines:  # each count is of decisions, the targets' too
        keys, seen = set(), set()
        for f in line["findings"]:
            key = ("custom" if CUSTOM_RULE_ID.fullmatch(f["rule"]) else f["rule"], f["level"])
            keys.add(key)
            targets.setdefault(key, Counter())
            if f["target"] is not None:
                seen.add((key, f["target"]))
        counts.update(keys)
        for key, target in seen:
            targets[key][target] += 1
    build = next((line["build"][:7] for line in reversed(lines)
                  if isinstance(line["build"], str) and _BUILD_ID.fullmatch(line["build"])), "unknown")
    width = max(len(rule) for rule, _ in counts)
    out = ["To share: did the guard deny or ask when it need not have? Paste the indented lines into",
           ISSUE_URL,
           "They have no command, path or time in them. Nothing is sent unless you paste them.",
           "Each count is of decisions; after it, how many of them had a target in each place.",
           f"  guard {build}, last {KEEP_DAYS} days, {len(lines)} decisions"]
    for (rule, level), n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])):
        where = ", ".join(f"{t} {c}" for t, c in sorted(targets[(rule, level)].items()))
        out.append(f"  {level:<4}  {rule:<{width}}  {n:>5}  {where}".rstrip())
    return out


def _cli(argv: list[str]) -> int:
    if argv != ["log"]:
        print("usage: bdxguard log", file=sys.stderr)
        return 2
    data_dir = os.environ.get("CLAUDE_PLUGIN_DATA")
    if not data_dir and getattr(sys, "frozen", False):  # <data>/current/bdxguard.exe
        data_dir = os.path.dirname(os.path.dirname(os.path.abspath(sys.executable)))
    prune(data_dir)
    sys.stdout.write(show(data_dir))
    return 0
