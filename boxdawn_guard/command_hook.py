"""Claude Code PreToolUse hook around `command_guard.evaluate` (Bash) and
`powershell_guard.evaluate_powershell` (PowerShell).

Reads the hook input on stdin and prints a decision for Bash and PowerShell calls:
`deny` or `ask` with a reason, or nothing (the normal permission flow).
Never `allow`. A `Grep` over a folder gets no decision either: its input comes
back with the secret files left out. Register it with `"onFailure": "block"` (Claude Code
v2.1.295+): a command hook that times out does not block by default.

Rules: the signed server bundle stored by `fetch-rules` when it is there
and good (`rules_bundle`), else the fixed rules in `command_rules_source`.
A deny or ask judged on the bundle is also written to the local block
record (`block_log`); on the fixed rules nothing is written.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import sys

from boxdawn_guard import block_log, messages_ko, secret_files
from boxdawn_guard.command_guard import evaluate, evaluate_file_tool
from boxdawn_guard.rules_bundle import load_stored
from boxdawn_guard.powershell_guard import evaluate_powershell


# Reading with these is no less a read, but they get no `onFailure: block`: a
# broken guard must not stop a session from opening any file.
_FILE_TOOLS = {"Read": ("file_path",), "Grep": ("path", "glob")}


def _globs(pattern: str) -> list[str]:
    """Grep's `{.env,.env.local}`: one level of braces is enough for a name list."""
    m = re.fullmatch(r"(.*)\{([^{}]*)\}(.*)", pattern)
    return [m.group(1) + part + m.group(3) for part in m.group(2).split(",")] if m else [pattern]


def _korean() -> bool:
    return os.environ.get("CLAUDE_PLUGIN_OPTION_LANGUAGE") == messages_ko.KOREAN


def _search_roots(tool_input: dict, cwd: str | None) -> tuple[str, ...]:
    """Where a `Grep` starts, as written and on disk: which of the two Claude Code
    searches from differs by system. A network path stays text: looking it up
    contacts the host, and this runs before the person is asked."""
    path = tool_input.get("path")
    path = path.strip() if isinstance(path, str) else ""  # as Claude Code reads it
    path = os.path.expanduser(path) if path else "."
    if os.name == "nt":
        path = re.sub(r"^/([a-zA-Z])(?=/|$)", r"\1:", path)
    written = re.sub(r"^[\\/]{2}[?.][\\/](?=[a-zA-Z]:)", "", os.path.abspath(os.path.join(cwd or "", path)))
    if written.replace("\\", "/").startswith(("//", "/net/")):
        return (written,)
    return written, os.path.realpath(written)


def _one_file(roots: tuple[str, ...]) -> bool:
    return len(roots) > 1 and os.path.isfile(roots[-1])


def _with_secret_folder(paths: list[str], tool_input: dict, cwd: str | None) -> list[str]:
    """`.ssh` as the session folder, a folder under it, or a link to it names nothing.
    The folder takes the place of the path that led there: one reason, not two."""
    roots = _search_roots(tool_input, cwd)
    found = None if _one_file(roots) else next(filter(None, map(secret_files.secret_folder, roots)), None)
    if found is None:
        return paths
    path = tool_input.get("path")
    return [p for p in paths if not isinstance(path, str) or p != path.strip()] + [found]


def _search_without_secrets(tool: str, tool_input: dict, cwd: str | None) -> dict | None:
    """`Grep` over a folder reads `.env` without naming it, and a window on every
    such search would be too many. No decision: the normal permission flow stays."""
    if tool != "Grep":
        return None
    roots = _search_roots(tool_input, cwd)
    if _one_file(roots):
        return None
    glob = tool_input.get("glob")
    excludes = " ".join(secret_files.search_excludes(*roots))
    if isinstance(glob, str) and glob.endswith(excludes):  # sent back as we changed it; the last glob wins
        return None
    return {"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "updatedInput": {**tool_input, "glob": f"{glob} {excludes}" if isinstance(glob, str) and glob else excludes},
        "additionalContext": messages_ko.SEARCH_NOTE if _korean() else
                             "Boxdawn guard keeps secret files such as .env out of folder searches, "
                             "so a file may be missing here. Give a file's path to search it.",
    }}


# The settings files that can hold permission rules. Rules that reach Claude Code
# another way (`--settings`, an SDK caller, a policy from the registry, MDM or a
# server) are not in these files and cannot be seen here.
_MANAGED_SETTINGS = {"win32": r"C:\Program Files\ClaudeCode\managed-settings.json",
                     "darwin": "/Library/Application Support/ClaudeCode/managed-settings.json"}.get(
    sys.platform, "/etc/claude-code/managed-settings.json")


def _settings_files(cwd: str | None) -> dict[str, str]:
    config = os.environ.get("CLAUDE_CONFIG_DIR") or os.path.join(os.path.expanduser("~"), ".claude")
    project = os.environ.get("CLAUDE_PROJECT_DIR") or cwd or ""
    files = {"managed": _MANAGED_SETTINGS, "user": os.path.join(config, "settings.json")}
    if project:
        files["project"] = os.path.join(project, ".claude", "settings.json")
        files["local"] = os.path.join(project, ".claude", "settings.local.json")
    return files


def _deny_and_ask_rules(cwd: str | None) -> list[str]:
    """What is inside `Bash(...)` in deny and ask. A file Claude Code could not read
    either, or a part of it in the wrong shape, holds no rule."""
    found = []
    for path in _settings_files(cwd).values():
        try:
            with open(path, encoding="utf-8-sig") as f:
                permissions = json.load(f).get("permissions")
        except (OSError, ValueError, AttributeError, RecursionError):
            continue
        for kind in ("deny", "ask"):
            rules = permissions.get(kind) if isinstance(permissions, dict) else None
            for rule in rules if isinstance(rules, list) else []:
                m = re.fullmatch(r"\s*Bash\((.*)\)\s*", rule, re.S) if isinstance(rule, str) else None
                if m:
                    found.append(m.group(1))
    return found


# Where one command ends and the next starts, and what goes before a command's name.
_COMMAND_ENDS = re.compile(r"&&|\|\||\$\(|[;|&\n()`{}]")
_BEFORE_NAME = re.compile(r"^(?:(?:[A-Za-z_]\w*=\S*|!|if|then|elif|else|do|while|until|time)\s+)*")


def _commands(line: str) -> list[str]:
    """The line and each command in it, with the spaces Claude Code sees, measured:
    `if grep -rn`, `! grep -rn`, `FOO=1 grep -rn`, `(grep -rn)` and `grep  -rn` all meet
    a deny rule `Bash(grep -rn:*)`. More pieces than the shell has only cost the flags."""
    words = (" ".join(p.split()) for p in [line, *_COMMAND_ENDS.split(line)])
    return [w for w in (_BEFORE_NAME.sub("", w) for w in words) if w]


def _wildcard(rule: str, command: str) -> bool:
    """`*` for anything, without a pattern that can take minutes on many stars."""
    first, *middle, last = rule.split("*")
    if len(command) < len(first) + len(last) or not (command.startswith(first) and command.endswith(last)):
        return False
    at, stop = len(first), len(command) - len(last)
    for piece in middle:
        at = command.find(piece, at, stop)
        if at < 0:
            return False
        at += len(piece)
    return True


def _rule_matches(rule: str, line: str) -> bool:
    """Close to how Claude Code reads a rule: `x:*` is `x` and any words after it,
    `*` stands for anything, else the command is the rule. A miss here only means
    the flags go in."""
    rule = " ".join(rule.split())
    if rule.endswith(":*"):
        head = rule[:-2].rstrip()
        return any(c == head or c.startswith(head + " ") for c in _commands(line))
    if "*" in rule:
        return any(_wildcard(rule, c) for c in _commands(line))
    return rule in _commands(line)


def _breaks_a_rule(command: str, changed: str, cwd: str | None) -> bool:
    """Claude Code matches its rules to the command as changed: with the flags after
    the name, a deny or ask rule like `Bash(grep -rn:*)` would no longer catch it,
    and the person's own rule would stop working. Such a rule keeps the command as written."""
    return any(_rule_matches(r, command) and not _rule_matches(r, changed) for r in _deny_and_ask_rules(cwd))


def _busybox_grep() -> bool:
    """BusyBox `grep` may refuse these flags, and a search that fails is worse than one that reads."""
    found = shutil.which("grep")
    return found is not None and os.path.basename(os.path.realpath(found)).startswith("busybox")


def _grep_without_secrets(tool_input: dict, ends: tuple[int, ...], cwd: str | None) -> dict | None:
    """`grep -r` reads `.env` without naming it. The flags go right after the name:
    any later word may be the end of the options, and later commands keep their place."""
    flags = " " + " ".join(secret_files.GREP_EXCLUDES)
    command = tool_input["command"]
    turned_off = (os.environ.get("CLAUDE_PLUGIN_OPTION_KEEP_SECRETS_OUT_OF_GREP") or "").lower() in ("false", "0", "no")
    if not ends or turned_off or _busybox_grep():
        return None
    line = command.encode("utf-8")
    for end in reversed(ends):
        line = line[:end] + flags.encode() + line[end:]
    if _breaks_a_rule(command, line.decode("utf-8"), cwd):
        return None
    return {"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "updatedInput": {**tool_input, "command": line.decode("utf-8")},
        "additionalContext": messages_ko.GREP_NOTE if _korean() else
                             "Boxdawn guard added --exclude flags to keep secret files such as .env "
                             "out of this grep, so a file may be missing here.",
    }}


def decide(payload: dict) -> dict | None:
    tool = payload.get("tool_name")
    tool_input = payload.get("tool_input") or {}
    if tool in _FILE_TOOLS:
        paths = [tool_input.get(k) for k in _FILE_TOOLS[tool]]
        paths = [g for p in paths if isinstance(p, str) for g in _globs(p.strip())]
        if tool == "Grep":
            paths = _with_secret_folder(paths, tool_input, payload.get("cwd"))
        if not paths:
            return _search_without_secrets(tool, tool_input, payload.get("cwd"))
    elif tool not in ("Bash", "PowerShell"):
        return None
    elif not isinstance(tool_input.get("command"), str):
        return None
    data_dir = os.environ.get("CLAUDE_PLUGIN_DATA")
    block_log.prune(data_dir)
    # The signed server bundle if one is stored and good, else the fixed rules.
    rules, bundle_exp = load_stored(data_dir)
    known_env = {k: os.environ[k] for k in ("TEMP", "TMP", "TMPDIR", "USERPROFILE") if os.environ.get(k)}
    where = {
        "cwd": payload.get("cwd") or os.getcwd(),
        "home": os.path.expanduser("~"),
        "rules": rules,
        "unattended": payload.get("permission_mode") in rules.unattended_modes,
    }
    if tool in _FILE_TOOLS:
        verdict = evaluate_file_tool(tool, paths, **where)
    else:
        verdict = (evaluate if tool == "Bash" else evaluate_powershell)(
            tool_input["command"], known_env=known_env, **where)
    if verdict is None or verdict.decision is None:
        if tool == "Bash":
            return _grep_without_secrets(tool_input, verdict.grep_ends, payload.get("cwd"))
        return _search_without_secrets(tool, tool_input, payload.get("cwd"))
    if bundle_exp is not None:
        block_log.record(data_dir, verdict, tool=tool, exp=bundle_exp)
    return {"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": verdict.decision,
        "permissionDecisionReason": "Boxdawn guard: " + "; ".join(
            map(messages_ko.translate, verdict.reasons) if _korean() else verdict.reasons),
    }}


def main() -> int:
    payload = None
    try:
        # Bytes: the default stdin encoding on a Korean Windows is cp949 and the
        # hook input is UTF-8, so a Korean file name would stop the read.
        stdin = sys.stdin
        raw = stdin.buffer.read().decode("utf-8") if hasattr(stdin, "buffer") else stdin.read()
        payload = json.loads(raw or "{}")
        out = decide(payload)
    except Exception as exc:  # noqa: BLE001 - a broken guard must not wave a call through
        tool = payload.get("tool_name") if isinstance(payload, dict) else None
        if isinstance(tool, str) and tool in _FILE_TOOLS:
            return 0
        out = {"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": messages_ko.FAILED.format(type(exc).__name__) if _korean()
            else f"Boxdawn guard failed ({type(exc).__name__}); refusing",
        }}
    if out is not None:
        sys.stdout.write(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
