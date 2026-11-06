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


def _grep_without_secrets(tool_input: dict, ends: tuple[int, ...]) -> dict | None:
    """`grep -r` reads `.env` without naming it. The flags go right after the name:
    any later word may be the end of the options, and later commands keep their place."""
    flags = " " + " ".join(secret_files.GREP_EXCLUDES)
    command = tool_input["command"]
    if not ends or flags in command:
        return None
    line = command.encode("utf-8")
    for end in reversed(ends):
        line = line[:end] + flags.encode() + line[end:]
    return {"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "updatedInput": {**tool_input, "command": line.decode("utf-8")},
        "additionalContext": "Boxdawn guard added --exclude flags to keep secret files such as .env "
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
            return _grep_without_secrets(tool_input, verdict.grep_ends)
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
