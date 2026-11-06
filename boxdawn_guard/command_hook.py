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

from boxdawn_guard import block_log, secret_files
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


def _search_roots(tool_input: dict, cwd: str | None) -> tuple[str, ...]:
    """Where a `Grep` starts, as written and on disk: which of the two Claude Code
    searches from differs by system. A network path stays text: looking it up
    contacts the host, and this runs before the person is asked."""
    path = tool_input.get("path")
    path = os.path.expanduser(path) if isinstance(path, str) and path else "."
    written = os.path.abspath(os.path.join(cwd or "", path))
    if written.replace("\\", "/").startswith(("//", "/net/")):
        return (written,)
    return written, os.path.realpath(written)


def _search_without_secrets(tool: str, tool_input: dict, cwd: str | None) -> dict | None:
    """`Grep` over a folder reads `.env` without naming it, and a window on every
    such search would be too many. No decision: the normal permission flow stays."""
    if tool != "Grep":
        return None
    roots = _search_roots(tool_input, cwd)
    if len(roots) > 1 and os.path.isfile(roots[-1]):
        return None
    glob = tool_input.get("glob")
    excludes = " ".join(secret_files.search_excludes(*roots))
    if isinstance(glob, str) and excludes in glob:  # sent back as we changed it
        return None
    return {"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "updatedInput": {**tool_input, "glob": f"{glob} {excludes}" if isinstance(glob, str) and glob else excludes},
        "additionalContext": "Boxdawn guard keeps secret files such as .env out of folder searches, "
                             "so a file may be missing here. Give a file's path to search it.",
    }}


def decide(payload: dict) -> dict | None:
    tool = payload.get("tool_name")
    tool_input = payload.get("tool_input") or {}
    if tool in _FILE_TOOLS:
        paths = [tool_input.get(k) for k in _FILE_TOOLS[tool]]
        paths = [g for p in paths if isinstance(p, str) for g in _globs(p)]
        if tool == "Grep" and not any(secret_files.is_secret(p, glob_matches_dots=True) for p in paths):
            # `.ssh` as the session folder, a folder under it, or a link to it names nothing
            found = map(secret_files.secret_folder, _search_roots(tool_input, payload.get("cwd")))
            paths += [f for f in found if f][:1]
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
        return _search_without_secrets(tool, tool_input, payload.get("cwd"))
    if bundle_exp is not None:
        block_log.record(data_dir, verdict, tool=tool, exp=bundle_exp)
    return {"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": verdict.decision,
        "permissionDecisionReason": "Boxdawn guard: " + "; ".join(verdict.reasons),
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
            "permissionDecisionReason": f"Boxdawn guard failed ({type(exc).__name__}); refusing",
        }}
    if out is not None:
        sys.stdout.write(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
