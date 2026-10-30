"""Claude Code PreToolUse hook around `command_guard.evaluate` (Bash) and
`powershell_guard.evaluate_powershell` (PowerShell).

Reads the hook input on stdin and prints a decision for Bash and PowerShell calls:
`deny` or `ask` with a reason, or nothing (the normal permission flow).
Never `allow`. Register it with `"onFailure": "block"` (Claude Code
v2.1.295+): a command hook that times out does not block by default.

Rules come from `command_rules_source` for now (A-1). Step 3 of the
protection design replaces that with the signed bundle from the server.
"""
from __future__ import annotations

import json
import os
import sys

from boxdawn_guard.command_guard import evaluate
from boxdawn_guard.command_rules_source import default_command_rules
from boxdawn_guard.powershell_guard import evaluate_powershell


def decide(payload: dict) -> dict | None:
    tool = payload.get("tool_name")
    if tool not in ("Bash", "PowerShell"):
        return None
    command = (payload.get("tool_input") or {}).get("command")
    if not isinstance(command, str):
        return None
    rules = default_command_rules()
    known_env = {k: os.environ[k] for k in ("TEMP", "TMP", "TMPDIR") if os.environ.get(k)}
    verdict = (evaluate if tool == "Bash" else evaluate_powershell)(
        command,
        cwd=payload.get("cwd") or os.getcwd(),
        home=os.path.expanduser("~"),
        rules=rules,
        unattended=payload.get("permission_mode") in rules.unattended_modes,
        known_env=known_env,
    )
    if verdict is None or verdict.decision is None:
        return None
    return {"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": verdict.decision,
        "permissionDecisionReason": "Boxdawn guard: " + "; ".join(verdict.reasons),
    }}


def main() -> int:
    try:
        payload = json.loads(sys.stdin.read() or "{}")
        out = decide(payload)
    except Exception as exc:  # noqa: BLE001 - a broken guard must not wave a call through
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
