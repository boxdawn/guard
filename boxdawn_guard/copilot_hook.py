"""GitHub Copilot CLI `preToolUse` hook around `command_hook.decide`.

Register it under the name `preToolUse`, not `PreToolUse`: with the Claude
spelling Copilot calls a PowerShell command `Bash`, and the Bash rules let
`Remove-Item` through. Prints `permissionDecision` for a deny or an ask, or
nothing. Copilot calls this for every tool, so the rest get no decision.

Copilot lets a call through when a hook times out or prints something it cannot
read, and has no setting for it. So this answers deny itself before its own
limit: keep DEADLINE_SECONDS well under `timeoutSec`. A guard that never gets
as far as `main` is not covered.
"""
from __future__ import annotations

import json
import os
import sys
import threading

DEADLINE_SECONDS = 10

_SHELLS = {"powershell": "PowerShell", "bash": "Bash"}
# These type into a shell already running. A command can arrive in pieces over
# several calls, so what one call carries says nothing: a person looks at each.
_SHELL_INPUT = ("write_powershell", "write_bash")


def _answer(decision: str, reason: str) -> dict:
    return {"permissionDecision": decision, "permissionDecisionReason": "Boxdawn guard: " + reason}


def decide(payload: dict) -> dict | None:
    tool = payload.get("toolName")
    if tool in _SHELL_INPUT:
        return _answer("ask", f"`{tool}` types into a running shell, which the guard cannot judge")
    if tool not in _SHELLS:
        return None
    args = payload.get("toolArgs")
    if isinstance(args, str):
        args = json.loads(args)
    # Here, not at the top: the deadline in `main` has to cover loading the rules code.
    from boxdawn_guard import command_hook
    out = command_hook.decide({"tool_name": _SHELLS[tool], "tool_input": args, "cwd": payload.get("cwd")})
    verdict = out["hookSpecificOutput"] if out else {}
    if "permissionDecision" not in verdict:
        return None
    return {k: verdict[k] for k in ("permissionDecision", "permissionDecisionReason")}


def main(deadline: float = DEADLINE_SECONDS) -> int:
    said = threading.Lock()  # never released: the first answer is the only one

    def say(out: dict | None) -> bool:
        if not said.acquire(blocking=False):
            return False
        if out is not None:
            sys.stdout.write(json.dumps(out))
            sys.stdout.flush()
        return True

    def too_late() -> None:
        if say(_answer("deny", "the check took too long; refusing")):
            os._exit(0)

    timer = threading.Timer(deadline, too_late)
    timer.daemon = True
    timer.start()
    try:
        # Bytes: see `command_hook.main`.
        stdin = sys.stdin
        raw = stdin.buffer.read().decode("utf-8") if hasattr(stdin, "buffer") else stdin.read()
        out = decide(json.loads(raw or "{}"))
    except Exception as exc:  # noqa: BLE001 - a broken guard must not wave a call through
        out = _answer("deny", f"failed ({type(exc).__name__}); refusing")
    timer.cancel()
    say(out)
    return 0
