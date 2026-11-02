"""A local record of the guard's deny and ask decisions, for team plans.

Written only when the call was judged on a verified signed bundle (a paying
customer): on the fixed rules nothing is written, so the free guard keeps no
record. One JSON line per deny or ask, never for a call let through. Every
value is from a closed set or a number, so no command, path or name has a
place in a line (decision ④, 2026-10-29). `block_send` sends it at session
start unless the customer keeps it local.

Day files under `${CLAUDE_PLUGIN_DATA}/log/`; files older than KEEP_DAYS go
at the next Bash or PowerShell call, whatever the plan and whether or not
anything new is written (`prune`, from the hook). A refused key removes the
whole folder (`rules_bundle.fetch`). Writing never raises: a failed write must not
change a decision, and with `onFailure: block` a crashing hook blocks every
command.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import time
from pathlib import Path

from boxdawn_guard.command_guard import RULE_IDS, TARGETS, Verdict

LOG_VERSION = 1
LOG_DIR = "log"
KEEP_DAYS = 30
TOOLS = frozenset({"Bash", "PowerShell"})
LEVELS = frozenset({"deny", "ask"})
DAY_FILE = re.compile(r"blocks-(\d{8})\.jsonl")
# Day files renamed for sending (`block_send`) keep their day, so they age out too.
_AGED_FILE = re.compile(r"(?:blocks|outbox)-(\d{8})(?:-[0-9a-f-]{36})?\.jsonl")
_BUILD_ID = re.compile(r"[0-9a-f]{7,64}")


def _build_id(data_dir: str) -> str | None:
    try:
        text = (Path(data_dir) / "current" / "BUILD_ID").read_text(encoding="ascii").strip()
    except (OSError, UnicodeDecodeError):
        return None
    return text if _BUILD_ID.fullmatch(text) else None


def entry(verdict: Verdict, *, tool: str, exp: int, build: str | None, now: float) -> dict | None:
    """The line for this verdict, or None when there is nothing to record or
    any value falls outside its closed set."""
    if verdict.decision not in LEVELS or tool not in TOOLS:
        return None
    findings = []
    for f in verdict.findings:
        if f.rule not in RULE_IDS or f.level not in LEVELS or not (f.target is None or f.target in TARGETS):
            return None
        findings.append({"rule": f.rule, "level": f.level, "target": f.target})
    return {"v": LOG_VERSION, "t": int(now), "tool": tool, "decision": verdict.decision,
            "escalated": bool(verdict.escalated), "findings": findings,
            "rules": "bundle", "exp": int(exp), "build": build}


def _open_append(path: Path) -> int:
    """A descriptor every write of which lands at the end of the file, even
    with other processes writing too. POSIX O_APPEND does that; on Windows
    O_APPEND is a seek then a write, and 20 writers lost about 40% of their
    lines (2026-11-01). A handle with append access only is appended to by
    the system itself."""
    if os.name != "nt":
        return os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    import ctypes
    import msvcrt
    from ctypes import wintypes

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateFileW.restype = wintypes.HANDLE
    k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
                                wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    file_append_data, share_all, open_always, normal = 0x4, 0x7, 4, 0x80
    handle = k32.CreateFileW(str(path), file_append_data, share_all, None, open_always, normal, None)
    if handle is None or handle == wintypes.HANDLE(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    return msvcrt.open_osfhandle(handle, os.O_WRONLY | os.O_BINARY)


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
            m = _AGED_FILE.fullmatch(p.name)
            if m and m.group(1) < cutoff:
                p.unlink(missing_ok=True)
    except Exception:  # noqa: BLE001 - see the module docstring
        pass


def record(data_dir: str | None, verdict: Verdict, *, tool: str, exp: int,
           now: float | None = None) -> bool:
    """Append this verdict's line; True when one was written. Never raises."""
    try:
        if not data_dir:
            return False
        now = time.time() if now is None else now
        line = entry(verdict, tool=tool, exp=exp, build=_build_id(data_dir), now=now)
        if line is None:
            return False
        folder = Path(data_dir) / LOG_DIR
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / f"blocks-{time.strftime('%Y%m%d', time.gmtime(now))}.jsonl"
        raw = (json.dumps(line, separators=(",", ":")) + "\n").encode("ascii")
        fd = _open_append(path)
        try:
            return os.write(fd, raw) == len(raw)
        finally:
            os.close(fd)
    except Exception:  # noqa: BLE001 - see the module docstring
        return False


def remove(data_dir: str | None) -> None:
    """Delete the whole record (the key was refused)."""
    if data_dir:
        shutil.rmtree(Path(data_dir) / LOG_DIR, ignore_errors=True)

