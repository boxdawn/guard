"""Check a built bdxguard binary against the Python code it was built from.

For each command, the binary's stdout must be byte-identical to what
`command_hook.main` would print for the same payload (`json.dumps(decide())`,
or nothing). Then time the binary's process round trip (median of N runs).

Usage: python packaging/check_binary.py <path-to-binary> [runs]
Exits non-zero on any mismatch, so CI goes red.
"""
from __future__ import annotations

import json
import statistics
import subprocess
import sys
import tempfile
import time

from boxdawn_guard.command_hook import decide

COMMANDS = [
    ("ls -la", "default"),
    ("git status && rm -rf build/ && ls -la", "default"),
    ("echo hi", "default"),
    ("rm -rf /", "default"),
    ("rm -rf $HOME", "default"),
    ("rm$IFS-rf$IFS/", "default"),
    ("echo cm0gLXJmIC8= | base64 -d | sh", "default"),
    ("dd if=/dev/zero of=/dev/sda", "default"),
    ("truncate -s 0 important.db", "default"),
    ("git reset --hard HEAD~3", "default"),
    ("git reset --hard HEAD~3", "bypassPermissions"),
    ("git push --force origin main", "dontAsk"),
    ("python -c \"import shutil; shutil.rmtree('/')\"", "default"),
]


def main() -> int:
    binary = sys.argv[1]
    runs = int(sys.argv[2]) if len(sys.argv) > 2 else 21
    cwd = tempfile.mkdtemp(prefix="bdxg_proj_")
    mismatches = 0
    for command, mode in COMMANDS:
        payload = {"tool_name": "Bash", "tool_input": {"command": command},
                   "cwd": cwd, "permission_mode": mode}
        expected = decide(payload)
        expected_out = "" if expected is None else json.dumps(expected)
        got = subprocess.run([binary], input=json.dumps(payload), capture_output=True,
                             text=True, timeout=30).stdout
        same = got == expected_out
        mismatches += not same
        decision = "none" if expected is None else expected["hookSpecificOutput"]["permissionDecision"]
        print(f"{'SAME' if same else 'DIFF'}  {decision:5}  [{mode}] {command}")
        if not same:
            print(f"      expected: {expected_out!r}\n      got:      {got!r}")

    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": COMMANDS[1][0]},
                          "cwd": cwd, "permission_mode": "default"})
    times = []
    for _ in range(runs):
        t = time.perf_counter()
        subprocess.run([binary], input=payload, capture_output=True, text=True, timeout=30)
        times.append((time.perf_counter() - t) * 1000)
    print(f"round trip median {statistics.median(times):.0f} ms over {runs} runs "
          f"(min {min(times):.0f}, max {max(times):.0f}) on {sys.platform}")
    print(f"{len(COMMANDS) - mismatches}/{len(COMMANDS)} identical")
    return 1 if mismatches else 0


if __name__ == "__main__":
    sys.exit(main())
