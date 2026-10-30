"""The PreToolUse hook around the command guard: what Claude Code receives."""
from __future__ import annotations

import io
import json

import pytest

pytest.importorskip("tree_sitter_bash")

from boxdawn_guard import command_hook  # noqa: E402


def _payload(command, mode="default", tool="Bash"):
    return {"tool_name": tool, "tool_input": {"command": command},
            "cwd": "/work/proj", "permission_mode": mode}


def test_other_tools_get_no_decision():
    assert command_hook.decide(_payload("rm -rf /", tool="Read")) is None


def test_ordinary_bash_gets_no_decision():
    assert command_hook.decide(_payload("ls -la")) is None


def test_a_denial_has_the_shape_claude_code_reads():
    out = command_hook.decide(_payload("rm -rf /"))["hookSpecificOutput"]
    assert out["hookEventName"] == "PreToolUse"
    assert out["permissionDecision"] == "deny"
    assert out["permissionDecisionReason"].startswith("Boxdawn guard: ")


@pytest.mark.parametrize("mode, expected", [
    ("default", "ask"), ("acceptEdits", "ask"), ("plan", "ask"),
    ("bypassPermissions", "deny"), ("dontAsk", "deny"),
])
def test_ask_becomes_deny_when_nobody_can_answer(mode, expected):
    out = command_hook.decide(_payload("git reset --hard HEAD~3", mode))
    assert out["hookSpecificOutput"]["permissionDecision"] == expected


def test_never_allow():
    for c in ("ls", "rm -rf /", "git reset --hard", "echo hi"):
        out = command_hook.decide(_payload(c))
        assert out is None or out["hookSpecificOutput"]["permissionDecision"] in ("deny", "ask")


def test_a_broken_guard_refuses(monkeypatch, capsys):
    def boom(payload):
        raise RuntimeError("x")
    monkeypatch.setattr(command_hook, "decide", boom)
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(_payload("ls"))))
    assert command_hook.main() == 0
    out = json.loads(capsys.readouterr().out)["hookSpecificOutput"]
    assert out["permissionDecision"] == "deny"


def test_unreadable_input_refuses(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO("{not json"))
    command_hook.main()
    assert json.loads(capsys.readouterr().out)["hookSpecificOutput"]["permissionDecision"] == "deny"
