"""The Copilot CLI preToolUse hook: inputs and answers as measured on Copilot 1.0.106."""
from __future__ import annotations

import io
import json
import os
import threading

import pytest

pytest.importorskip("tree_sitter_bash")

from boxdawn_guard import command_hook, copilot_hook

_helper = os.environ.get("BDX_PSPARSE")
needs_helper = pytest.mark.skipif(not (_helper and os.path.isfile(_helper)),
                                  reason="BDX_PSPARSE (bdxpsparse.exe) not built")


def _payload(command, tool="powershell"):
    return {"sessionId": "s", "timestamp": 1, "cwd": "C:\\work\\proj", "toolCallId": "c", "toolName": tool,
            "toolArgs": {"command": command, "description": "d"}}


def _run(monkeypatch, capsys, stdin, **kwargs):
    monkeypatch.setattr("sys.stdin", io.StringIO(stdin))
    assert copilot_hook.main(**kwargs) == 0
    return capsys.readouterr().out


@needs_helper
@pytest.mark.parametrize("command", [
    "Remove-Item -Recurse -Force C:\\Users\\someone\\Documents",
    "ri -r -fo C:\\Users\\someone\\Documents",
    "Get-ChildItem C:\\Users\\someone\\Documents | Remove-Item -Recurse -Force",
])
def test_powershell_commands_get_the_powershell_rules(command):
    # Judged as Bash these get no decision at all.
    out = copilot_hook.decide(_payload(command))
    assert set(out) == {"permissionDecision", "permissionDecisionReason"}
    assert out["permissionDecision"] == "deny"
    assert out["permissionDecisionReason"].startswith("Boxdawn guard: ")


def test_bash_commands_get_the_bash_rules():
    assert copilot_hook.decide(_payload("rm -rf /", "bash"))["permissionDecision"] == "deny"


def test_ordinary_commands_get_no_decision():
    assert copilot_hook.decide(_payload("echo hello", "bash")) is None


@pytest.mark.parametrize("tool", ["view", "rg", "edit", "create", "task_complete"])
def test_other_tools_get_no_decision(tool):
    assert copilot_hook.decide({"toolName": tool, "toolArgs": {"path": "x"}, "cwd": "/w"}) is None


@pytest.mark.parametrize("tool", ["write_powershell", "write_bash"])
def test_typing_into_a_running_shell_is_always_asked(tool):
    out = copilot_hook.decide({"toolName": tool, "toolArgs": {"input": "echo hi"}, "cwd": "/w"})
    assert out["permissionDecision"] == "ask"


def test_tool_args_as_a_string_are_read():
    payload = {**_payload("x"), "toolArgs": json.dumps({"command": "rm -rf /"}), "toolName": "bash"}
    assert copilot_hook.decide(payload)["permissionDecision"] == "deny"


def test_a_decision_without_a_verdict_is_no_decision(monkeypatch):
    monkeypatch.setattr(command_hook, "decide", lambda p: {"hookSpecificOutput": {"updatedInput": {}}})
    assert copilot_hook.decide(_payload("anything")) is None


def test_main_prints_only_the_copilot_shape(monkeypatch, capsys):
    out = json.loads(_run(monkeypatch, capsys, json.dumps(_payload("rm -rf /", "bash"))))
    assert out["permissionDecision"] == "deny" and "hookSpecificOutput" not in out


def test_main_prints_nothing_for_no_decision(monkeypatch, capsys):
    assert _run(monkeypatch, capsys, json.dumps(_payload("echo hello", "bash"))) == ""


@pytest.mark.parametrize("stdin", ["not json", json.dumps({"toolName": "bash", "toolArgs": "not json"})])
def test_a_broken_call_is_refused(monkeypatch, capsys, stdin):
    out = json.loads(_run(monkeypatch, capsys, stdin))
    assert out["permissionDecision"] == "deny"


def test_a_failing_guard_refuses(monkeypatch, capsys):
    def boom(_):
        raise RuntimeError
    monkeypatch.setattr(command_hook, "decide", boom)
    out = json.loads(_run(monkeypatch, capsys, json.dumps(_payload("echo hello"))))
    assert out["permissionDecision"] == "deny" and "RuntimeError" in out["permissionDecisionReason"]


def test_a_stuck_guard_is_refused_before_copilot_gives_up(monkeypatch, capsys):
    exited = threading.Event()
    release = threading.Event()
    monkeypatch.setattr(copilot_hook.os, "_exit", lambda code: (exited.set(), release.set()))
    monkeypatch.setattr(command_hook, "decide", lambda p: release.wait(5) and None)
    out = json.loads(_run(monkeypatch, capsys, json.dumps(_payload("echo hello")), deadline=0.05))
    assert exited.is_set()
    assert out["permissionDecision"] == "deny"


def test_the_plugin_manifest_has_no_schema():
    # With `$schema` Copilot reads hooks only under com.github.copilot/, so ours
    # would stop running, with no warning, and every command would go through.
    path = os.path.join(os.path.dirname(__file__), "..", "..", "plugin-copilot", "plugin.json")
    with open(path, encoding="utf-8") as f:
        assert "$schema" not in json.load(f)


def test_the_copilot_plugin_carries_the_same_version():
    """The release checks its tag against both manifests; a bump that misses one fails there."""
    root = os.path.join(os.path.dirname(__file__), "..", "..")
    with open(os.path.join(root, "plugin-copilot", "plugin.json"), encoding="utf-8") as f:
        copilot = json.load(f)["version"]
    with open(os.path.join(root, "plugin", ".claude-plugin", "plugin.json"), encoding="utf-8") as f:
        claude = json.load(f)["version"]
    assert copilot == claude
