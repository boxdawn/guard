"""With `undo` on, a line that plainly runs the guard's own `undo restore` asks first."""
from __future__ import annotations

import os
import shutil

import pytest

from boxdawn_guard import command_hook, undo
from boxdawn_guard.tests.test_undo import _payload, project  # noqa: F401 - `project` is a fixture

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")


def _decision(payload):
    out = command_hook.decide(payload)
    h = (out or {}).get("hookSpecificOutput", {})
    return h.get("permissionDecision"), h.get("permissionDecisionReason", "")


def _exe():
    return os.environ["CLAUDE_PLUGIN_DATA"].replace("\\", "/") + "/current/bdxguard.exe"


def test_restore_asks_and_is_denied_with_nobody_there(project):
    for command, tool in ((f'"{_exe()}" undo restore 2 "{project}"', "Bash"),
                          (f'& "{_exe()}" undo restore 2', "PowerShell"),
                          ("../data/current/bdxguard.exe undo restore 1", "Bash"),
                          ("bdxguard undo restore 1", "Bash")):
        decision, reason = _decision(_payload(project, command, tool))
        assert decision == "ask" and "snapshot" in reason, command
        unattended = dict(_payload(project, command, tool), permission_mode="bypassPermissions")
        assert _decision(unattended)[0] == "deny", command


def test_a_deny_on_the_same_line_stays_a_deny(project):
    decision, _ = _decision(_payload(project, f'"{_exe()}" undo restore 2; rm -rf /'))
    assert decision == "deny"


def test_list_and_other_lines_are_left_alone_and_undo_off_changes_nothing(project, monkeypatch):
    for command in (f'"{_exe()}" undo list "{project}"', "echo undo restore", "git restore ."):
        assert "snapshot" not in _decision(_payload(project, command))[1], command
    # Undo off and no copies of this project: nothing to go back to (with copies it asks,
    # test_undo_default_on).
    monkeypatch.setenv("CLAUDE_PLUGIN_OPTION_UNDO", "false")
    assert _decision(_payload(project, f'"{_exe()}" undo restore 2'))[0] is None


def test_the_guards_own_undo_line_takes_no_snapshot(project):
    store = undo.Store(os.path.realpath(project), os.environ["CLAUDE_PLUGIN_DATA"])
    for command in (f'"{_exe()}" undo list "{project}"', f'"{_exe()}" undo restore 1 "{project}"'):
        payload = _payload(project, command)
        command_hook._snapshot_before(payload, command_hook.decide(payload))
    assert store.rows() == []
    command_hook._snapshot_before(_payload(project, "ls"), None)
    assert [r["n"] for r in store.snapshots()] == [1]


def test_a_number_that_is_not_ascii_is_not_a_snapshot_number(project, capsys):
    undo.before_command(_payload(project), os.environ["CLAUDE_PLUGIN_DATA"])
    for number in ("²", "١"):
        assert undo._cli(["undo", "restore", number, project]) == 1, number
