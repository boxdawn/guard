"""With `undo` on, a call that names the plugin's data folder is not let through."""
from __future__ import annotations

import os
import shutil

import pytest

from boxdawn_guard import command_hook
from boxdawn_guard.tests.test_undo import _payload, project  # noqa: F401 - `project` is a fixture

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")


def _data():
    return os.path.realpath(os.environ["CLAUDE_PLUGIN_DATA"])


def _decision(payload):
    out = command_hook.decide(payload)
    if out is None or "permissionDecision" not in out["hookSpecificOutput"]:
        return None, ""
    return out["hookSpecificOutput"]["permissionDecision"], out["hookSpecificOutput"]["permissionDecisionReason"]


def _forms(project):
    data = _data()
    slash = data.replace("\\", "/")
    bash = [
        f"git --git-dir={slash}/undo/abc.git show HEAD:.env",
        f'git --git-dir="{slash}/undo/abc.git" config filter.x.clean evil',
        f"cat '{slash}/undo/abc.jsonl'",
        f"cd {slash} && ls",
        f"mkdir -p {slash}/undo",
        f"ln -s /tmp/w {slash}/undo",
        f"cp -r {slash} /tmp/copy",
        f"echo x >> {slash}/undo/abc.git/info/attributes",
        f"ls '{slash[:6]}'\"{slash[6:]}\"/undo",  # quoted in two pieces
        "ls $CLAUDE_PLUGIN_DATA/undo",
        'ls "${CLAUDE_PLUGIN_DATA}"',
        f"ls {data}" if os.name == "nt" else f"ls {slash}/",
        f"ls {slash.upper()}" if os.name == "nt" else f"ls {slash}//undo",
    ]
    if os.name == "nt":
        drive, rest = slash[0].lower(), slash[2:]
        bash += [f"ls /{drive}{rest}/undo", f"ls /mnt/{drive}{rest}", f'subst X: "{data}"', f'robocopy d "{data}\\undo" /MIR',
                 f'cmd /c "type {data}\\undo\\abc.jsonl"']
    home = os.path.realpath(os.path.expanduser("~")).replace("\\", "/")
    if slash.lower().startswith(home.lower() + "/"):
        bash += [f"ls ~{slash[len(home):]}", f'ls "$HOME{slash[len(home):]}/undo"']
    powershell = [f"Get-Content '{data}{os.sep}undo{os.sep}abc.jsonl'",
                  f'New-Item -ItemType Directory "{slash}/undo"',
                  "Get-ChildItem $env:CLAUDE_PLUGIN_DATA"]
    return [(c, "Bash") for c in bash] + [(c, "PowerShell") for c in powershell]


def test_a_command_that_names_the_folder_is_denied(project):
    for command, tool in _forms(project):
        decision, reason = _decision(_payload(project, command, tool))
        assert decision == "deny" and "own folder" in reason, (tool, command, decision, reason)


def test_with_undo_off_nothing_changes(project, monkeypatch):
    monkeypatch.setenv("CLAUDE_PLUGIN_OPTION_UNDO", "false")
    for command, tool in _forms(project):
        assert "own folder" not in _decision(_payload(project, command, tool))[1], (tool, command)
    for tool, key in (("Write", "file_path"), ("Edit", "file_path"), ("NotebookEdit", "notebook_path")):
        assert command_hook.decide({"tool_name": tool, "tool_input": {key: os.path.join(_data(), "undo", "x")},
                                    "cwd": project}) is None


def test_a_path_reached_in_steps_is_denied_by_the_judge(project):
    parent, name = os.path.split(_data())
    parent = parent.replace("\\", "/")
    for command in (f"cd {parent} && echo x > {name}/undo/planted", f"cd {parent} && rm -rf {name}/undo"):
        decision, reason = _decision(_payload(project, command))
        assert decision == "deny" and "own folder" in reason, (command, reason)


def test_another_folder_with_a_longer_name_and_plain_commands_are_left_alone(project):
    slash = _data().replace("\\", "/")
    for command in (f"ls {slash}-old", f"ls {slash}_2/undo", "ls", "git status", "echo undo"):
        assert "own folder" not in _decision(_payload(project, command))[1], command


def test_the_guards_own_undo_command(project):
    exe = _data().replace("\\", "/") + "/current/bdxguard.exe"
    listing = f'"{exe}" undo list "{project}"'
    restore = f'"{exe}" undo restore 2 "{project}"'
    assert _decision(_payload(project, listing))[0] is None
    assert _decision(_payload(project, "& " + listing, "PowerShell"))[0] is None
    decision, reason = _decision(_payload(project, restore))
    assert decision == "ask" and "snapshot" in reason
    unattended = dict(_payload(project, restore), permission_mode="bypassPermissions")
    assert _decision(unattended)[0] == "deny"
    for more in (restore + "; rm -rf src", restore + " && echo x", listing + " | tee out.txt", listing + " `echo x`",
                 listing + "\nrm -rf src", f'"{exe}" undo list "$(echo x)"', f'"{exe}" fetch-rules',
                 f'"{exe}" undo list "{_data()}"'):
        decision, reason = _decision(_payload(project, more))
        assert decision == "deny" and "own folder" in reason, more


def test_file_tools_do_not_reach_into_the_folder(project):
    inside = os.path.join(_data(), "undo", "abc.git", "config")
    for tool, key in (("Write", "file_path"), ("Edit", "file_path"), ("MultiEdit", "file_path"),
                      ("NotebookEdit", "notebook_path"), ("Read", "file_path"), ("Grep", "path")):
        decision, reason = _decision({"tool_name": tool, "tool_input": {key: inside}, "cwd": project})
        assert decision == "deny" and "own folder" in reason, tool
    assert command_hook.decide({"tool_name": "Write", "tool_input": {"file_path": os.path.join(project, "a.txt")},
                                "cwd": project}) is None
    assert command_hook.decide({"tool_name": "Write", "tool_input": {}, "cwd": project}) is None
