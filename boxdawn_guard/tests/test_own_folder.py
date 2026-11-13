"""With `undo` on, a call that names the plugin's data folder is not let through."""
from __future__ import annotations

import os
import shutil
import subprocess

import pytest

from boxdawn_guard import command_hook, undo
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
                 listing + "\nrm -rf src", restore + "\rrm -rf src", listing + "\rrm -rf src",
                 restore + "\u2028rm -rf src", listing + "\x0brm -rf src", f'"{exe}" undo list "$(echo x)"', f'"{exe}" fetch-rules',
                 f'"{exe}" undo list "{_data()}"'):
        decision, reason = _decision(_payload(project, more))
        assert decision == "deny" and "own folder" in reason, more


def test_a_second_powershell_statement_after_a_carriage_return_is_not_carried(project):
    exe = _data().replace("\\", "/") + "/current/bdxguard.exe"
    delete = "Remove-Item -Recurse -Force C:\\Windows\\Temp\\x"
    alone = _decision(_payload(project, delete, "PowerShell"))[0]
    for first in (f'& "{exe}" undo restore 2 "{project}"', f'& "{exe}" undo list "{project}"'):
        assert _decision(_payload(project, first + "\r" + delete, "PowerShell"))[0] == "deny" == alone


def test_file_tools_do_not_reach_into_the_folder(project):
    inside = os.path.join(_data(), "undo", "abc.git", "config")
    for tool, key in (("Write", "file_path"), ("Edit", "file_path"), ("MultiEdit", "file_path"),
                      ("NotebookEdit", "notebook_path"), ("Read", "file_path"), ("Grep", "path")):
        decision, reason = _decision({"tool_name": tool, "tool_input": {key: inside}, "cwd": project})
        assert decision == "deny" and "own folder" in reason, tool
    assert command_hook.decide({"tool_name": "Write", "tool_input": {"file_path": os.path.join(project, "a.txt")},
                                "cwd": project}) is None
    assert command_hook.decide({"tool_name": "Write", "tool_input": {}, "cwd": project}) is None


# -- fourth review -----------------------------------------------------------

def _home_rest():
    """The data folder written from the home folder on, when it is under it."""
    home = os.path.realpath(os.path.expanduser("~"))
    data = _data()
    return data[len(home):] if data.lower().startswith(home.lower() + os.sep) else None


def test_a_relative_path_into_the_folder_is_denied(project):
    for command, tool in [
        ("cat ../data/undo/k.jsonl", "Bash"),
        ("git --git-dir=../data/undo/k.git config core.hooksPath x", "Bash"),
        ("git --git-dir=../data/undo/k.git archive refs/snap/1 -o all.tar", "Bash"),
        ('cmd /c "rd /s /q ..\\data\\undo"', "Bash"),
        ("touch ../data/undo/k.lock", "Bash"),
        ("python -c \"open('../data/undo/k.jsonl','a').write('[')\"", "Bash"),
        ("GIT_DIR=../data/undo/k.git git config filter.x.clean evil", "Bash"),
        ("7z x a.7z -o../data/undo", "Bash"),
        ("cd .. && cat data/undo/k.jsonl", "Bash"),
        ("(cd .. && git -C data/undo/k.git config x y)", "Bash"),
        ("D=..; cat $D/data/undo/k.jsonl", "Bash"),
        ("ln -s ../data lnk", "Bash"),
        ("Get-Content ..\\data\\undo\\k.jsonl", "PowerShell"),
        ("New-Item -ItemType Junction -Path j -Target ..\\data", "PowerShell"),
        ("Remove-Item -Path:..\\data\\undo -Recurse", "PowerShell"),
    ]:
        decision, reason = _decision(_payload(project, command, tool))
        assert decision == "deny" and "own folder" in reason, (tool, command, decision, reason)


def test_other_spellings_of_the_full_path_are_denied(project):
    data = _data()
    slash = data.replace("\\", "/")
    head, name = slash.rsplit("/", 1)
    first, rest = slash.split("/", 1)
    forms = [
        (f"cat {first}/./{rest}/undo/k.jsonl", "Bash"),
        (f"cat {first}/x/../{rest}/undo/k.jsonl", "Bash"),
        (f"cat {head}/{name[0]}\\{name[1:]}/undo/k.jsonl", "Bash"),
        (f"cat {head}/{{{name}}}/undo/k.jsonl", "Bash"),
        (f"cat {head}/$'{name}'/undo/k.jsonl", "Bash"),
    ]
    if os.name == "nt":
        drive = slash[0].lower()
        forms += [(f"cat /proc/cygdrive/{drive}{slash[2:]}/undo/k.jsonl", "Bash"),
                  (f"cat /cygdrive/{drive}{slash[2:]}/undo/k.jsonl", "Bash"),
                  (f"Get-Content \\\\localhost\\{drive}$\\{data[3:]}\\undo\\k.jsonl", "PowerShell"),
                  (f"Get-Content \\\\127.0.0.1\\{drive}$\\{data[3:]}\\undo\\k.jsonl", "PowerShell"),
                  (f"Get-Content {data}.\\undo\\k.jsonl", "PowerShell")]
    rest_home = _home_rest()
    if rest_home:
        user = os.path.basename(os.path.realpath(os.path.expanduser("~")))
        r = rest_home.replace("\\", "/")
        forms += [(f"cat ~{user}{r}/undo/k.jsonl", "Bash"),
                  (f"cat ${{HOME:-x}}{r}/undo/k.jsonl", "Bash"),
                  (f"cat $HOMEDRIVE$HOMEPATH{r}/undo/k.jsonl", "Bash"),
                  (f'cmd /c "type %HOMEDRIVE%%HOMEPATH%{rest_home}\\undo\\k.jsonl"', "Bash"),
                  (f"Get-Content ${{env:USERPROFILE}}{rest_home}\\undo\\k.jsonl", "PowerShell"),
                  (f"Get-Content $env:HOMEDRIVE$env:HOMEPATH{rest_home}\\undo\\k.jsonl", "PowerShell"),
                  (f"cat %userprofile%{r}/undo/k.jsonl", "Bash"),
                  (f"cat ${{HOME}}{r}/undo", "Bash")]
    forms += [("Get-Content ${env:CLAUDE_PLUGIN_DATA}\\undo\\k.jsonl", "PowerShell"),
              ("cat ${CLAUDE_PLUGIN_DATA:-x}/undo/k.jsonl", "Bash"),
              ('cmd /c "type %CLAUDE_PLUGIN_DATA:~0%\\undo\\k.jsonl"', "Bash")]
    for command, tool in forms:
        decision, reason = _decision(_payload(project, command, tool))
        assert decision == "deny" and "own folder" in reason, (tool, command, decision, reason)


def test_the_guards_own_command_called_by_a_relative_path(project):
    assert _decision(_payload(project, "../data/current/bdxguard.exe undo list"))[0] is None
    decision, reason = _decision(_payload(project, "../data/current/bdxguard.exe undo restore 1"))
    assert decision == "ask" and "snapshot" in reason
    assert _decision(_payload(project, "& ..\\data\\current\\bdxguard.exe undo restore 1", "PowerShell"))[0] == "ask"
    for command in ("../data/current/bdxguard.exe undo-start /c/Users", "../data/current/bdxguard.exe fetch-rules",
                    "../data/current/bdxguard.exe undo restore 1 --force"):
        decision, reason = _decision(_payload(project, command))
        assert decision == "deny" and "own folder" in reason, command


def test_file_tools_with_other_spellings_are_denied(project):
    data = _data()
    inside = os.path.join(data, "undo", "k.jsonl")
    paths = [os.path.join(project, "..", "data", "undo", "k.jsonl"), "../data/undo/k.jsonl", inside.upper(),
             inside + "::$DATA", os.path.join(data + ".", "undo", "k.jsonl")]
    if os.name == "nt":
        drive = data[0].lower()
        paths += ["\\\\?\\" + inside, "\\\\.\\" + inside, "//?/" + inside.replace("\\", "/"),
                  f"\\\\localhost\\{drive}$\\{inside[3:]}", f"\\\\127.0.0.1\\{drive}$\\{inside[3:]}",
                  f"\\\\?\\UNC\\localhost\\{drive}$\\{inside[3:]}", "\\\\?\\GLOBALROOT\\DosDevices\\" + inside,
                  f"/{drive}{inside[2:]}".replace("\\", "/")]
        os.makedirs(os.path.join(data, "undo"), exist_ok=True)
        link = os.path.join(project, "lnk")
        subprocess.run(["cmd", "/c", "mklink", "/J", link, data], check=True, capture_output=True)
        paths.append(os.path.join(link, "undo", "k.jsonl"))
    for path in paths:
        for tool, key in (("Read", "file_path"), ("Write", "file_path"), ("Grep", "path")):
            decision, reason = _decision({"tool_name": tool, "tool_input": {key: path, "pattern": "x"}, "cwd": project})
            assert decision == "deny" and "own folder" in reason, (tool, path, decision)


def test_a_folder_search_above_leaves_the_folder_out(project):
    data = _data()
    above = os.path.dirname(data)
    out = command_hook.decide({"tool_name": "Grep", "tool_input": {"pattern": "before", "path": above,
                                                                    "glob": "**/undo/*.jsonl"}, "cwd": project})
    glob = out["hookSpecificOutput"]["updatedInput"]["glob"]
    assert glob.startswith("**/undo/*.jsonl ") and f"!**/{os.path.basename(data)}/**" in glob
    decision, reason = _decision({"tool_name": "Grep", "tool_input": {
        "pattern": "before", "glob": data.replace("\\", "/") + "/undo/*.jsonl"}, "cwd": project})
    assert decision == "deny" and "own folder" in reason
    beside = command_hook.decide({"tool_name": "Grep", "tool_input": {"pattern": "x", "path": project}, "cwd": project})
    assert f"!**/{os.path.basename(data)}/**" not in beside["hookSpecificOutput"]["updatedInput"]["glob"]


def test_neighbours_and_mentions_of_other_paths_are_left_alone(project):
    slash = _data().replace("\\", "/")
    for command in (f"ls {slash}.bak", f"ls {slash}~", f"ls {slash}+x", f"ls {slash}@2",
                    f"ls {slash}-old", f"ls {slash}_2/undo", f"curl https://example.com{slash[2:]}/undo",
                    f"ls ./vendor{slash[2:]}", "ls ../database", "cat data/undo/x", "git status", "echo undo"):
        assert "own folder" not in _decision(_payload(project, command))[1], command


def test_the_guards_own_list_takes_no_snapshot(project):
    exe = _data().replace("\\", "/") + "/current/bdxguard.exe"
    store = undo.Store(os.path.realpath(project), os.environ["CLAUDE_PLUGIN_DATA"])
    for command in (f'"{exe}" undo list "{project}"', f'"{exe}" undo restore 1 "{project}"'):
        payload = _payload(project, command)
        command_hook._snapshot_before(payload, command_hook.decide(payload))
    assert store.rows() == []
    command_hook._snapshot_before(_payload(project, "ls"), None)
    assert [r["n"] for r in store.snapshots()] == [1]


def test_a_setting_that_points_at_home_or_the_project_turns_the_rule_off(project, monkeypatch):
    for where in (os.path.expanduser("~"), project, os.path.splitdrive(project)[0] + os.sep):
        monkeypatch.setenv("CLAUDE_PLUGIN_DATA", where)
        assert command_hook.decide({"tool_name": "Write", "tool_input": {"file_path": os.path.join(project, "a.txt")},
                                    "cwd": project}) is None, where
        assert "own folder" not in _decision(_payload(project, "git status"))[1], where


def test_lines_the_mutation_check_found_untested(project, monkeypatch):
    data = _data()
    from boxdawn_guard import own_folder
    folder = os.path.normcase(data)
    # a command run from inside the folder
    inside = os.path.join(data, "undo")
    os.makedirs(inside, exist_ok=True)
    decision, reason = _decision(dict(_payload(project, "git status"), cwd=inside))
    assert decision == "deny" and "own folder" in reason
    # PowerShell's -Name:value, on a reading command the judge does not look at
    decision, reason = _decision(_payload(project, "Get-Content -Path:..\\data\\undo\\k.jsonl", "PowerShell"))
    assert decision == "deny" and "own folder" in reason
    # a stream named on the folder itself
    if os.name == "nt":
        assert own_folder.command_reaches(f"Get-Content {data}::$INDEX_ALLOCATION\\undo\\k.jsonl", folder, project)
    # a carriage return inside the guard's own line
    exe = data.replace("\\", "/") + "/current/bdxguard.exe"
    assert own_folder.own_command(f'"{exe}" undo list\rx', folder, project) is None
    assert own_folder.own_command(f'"{exe}" undo list x', folder, project) == "list"
    # a setting that is the home folder or a whole drive, without a project to hold
    assert own_folder.folder_to_keep(os.path.expanduser("~"), None) is None
    assert own_folder.folder_to_keep(os.path.splitdrive(data)[0] + os.sep if os.name == "nt" else "/", None) is None
    assert own_folder.folder_to_keep(data, None) == folder
