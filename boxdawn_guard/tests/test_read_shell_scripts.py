"""A shell script the line runs (`bash x.sh`, `./x.sh`) is read from disk and
judged as typed. Only what would be refused asks, under `script.refused` with
the script's own reasons; a delete of a path known only at run time
(`rm -rf "$TMP"`, how scripts clean up) does not, nor does anything that would
only ask. Nothing is ever refused for a script: what it holds can change.
"""
from __future__ import annotations

import os
import time

import pytest

pytest.importorskip("tree_sitter_bash")

from boxdawn_guard import messages_ko  # noqa: E402
from boxdawn_guard.command_guard import evaluate  # noqa: E402
from boxdawn_guard.command_rules_source import default_command_rules  # noqa: E402

RULES = default_command_rules()
HOME_WIPE = "#!/bin/bash\nset -e\nrm -rf ~/\n"


def judge(project, command, unattended=False):
    return evaluate(command, cwd=str(project), home=os.path.expanduser("~"), rules=RULES, unattended=unattended)


@pytest.fixture
def project(tmp_path):
    p = tmp_path / "proj"
    (p / "scripts").mkdir(parents=True)
    return p


def write(project, name, text):
    f = project / name
    f.write_text(text, encoding="utf-8", newline="\n")
    return f


@pytest.mark.parametrize("command", [
    "bash scripts/x.sh", "sh scripts/x.sh", "bash -e scripts/x.sh", "bash -euo pipefail scripts/x.sh",
    "./scripts/x.sh", "sudo bash scripts/x.sh", "timeout 60 bash scripts/x.sh arg",
    "cd scripts && bash x.sh", "zsh ./scripts/x.sh", "echo start; bash scripts/x.sh",
])
def test_a_script_that_would_wipe_the_home_folder_asks(project, command):
    write(project, "scripts/x.sh", HOME_WIPE)
    v = judge(project, command)
    assert v.decision == "ask", v.reasons
    rules = {f.rule for f in v.findings}
    assert {"script.refused", "rm.outside"} <= rules, v.reasons


def test_the_reason_names_the_script_and_what_it_holds(project):
    write(project, "scripts/x.sh", HOME_WIPE)
    v = judge(project, "bash scripts/x.sh")
    assert "`scripts/x.sh` runs a command that would be refused" in v.reasons
    said = [messages_ko.translate(r) for r in v.reasons]
    assert "`scripts/x.sh`: 안에 거절될 명령이 있습니다" in said


def test_it_asks_and_never_refuses_here(project):
    write(project, "scripts/x.sh", HOME_WIPE)
    assert all(f.level == "ask" for f in judge(project, "bash scripts/x.sh").findings)


def test_with_nobody_present_the_ask_is_refused(project):
    write(project, "scripts/x.sh", HOME_WIPE)
    assert judge(project, "bash scripts/x.sh", unattended=True).decision == "deny"


@pytest.mark.parametrize("body", [
    "git push --force origin main\n",
    "terraform destroy -auto-approve\n",
    "psql -c 'DROP DATABASE app'\n",
    "dd if=/dev/zero of=/dev/sda\n",
])
def test_other_commands_that_would_be_refused_ask(project, body):
    write(project, "scripts/x.sh", "#!/bin/sh\n" + body)
    v = judge(project, "sh scripts/x.sh")
    assert v.decision == "ask", v.reasons
    assert "script.refused" in {f.rule for f in v.findings}


@pytest.mark.parametrize("body", [
    'TMP_DIR=$(mktemp -d)\ntrap \'rm -rf "$TMP_DIR"\' EXIT\nrm -rf "$TMP_DIR"\n',  # cleans up after itself
    'rm -rf "$1"\n',
    "rm -rf build dist\nnpm ci\nnpm run build\n",
    "git reset --hard\n",  # would only ask
    "pip install -r requirements.txt\npytest -q\n",
    "",
])
def test_an_ordinary_script_gets_no_decision(project, body):
    write(project, "scripts/x.sh", "#!/bin/bash\n" + body)
    assert judge(project, "bash scripts/x.sh").decision is None


@pytest.mark.parametrize("command", [
    "bash -n scripts/x.sh",  # reads it for mistakes
    "bash -c 'echo hi' scripts/x.sh",
    "cat scripts/x.sh",
    "bash scripts/missing.sh",
    "fish scripts/x.sh",
])
def test_a_script_not_run_or_not_there_is_not_read(project, command):
    write(project, "scripts/x.sh", HOME_WIPE)
    assert judge(project, command).decision is None


def test_a_file_run_directly_is_read_only_when_it_is_a_shell_script(project):
    write(project, "scripts/tool", "#!/usr/bin/env python3\nimport os\n# rm -rf ~/\n")
    write(project, "scripts/run", HOME_WIPE)
    assert judge(project, "./scripts/tool").decision is None
    assert judge(project, "./scripts/run").decision == "ask"


def test_a_long_script_is_not_read(project):
    write(project, "scripts/x.sh", HOME_WIPE + "# " + "x" * (64 * 1024) + "\n")
    assert judge(project, "bash scripts/x.sh").decision is None


def test_a_script_that_names_itself_in_an_alias_or_on_a_remote_is_read_once(project):
    write(project, "x.sh", "git config alias.a '!bash x.sh'\ngit config alias.b '!bash x.sh'\n"
                           "ssh h 'bash x.sh'\n" + HOME_WIPE)
    started = time.monotonic()
    v = judge(project, "bash x.sh")
    assert time.monotonic() - started < 5
    assert "script.refused" in {f.rule for f in v.findings}


def test_a_remote_line_does_not_read_this_computers_file(project):
    write(project, "x.sh", HOME_WIPE)
    assert "script.refused" not in {f.rule for f in judge(project, "ssh host 'bash x.sh'").findings}


def test_bash_s_runs_stdin_not_the_file_named(project):
    write(project, "x.sh", HOME_WIPE)
    assert judge(project, "bash -s x.sh < /dev/null").decision is None


def test_each_folder_the_line_may_be_in_is_read(project):
    write(project, "x.sh", "#!/bin/sh\necho hi\n")
    write(project, "scripts/x.sh", HOME_WIPE)
    assert judge(project, "cd scripts && bash x.sh").decision == "ask"


def test_a_script_on_another_computer_is_not_looked_for():
    v = evaluate("bash //nohost-zz9-boxdawn/share/x.sh; cd //nohost-zz9-boxdawn/s && bash y.sh",
                 cwd="C:\\proj", home="C:\\Users\\me", rules=RULES)
    assert "script.refused" not in {f.rule for f in v.findings}


def test_a_script_too_slow_to_read_is_left_unread(project):
    # Many `cd`s make each later path count against every folder: slow to judge.
    write(project, "x.sh", "".join(f"cd d{i}\nrm -rf x{i}\n" for i in range(2500)) + "rm -rf ~/\n")
    started = time.monotonic()
    v = judge(project, "bash x.sh")
    assert time.monotonic() - started < 4
    assert "script.refused" not in {f.rule for f in v.findings}


def test_a_script_it_runs_is_not_followed(project):
    write(project, "scripts/x.sh", "#!/bin/bash\nbash scripts/y.sh\n")
    write(project, "scripts/y.sh", HOME_WIPE)
    assert judge(project, "bash scripts/x.sh").decision is None
    assert judge(project, "bash scripts/y.sh").decision == "ask"
