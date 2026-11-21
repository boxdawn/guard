"""After an assignment (`PYTHONPATH=. C:/tools/python.exe -m pytest`) the bash grammar split the
drive letter off as a stray name, read the command as `:/tools/python.exe`, and the line asked
(`parse.unreadable`). The letter is now read as Git Bash reads the path (`/c/tools/…`), so the
command is judged as what it is.
"""
from __future__ import annotations

import pytest

pytest.importorskip("tree_sitter_bash")

from boxdawn_guard.command_guard import evaluate  # noqa: E402
from boxdawn_guard.command_rules_source import default_command_rules  # noqa: E402

RULES = default_command_rules()


def bash(command):
    return evaluate(command, cwd="C:/Users/me/proj", home="C:/Users/me", rules=RULES)


def seen(verdict):
    return verdict.decision, sorted({f.rule for f in verdict.findings})


@pytest.mark.parametrize("command", [
    "PYTHONPATH=. C:/tools/python.exe -m pytest tests -q",
    'A="$PWD/x" C:/tools/p -m x',
    "A=1 B=2 C:/tools/p x",
    "A=1 D:\\tools\\p x",
])
def test_a_program_after_an_assignment_gets_no_decision(command):
    assert seen(bash(command)) == (None, [])


@pytest.mark.parametrize("command, written", [
    ("A=1 C:/bin/rm -rf ~", "/c/bin/rm -rf ~"),
    ("A=1 C:/tools/p x; rm -rf ~", "rm -rf ~"),
    ("A=1 C:/tools/bash -c 'rm -rf ~'", "/c/tools/bash -c 'rm -rf ~'"),
])
def test_it_is_judged_as_the_same_line_written_the_git_bash_way(command, written):
    assert seen(bash(command)) == seen(bash(written))


def test_a_drive_path_as_an_argument_is_read_as_before():
    assert seen(bash("A=1 rm -rf C:/Users/me/other")) == seen(bash("rm -rf C:/Users/me/other"))
