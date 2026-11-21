"""`bash < x.sh`: a shell given no code or script of its own runs its stdin, so
the file on stdin is read as `bash x.sh` reads it (test_read_shell_scripts.py):
only what would be refused asks, under `script.refused`.
"""
from __future__ import annotations

import os

import pytest

pytest.importorskip("tree_sitter_bash")

from boxdawn_guard.command_guard import evaluate  # noqa: E402
from boxdawn_guard.command_rules_source import default_command_rules  # noqa: E402

RULES = default_command_rules()
HOME_WIPE = "#!/bin/bash\nset -e\nrm -rf ~/\n"


def judge(project, command, unattended=False):
    return evaluate(command, cwd=str(project), home=os.path.expanduser("~"), rules=RULES, unattended=unattended)


def rules_of(verdict):
    return {f.rule for f in verdict.findings}


@pytest.fixture
def project(tmp_path):
    p = tmp_path / "proj"
    (p / "scripts").mkdir(parents=True)
    for name, text in [("wipe.sh", HOME_WIPE), ("ok.sh", "#!/bin/bash\necho hi\n"),
                       ("tmp.sh", '#!/bin/bash\nrm -rf "$TMP"\n')]:
        (p / "scripts" / name).write_text(text, encoding="utf-8", newline="\n")
    return p


@pytest.mark.parametrize("command", [
    "bash < scripts/wipe.sh", "sh < scripts/wipe.sh", "zsh < scripts/wipe.sh", "sh 0< scripts/wipe.sh",
    "bash -e < scripts/wipe.sh", "bash -s < scripts/wipe.sh", "bash -s arg < scripts/wipe.sh",
    "sudo bash < scripts/wipe.sh", "cd scripts && bash < wipe.sh", "bash < scripts/wipe.sh > out.txt",
    "echo start; bash < scripts/wipe.sh",
])
def test_a_script_on_stdin_that_would_wipe_the_home_folder_asks(project, command):
    v = judge(project, command)
    assert v.decision == "ask", v.reasons
    assert {"script.refused", "rm.outside"} <= rules_of(v), v.reasons


def test_unattended_it_is_denied(project):
    assert judge(project, "bash < scripts/wipe.sh", unattended=True).decision == "deny"


@pytest.mark.parametrize("command", [
    "bash < scripts/ok.sh",
    "bash < scripts/tmp.sh",                   # a delete of a path known only at run time does not count
    "bash -n < scripts/wipe.sh",               # reads it for mistakes
    "bash scripts/ok.sh < scripts/wipe.sh",    # the script is ok.sh; wipe.sh is its input
    "bash -c 'echo hi' < scripts/wipe.sh",     # the code is on the line
    "cat < scripts/wipe.sh",
    "bash 3< scripts/wipe.sh",                 # not stdin
    "bash < scripts/missing.sh",
])
def test_these_get_no_decision(project, command):
    v = judge(project, command)
    assert "script.refused" not in rules_of(v), v.reasons
    assert v.decision is None, v.reasons
