"""A command named through a variable set earlier on the line (`S=/c/tools; $S/python.exe x.py`)
is judged as the command it names. Before, any command whose name was not written out
made every value on the line unknown (it might be `eval` or `read`), its own name too,
so the line asked. Now its name is read from the values set before it, and the values
are dropped only when that name could still reassign them, or is not one word.
"""
from __future__ import annotations

import pytest

pytest.importorskip("tree_sitter_bash")

from boxdawn_guard.command_guard import evaluate  # noqa: E402
from boxdawn_guard.command_rules_source import default_command_rules  # noqa: E402

RULES = default_command_rules()


def bash(command, unattended=False):
    return evaluate(command, cwd="/work/proj", home="/home/me", rules=RULES, unattended=unattended)


def seen(verdict):
    return verdict.decision, sorted({f.rule for f in verdict.findings})


@pytest.mark.parametrize("command", [
    "S=/c/tools; $S/python.exe x.py",
    "S=/c/tools; PYTHONPATH=. $S/python.exe x.py",
    "S=/c/tools && $S/python.exe x.py",
    'S=/c/tools; "$S/python.exe" x.py',
    "PY=/c/tools/python.exe; $PY x.py",
    "export S=/c/tools; $S/python.exe x.py",
    "S=/c/tools; cd $S/work && PYTHONPATH=. $S/python.exe ../probe.py",
    "S=/c/tools; command $S/python.exe x.py",
])
def test_a_known_program_named_through_a_variable_gets_no_decision(command):
    assert seen(bash(command)) == (None, [])


@pytest.mark.parametrize("command, plain", [
    ("X=rm; $X -rf ~", "rm -rf ~"),
    ("X=/bin/rm; $X -rf ~", "/bin/rm -rf ~"),
    ("S=/c/tools; $S/bash -c 'rm -rf ~'", "/c/tools/bash -c 'rm -rf ~'"),
    ("S=/c/tools; X=$S/python.exe; $X -c 'import shutil; shutil.rmtree(\"/\")'",
     "/c/tools/python.exe -c 'import shutil; shutil.rmtree(\"/\")'"),
])
def test_it_is_judged_as_the_command_it_names(command, plain):
    assert seen(bash(command)) == seen(bash(plain))


def test_the_rest_of_the_line_keeps_its_values():
    # before, the unknown name dropped `D` too, and the redirect was only "known at run time"
    decision, rules = seen(bash("S=/c/tools; D=/c/out; $S/python.exe x.py > $D/log.txt"))
    assert decision == "ask" and rules == ["redirect.outside"]


@pytest.mark.parametrize("command", [
    'C="rm -rf"; $C ~',                         # split by the shell: runs `rm -rf ~`
    "X=; $X rm -rf ~",                          # empty: runs `rm -rf ~`
    "S=/c/*; $S/x",                             # globbed
    'S="/c/my tools"; $S/python.exe x.py',      # unquoted with a space: split by the shell
    "X=eval; $X 'rm -rf ~'",                    # a builtin that reassigns
    "X=read; $X S; $S/x",
    "if true; then S=/c/tools; fi; $S/python.exe x.py",   # may not have run
    "S=/c/tools; S=$(pwd); $S/python.exe",      # known only at run time
    "for f in a b; do $f; done",
    "$EDITOR notes.txt",
])
def test_these_still_ask_as_before(command):
    decision, rules = seen(bash(command))
    assert decision == "ask" and "name.runtime" in rules, rules


@pytest.mark.parametrize("command", [
    # a review found these: a builtin named through a variable changes a value in this shell
    "Y=/work/proj/ok; X=export; $X Y=/home/me; rm -rf $Y",
    "Y=/work/proj/ok; X=export; $X Y=/home/me && rm -rf $Y",
    "Y=echo; X=export; $X Y=rm; $Y -rf ~",
    "Y=/work/proj/ok; T=trap; $T 'Y=/home/me' DEBUG; rm -rf $Y",
    "E=eval; $E 'rm -rf ~'",
    "S=x; P=printf; $P -v S /home/me; rm -rf $S",
])
def test_a_builtin_named_through_a_variable_keeps_the_values_unknown(command):
    assert bash(command).decision in ("ask", "deny")


@pytest.mark.parametrize("command", [
    # older shapes, closed with the same change: `export` and `trap` reassign
    "Y=/work/proj/ok; command export Y=/home/me; rm -rf $Y",
    "Y=/work/proj/ok; trap 'Y=/home/me' DEBUG; rm -rf $Y",
])
def test_command_export_and_trap_make_the_values_unknown(command):
    assert bash(command).decision in ("ask", "deny")


@pytest.mark.parametrize("command", ['C="rm -rf"; $C ~', "X=; $X rm -rf ~", "X=rm; $X -rf ~"])
def test_unattended_none_of_them_runs(command):
    assert bash(command, unattended=True).decision == "deny"
