"""Two shapes that made a line's values unknown for no reason:
- a command named through a quoted variable whose path has a space
  (`C="/c/Program Files/…/chrome.exe"; "$C" …`): quoted, the shell does not split it;
- `printf` without `-v`, which sets nothing; only `printf -v NAME` reassigns, and only NAME.
"""
from __future__ import annotations

import pytest

pytest.importorskip("tree_sitter_bash")

from boxdawn_guard.command_guard import evaluate  # noqa: E402
from boxdawn_guard.command_rules_source import default_command_rules  # noqa: E402

RULES = default_command_rules()


def bash(command):
    return evaluate(command, cwd="/work/proj", home="/home/me", rules=RULES)


def seen(verdict):
    return verdict.decision, sorted({f.rule for f in verdict.findings})


@pytest.mark.parametrize("command", [
    'C="/c/Program Files/Google/Chrome/Application/chrome.exe"; "$C" --headless x.html',
    'S="/c/my tools"; "$S/python.exe" x.py',
    "B=/c/tools/bdxguard.exe; printf '{\"a\":1}' | $B hook",
    "B=/c/tools/bdxguard.exe; printf 'x\\n'; $B --version",
])
def test_these_now_get_no_decision(command):
    assert seen(bash(command)) == (None, [])


def test_a_quoted_name_is_judged_as_what_it_names():
    assert seen(bash('X="/bin/rm"; "$X" -rf ~')) == seen(bash("/bin/rm -rf ~"))


def test_a_printf_keeps_the_other_values_known():
    assert seen(bash("D=/c/out; printf 'x\\n' > \"$D/a.txt\"")) == ("ask", ["redirect.outside"])


@pytest.mark.parametrize("command", [
    'C="/c/Program Files/x.exe"; $C --flag',                       # unquoted: split
    "B=/c/tools/bdxguard.exe; printf -v B '%s' /bin/rm; $B -rf ~",  # B reassigned
    "B=/c/tools/bdxguard.exe; printf -vB '%s' /bin/rm; $B -rf ~",
])
def test_these_still_ask(command):
    decision, rules = seen(bash(command))
    assert decision == "ask" and "name.runtime" in rules, rules


@pytest.mark.parametrize("command", [
    "Y=/work/proj/ok; printf -v Y '%s' /home/me; rm -rf $Y",
    "Y=/work/proj/ok; command printf -v Y '%s' /home/me; rm -rf $Y",
    "Y=/work/proj/ok; printf -v \"$N\" '%s' x; rm -rf $Y",            # which name is not known
    # a review found these: every `-v` counts, and an unknown word before the format may hold one
    "Y=/work/proj/ok; printf -v S -v Y /; rm -rf \"$Y\"",
    "Y=/work/proj/ok; printf -v S -vY /; rm -rf \"$Y\"",
    "Y=/work/proj/ok; command printf -v S -v Y /; rm -rf \"$Y\"",
    "Y=/work/proj/ok; printf $(echo -vY /) x; rm -rf \"$Y\"",
])
def test_printf_v_makes_its_name_unknown(command):
    decision, rules = seen(bash(command))
    assert decision == "deny" and "rm.runtime" in rules, rules
