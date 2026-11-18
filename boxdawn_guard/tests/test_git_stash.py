"""`git stash` takes uncommitted work out of the folder, and `git stash pop`
puts back the newest stash, which may be someone else's: both ask. Reading
the stash list does not.
"""
from __future__ import annotations

import os

import pytest

pytest.importorskip("tree_sitter_bash")

from boxdawn_guard import messages_ko, powershell_guard  # noqa: E402
from boxdawn_guard.command_guard import evaluate  # noqa: E402
from boxdawn_guard.command_rules_source import default_command_rules  # noqa: E402

RULES = default_command_rules()


def judge(command):
    return evaluate(command, cwd="/home/u/proj", home="/home/u", rules=RULES)


@pytest.mark.parametrize("command", [
    "git stash", "git stash -q", "git stash -u", "git stash --include-untracked", "git stash push",
    "git stash push -q src/a.py", "git stash push -m wip -- src/", "git stash save wip", "git stash -k",
    "git stash pop", "git stash pop -q", "git stash pop stash@{1}", "git stash apply", "git stash apply --index", "git stash branch fix stash@{0}",
    "git -C sub stash", "git stash $X",
    "git stash -q && pytest; git stash pop -q",
    "cd repo && git stash -u -q && git switch -q main && pytest && git switch - && git stash pop",
])
def test_stash_and_pop_ask(command):
    v = judge(command)
    assert v.decision == "ask", (command, v.reasons)
    assert {f.rule for f in v.findings} == {"git.stash"}


@pytest.mark.parametrize("command,rules", [
    ("git stash drop", {"git.stash_drop"}),
    ("git stash push && git stash drop", {"git.stash", "git.stash_drop"}),
    ("git stash && git clean -fd", {"git.stash", "git.clean"}),
])
def test_drop_keeps_its_own_rule(command, rules):
    assert {f.rule for f in judge(command).findings} == rules


@pytest.mark.parametrize("command", [
    "git stash list", "git stash show", "git stash show -p stash@{0}", "git stash --help", "git stash -h",
    "git stash create", "git log --oneline -- stash", "echo git stash",
])
def test_reading_the_stash_has_no_decision(command):
    assert judge(command).decision is None, (command, judge(command).reasons)


def test_korean_reasons():
    for command in ("git stash", "git stash pop"):
        for reason in judge(command).reasons:
            assert messages_ko.translate(reason) != reason, reason


_helper = os.environ.get("BDX_PSPARSE")


@pytest.mark.skipif(not (_helper and os.path.isfile(_helper)), reason="BDX_PSPARSE (bdxpsparse.exe) not built")
@pytest.mark.parametrize("command,decision", [
    ("git stash", "ask"), ("git stash pop", "ask"), ("git stash list", None),
])
def test_powershell_reads_it_the_same(command, decision):
    v = powershell_guard.evaluate_powershell(command, cwd=r"C:\work\proj", home=r"C:\Users\me", rules=RULES)
    assert v.decision == decision, v.reasons
