"""`for n in 1 2 3; do … "$n" …; done`: when every value is written out, the body is judged
once for each value, with the variable set to it there. Before, the variable was unknown,
so a redirect asked and a delete was refused even when every value is ordinary. A loop
the shell could give other values, or whose body could change its variable, is judged
as before: its variable unknown.
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
    'for n in 1 2 3; do echo "item $n" > "note_$n.txt"; done',
    'for f in a.txt b.txt; do rm -f "$f"; done',
    'for n in 1 2; do for m in a b; do echo > "o_$n$m.txt"; done; done',
    "for p in pricing terms; do curl -s https://example.com/$p > \"$p.html\"; done",
])
def test_ordinary_values_get_no_decision(command):
    assert seen(bash(command)) == (None, [])


@pytest.mark.parametrize("command, written_out", [
    ('for d in build /etc; do rm -rf "$d"; done', "rm -rf build; rm -rf /etc"),
    ('for d in build "/home/me"; do rm -rf $d; done', "rm -rf build; rm -rf /home/me"),
])
def test_each_value_is_judged_as_written_out(command, written_out):
    assert seen(bash(command)) == seen(bash(written_out))


@pytest.mark.parametrize("command", [
    'for d in a b; do d=/etc; rm -rf "$d"; done',
    'for d in "a /etc"; do rm -rf $d; done',            # split where used unquoted
    'for f in *.txt; do rm -f "$f"; done',
    'for d in build dist ~; do rm -rf "$d"; done',
    'for p in $LIST; do rm -rf "$p"; done',
    'for d in a b; do read d; rm -rf "$d"; done',
    'for d in a b; do printf -v d /etc; rm -rf "$d"; done',
    'for d in a b; do unset d; rm -rf "$d"/x; done',
    'for d in a b; do declare d=/etc; rm -rf "$d"; done',
    'for d in a b; do for d in /etc; do :; done; rm -rf "$d"; done',
    'for d in a b; do command read d; rm -rf "$d"; done',
    'for x in 1 2; do echo $x; done; rm -rf "$x"',       # after the loop: unknown, as before
])
def test_these_are_still_refused(command):
    decision, rules = seen(bash(command))
    assert decision == "deny" and "rm.runtime" in rules, rules


@pytest.mark.parametrize("command", [
    "for c in cd; do $c /etc; rm -rf x; done",           # the value is what runs
    'for n in {1..3}; do echo > "/etc/x$n"; done',
])
def test_these_still_ask(command):
    assert bash(command).decision == "ask"


def test_a_long_list_is_judged_as_before():
    values = " ".join(f"v{i}" for i in range(17))
    assert bash(f'for d in {values}; do rm -rf "$d"; done').decision == "deny"
