"""Findings: the part of a verdict that may leave the machine (decision ④,
2026-10-29: a blocked-command record carries count, rule id, deny/ask and a
target class, never the command or a path). Reasons stay local.
"""
from __future__ import annotations

import ast
import pathlib

import pytest

pytest.importorskip("tree_sitter_bash")

from boxdawn_guard import command_guard, powershell_guard  # noqa: E402
from boxdawn_guard.command_guard import RULE_IDS, TARGETS, Finding, evaluate  # noqa: E402
from boxdawn_guard.tests.test_command_guard import ASK, CWD, DENY, HOME, KNOWN_ENV, NONE, RULES  # noqa: E402

# Both judges raise flags; a rule only the PowerShell one raises is still live.
SOURCES = [pathlib.Path(m.__file__).read_text(encoding="utf-8") for m in (command_guard, powershell_guard)]


def verdict(command: str, unattended: bool = False):
    return evaluate(command, cwd=CWD, home=HOME, rules=RULES, unattended=unattended,
                    known_env=KNOWN_ENV)


def _flag_rule_ids() -> list[str]:
    ids = []
    for source in SOURCES:
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.Call) and getattr(node.func, "attr", None) == "flag":
                arg = node.args[1]
                assert isinstance(arg, ast.Constant) and isinstance(arg.value, str), ast.dump(arg)
                ids.append(arg.value)
    return ids


def test_every_flag_names_a_registered_rule():
    ids = _flag_rule_ids()
    assert len(ids) >= 51
    assert set(ids) <= RULE_IDS


def test_no_registered_rule_is_dead():
    """An id nobody raises is a rule a dashboard would show and never see."""
    assert RULE_IDS <= set(_flag_rule_ids())


@pytest.mark.parametrize("command", DENY + ASK)
@pytest.mark.parametrize("unattended", [False, True])
def test_findings_hold_only_closed_values(command, unattended):
    v = verdict(command, unattended)
    assert v.findings, command
    assert len(v.findings) == len(v.reasons) - (1 if v.escalated else 0)
    for f in v.findings:
        assert f.rule in RULE_IDS
        assert f.level in ("deny", "ask")
        assert f.target is None or f.target in TARGETS


@pytest.mark.parametrize("command", DENY + ASK)
def test_no_path_or_command_text_rides_in_a_finding(command):
    """The literal check behind the closed sets: nothing the agent typed
    appears in what would be sent, beyond words that are themselves rule ids."""
    v = verdict(command)
    words = {w for w in command.replace("/", " ").split() if len(w) > 2}
    allowed = {p for r in RULE_IDS for p in r.split(".")} | TARGETS | {"deny", "ask"}
    for f in v.findings:
        for value in (f.rule, f.level, f.target or ""):
            assert "/" not in value and "\\" not in value
            for w in words - allowed:
                assert w not in value.split("."), (command, f)


@pytest.mark.parametrize("command", NONE)
def test_ordinary_work_has_no_findings(command):
    assert verdict(command).findings == ()


@pytest.mark.parametrize("command, expected", [
    ("dd if=/dev/zero of=$HOME/probe.bin bs=1 count=1", Finding("dd.outside", "deny", "outside")),
    ("dd if=/dev/zero of=/dev/sda", Finding("dd.disk_device", "deny", "disk_device")),
    ("truncate -s 0 victim.txt", Finding("truncate.file", "ask", "project")),
    ("rm -rf /etc", Finding("rm.outside", "deny", "outside")),
    ("rm -rf .", Finding("rm.project_root", "ask", "project_root")),
    ("git push --force origin main", Finding("git.push_force", "deny", None)),
    ("echo x > /etc/hosts", Finding("redirect.outside", "ask", "outside")),
])
def test_known_commands_map_to_their_finding(command, expected):
    assert expected in verdict(command).findings


def test_escalation_is_a_flag_not_a_rewritten_finding():
    """Nobody present turns the decision into deny; the finding keeps the
    rule's own level so a dashboard can tell 'deny' from 'ask, unattended'."""
    v = verdict("truncate -s 0 victim.txt", unattended=True)
    assert v.decision == "deny" and v.escalated
    assert v.findings == (Finding("truncate.file", "ask", "project"),)
    assert not verdict("truncate -s 0 victim.txt").escalated


def test_flag_refuses_an_unregistered_rule_or_target():
    judge = command_guard._Judge(cwd=CWD, home=HOME, rules=RULES)
    with pytest.raises(ValueError):
        judge.flag("deny", "not.a.rule", "x")
    with pytest.raises(ValueError):
        judge.flag("deny", "rm.outside", "x", "/etc")
