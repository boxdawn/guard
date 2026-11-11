"""Every reason the guard can give has a Korean line, and the setting reaches the output."""
from __future__ import annotations

import ast
import json
import os
import re

import pytest

from boxdawn_guard import command_guard, command_hook, messages_ko, powershell_guard

SAID = ("a path known only at run time", "`x` outside the project")


def rendered(node):
    """The reason as text, with X for each value; `said` is one of its two sentences."""
    if isinstance(node, ast.Constant):
        return [node.value]
    if isinstance(node, ast.FormattedValue):
        return list(SAID) if isinstance(node.value, ast.Name) and node.value.id == "said" else ["X"]
    if isinstance(node, ast.JoinedStr):
        texts = [""]
        for part in node.values:
            texts = [t + r for t in texts for r in rendered(part)]
        return texts
    return []


def reasons():
    for module in (command_guard, powershell_guard):
        for node in ast.walk(ast.parse(open(module.__file__, encoding="utf-8").read())):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "flag":
                yield from rendered(node.args[2])


def test_the_source_has_reasons_to_check():
    assert len(list(reasons())) > 90


@pytest.mark.parametrize("reason", sorted(set(reasons())))
def test_every_reason_has_a_korean_line(reason):
    said = messages_ko.translate(reason)
    assert said != reason
    assert re.search("[가-힣]", said)
    assert "{" not in said


@pytest.mark.parametrize("reason", [
    "team rule r12: ask the DBA first",
    "team rule r12 on `psql`",
    "team rule r12: ask the DBA first (a value is known only at run time)",
    "team rule r12 on `psql` (a value is known only at run time)",
    "nobody is present to approve it",
])
def test_the_reasons_built_elsewhere_have_a_korean_line(reason):
    assert re.search("[가-힣]", messages_ko.translate(reason))


def test_values_are_kept():
    said = messages_ko.translate("`rm` reaches outside the project: `/etc/x`")
    assert "`rm`" in said and "`/etc/x`" in said


def test_a_reason_not_in_the_table_stays_english():
    assert messages_ko.translate("something new") == "something new"


def payload(command):
    return {"tool_name": "Bash", "tool_input": {"command": command}, "cwd": "/work/proj", "permission_mode": "default"}


def test_english_is_the_default(monkeypatch):
    monkeypatch.delenv("CLAUDE_PLUGIN_OPTION_LANGUAGE", raising=False)
    out = command_hook.decide(payload("rm -rf /etc/x"))["hookSpecificOutput"]
    assert out["permissionDecisionReason"].isascii()


@pytest.mark.parametrize("choice", [None, "", "Auto"])
def test_with_no_choice_a_korean_system_gets_korean(monkeypatch, choice):
    monkeypatch.setattr(command_hook, "_system_is_korean", lambda: True)
    if choice is None:
        monkeypatch.delenv("CLAUDE_PLUGIN_OPTION_LANGUAGE", raising=False)
    else:
        monkeypatch.setenv("CLAUDE_PLUGIN_OPTION_LANGUAGE", choice)
    out = command_hook.decide(payload("rm -rf /etc/x"))["hookSpecificOutput"]
    assert out["permissionDecision"] == "deny"
    assert re.search("[가-힣]", out["permissionDecisionReason"])


def test_a_chosen_language_wins_over_the_system(monkeypatch):
    monkeypatch.setattr(command_hook, "_system_is_korean", lambda: True)
    monkeypatch.setenv("CLAUDE_PLUGIN_OPTION_LANGUAGE", "English")
    assert command_hook.decide(payload("rm -rf /etc/x"))["hookSpecificOutput"]["permissionDecisionReason"].isascii()
    monkeypatch.setattr(command_hook, "_system_is_korean", lambda: False)
    monkeypatch.setenv("CLAUDE_PLUGIN_OPTION_LANGUAGE", messages_ko.KOREAN)
    assert re.search("[가-힣]", command_hook.decide(payload("rm -rf /etc/x"))["hookSpecificOutput"]["permissionDecisionReason"])


@pytest.mark.parametrize("env, korean", [
    ({"LANG": "ko_KR.UTF-8"}, True), ({"LANG": "en_US.UTF-8"}, False), ({}, False),
    ({"LC_ALL": "C", "LANG": "ko_KR.UTF-8"}, False), ({"LC_MESSAGES": "ko_KR", "LANG": "en_US"}, True),
])
def test_the_system_language_off_windows_is_read_from_the_locale(monkeypatch, env, korean):
    monkeypatch.undo()  # the real function, not the fixture's stand-in
    monkeypatch.setattr(command_hook.os, "name", "posix")
    for name in ("LC_ALL", "LC_MESSAGES", "LANG"):
        monkeypatch.delenv(name, raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    assert command_hook._system_is_korean() is korean


def test_korean_changes_the_words_and_not_the_decision(monkeypatch):
    monkeypatch.delenv("CLAUDE_PLUGIN_OPTION_LANGUAGE", raising=False)
    english = command_hook.decide(payload("rm -rf /etc/x"))["hookSpecificOutput"]
    monkeypatch.setenv("CLAUDE_PLUGIN_OPTION_LANGUAGE", messages_ko.KOREAN)
    korean = command_hook.decide(payload("rm -rf /etc/x"))["hookSpecificOutput"]
    assert korean["permissionDecision"] == english["permissionDecision"] == "deny"
    assert re.search("[가-힣]", korean["permissionDecisionReason"])
    json.dumps(korean)  # the hook prints it escaped, so a cp949 console cannot break it
