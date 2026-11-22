"""`time read X` is `read X`, as `command read X` already was: it may change `X` unseen. IFS
set without `IFS=` (`for IFS in /`, `printf -v IFS /`) splits words differently, as `IFS=`
does. Before, both kept the line's values, so `rm -rf $X` was judged with a value it may not
have. And `$APPDATA`, `$LOCALAPPDATA` are read from the hook's environment like `$TEMP`.
"""
from __future__ import annotations

import pytest

pytest.importorskip("tree_sitter_bash")

from boxdawn_guard.command_guard import evaluate  # noqa: E402
from boxdawn_guard.command_rules_source import default_command_rules  # noqa: E402

RULES = default_command_rules()


def bash(command, known_env=None):
    return evaluate(command, cwd="/work/proj", home="/home/me", rules=RULES, known_env=known_env)


def seen(verdict):
    return verdict.decision, sorted({f.rule for f in verdict.findings})


@pytest.mark.parametrize("command", [
    "X=/work/proj/a; time read X <<< /etc; rm -rf $X",
    "X=/work/proj/a; time -p read X <<< /etc; rm -rf $X",
    "X=/work/proj/a; time eval 'X=/etc'; rm -rf $X",
    "X=/work/proj/a; time printf -v X /etc; rm -rf $X",
    "T=time; X=/work/proj/a; $T read X <<< /etc; rm -rf $X",
    "for d in x; do time read d <<< /etc; rm -rf $d; done",
])
def test_time_in_front_of_a_builtin_is_that_builtin(command):
    decision, rules = seen(bash(command))
    assert decision == "deny" and "rm.runtime" in rules, rules


@pytest.mark.parametrize("command", [
    "C=eval/; for IFS in /; do :; done; $C 'rm -rf ~'",
    "C=eval/; printf -v IFS /; $C 'rm -rf ~'",
    # a review: a redirect or `wait -p` puts a number in IFS, which splits `eval1`
    "exec {IFS}>/dev/null; C=eval1; $C 'rm -rf ~'",
    ": {IFS}>/dev/null; C=eval1; $C 'rm -rf ~'",
    "sleep 0 & wait -n -p IFS; C=eval1; $C 'rm -rf ~'",
])
def test_ifs_changed_any_way_drops_the_values(command):
    assert seen(bash(command)) == ("ask", ["name.runtime"])


def test_time_of_a_program_is_unchanged():
    assert seen(bash("X=/work/proj/a; time python x.py; rm -rf $X")) == (None, [])


APPDATA = {"APPDATA": "C:\\Users\\me\\AppData\\Roaming", "LOCALAPPDATA": "C:\\Users\\me\\AppData\\Local"}


@pytest.mark.parametrize("command", [
    'C="$APPDATA/npm/copilot.cmd"; "$C" plugin --help',
    '"$LOCALAPPDATA/Programs/cursor/Cursor.exe" --version',
])
def test_appdata_is_known_when_the_hook_passes_it(command):
    assert seen(bash(command)) == ("ask", ["name.runtime"])
    assert seen(bash(command, known_env=APPDATA)) == (None, [])


def test_the_hook_passes_appdata(monkeypatch):
    from boxdawn_guard import command_hook
    passed = {}
    real = command_hook.evaluate

    def spy(command, *, known_env, **where):
        passed.update(known_env)
        return real(command, known_env=known_env, **where)

    monkeypatch.setattr(command_hook, "evaluate", spy)
    monkeypatch.delenv("CLAUDE_PLUGIN_DATA", raising=False)
    monkeypatch.setenv("APPDATA", "C:\\Users\\me\\AppData\\Roaming")
    monkeypatch.setenv("LOCALAPPDATA", "C:\\Users\\me\\AppData\\Local")
    command_hook.decide({"tool_name": "Bash", "tool_input": {"command": "echo hi"}, "cwd": "/work/proj"})
    assert passed["APPDATA"] == "C:\\Users\\me\\AppData\\Roaming"
    assert passed["LOCALAPPDATA"] == "C:\\Users\\me\\AppData\\Local"
