"""Statements fed to a database client on stdin (`psql <<< '…'`, `mysql <<EOF … EOF`)
are checked as `-c` ones are: a destructive one is denied here, and asks when the
client runs on another machine or in a container (`ssh host psql <<< …`). Through
`sudo` the client still reads that stdin.
"""
from __future__ import annotations

import pytest

pytest.importorskip("tree_sitter_bash")

from boxdawn_guard.command_guard import evaluate  # noqa: E402
from boxdawn_guard.command_rules_source import default_command_rules  # noqa: E402

RULES = default_command_rules()


def bash(command, unattended=False):
    return evaluate(command, cwd="/work/proj", home="/home/me", rules=RULES, unattended=unattended,
                    known_env={"TEMP": "/tmp", "TMPDIR": "/tmp"})


def seen(verdict):
    return verdict.decision, sorted({f.rule for f in verdict.findings})


DENIED = [
    "psql <<< 'DROP TABLE users'",
    "psql -d app <<< 'drop table users;'",
    "mysql app <<EOF\nDELETE FROM users;\nEOF\n",
    "sqlite3 app.db <<< 'DROP TABLE t'",
    "redis-cli <<< FLUSHALL",
    "psql 0<<< 'DROP TABLE users'",
]


@pytest.mark.parametrize("command", DENIED)
def test_a_destructive_statement_on_stdin_is_denied(command):
    decision, rules = seen(bash(command))
    assert decision == "deny", rules
    assert "db.destructive" in rules


def test_it_is_denied_as_the_same_statement_given_with_c():
    assert seen(bash("psql <<< 'DROP TABLE users'")) == seen(bash("psql -c 'DROP TABLE users'"))


def test_through_sudo_the_client_reads_it_too():
    decision, rules = seen(bash("sudo -u postgres psql <<< 'DROP DATABASE app'"))
    assert decision == "deny"
    assert "db.destructive" in rules


@pytest.mark.parametrize("command", [
    "ssh host psql <<< 'DROP TABLE t'",
    "ssh host 'psql app' <<< 'DROP TABLE t'",
    "docker exec -i db psql <<< 'DROP TABLE t'",
])
def test_on_another_machine_it_asks(command):
    decision, rules = seen(bash(command))
    assert decision == "ask", rules
    assert {"db.destructive", "remote.run"} <= set(rules)


@pytest.mark.parametrize("command", [
    "psql <<< 'SELECT * FROM users'",
    "ssh host psql <<< 'SELECT 1'",
    "mysql app <<EOF\nSELECT 1;\nEOF\n",
    "psql <<EOF\nDROP TABLE $T;\nEOF\n",   # text known only at run time: as before
])
def test_these_get_no_decision(command):
    assert bash(command).decision is None


def test_a_file_flag_keeps_its_own_ask():
    # the statements are the file's; what is on stdin is not read as them
    assert seen(bash("psql -f x.sql <<< 'DROP TABLE t'")) == ("ask", ["db.file"])
