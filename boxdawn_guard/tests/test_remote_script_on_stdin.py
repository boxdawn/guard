"""A local file on the stdin of a command run on another machine or in a container
(`ssh host < x.sh`, `docker exec -i c sh < x.sh`) is read here, within the limits a script
is read in, and judged there as text fed on stdin is (`ssh host <<'EOF'`): what would be
refused asks, since the other machine's paths are not this one's.
"""
from __future__ import annotations

import os

import pytest

pytest.importorskip("tree_sitter_bash")

from boxdawn_guard.command_guard import evaluate  # noqa: E402
from boxdawn_guard.command_rules_source import default_command_rules  # noqa: E402

RULES = default_command_rules()


@pytest.fixture
def project(tmp_path):
    p = tmp_path / "proj"
    (p / "scripts").mkdir(parents=True)
    for name, text in [("wipe.sh", "#!/bin/bash\nrm -rf ~/\n"), ("ok.sh", "#!/bin/bash\necho hi\n"),
                       ("drop.sql", "DROP TABLE users;\n")]:
        (p / "scripts" / name).write_text(text, encoding="utf-8", newline="\n")
    return p


def judge(project, command):
    v = evaluate(command, cwd=str(project), home=os.path.expanduser("~"), rules=RULES)
    return v.decision, sorted({f.rule for f in v.findings})


@pytest.mark.parametrize("command", [
    "ssh host < scripts/wipe.sh", "ssh host bash < scripts/wipe.sh", "ssh host 'bash -s' < scripts/wipe.sh",
    "ssh host sh 0< scripts/wipe.sh", "docker exec -i c sh < scripts/wipe.sh",
    "kubectl exec -i pod -- bash < scripts/wipe.sh",
])
def test_a_script_sent_on_stdin_to_a_remote_shell_asks(project, command):
    assert judge(project, command) == ("ask", ["remote.run", "rm.outside"])


def test_it_asks_as_the_same_text_in_a_here_document(project):
    assert judge(project, "ssh host < scripts/wipe.sh")[0] == \
        judge(project, "ssh host <<'EOF'\nrm -rf ~/\nEOF\n")[0]


def test_statements_sent_to_a_remote_database_client_ask(project):
    assert judge(project, "ssh host psql < scripts/drop.sql") == ("ask", ["db.destructive", "remote.run"])


@pytest.mark.parametrize("command", [
    "ssh host < scripts/ok.sh",
    "ssh host cat < scripts/wipe.sh",               # not run as code there
    "ssh host 'cat > /tmp/x' < scripts/wipe.sh",
    "docker exec c sh < scripts/wipe.sh",           # no -i: stdin does not reach it
    "ssh host < scripts/missing.sh",
    "cat < scripts/wipe.sh",                        # not sent anywhere
    "ssh host < scripts/drop.sql",                  # SQL is no shell code
])
def test_these_get_no_decision(project, command):
    assert judge(project, command) == (None, [])
