"""`git checkout`, `git restore` and `git switch` that overwrite edits in a
folder or in many files ask, the way `git checkout -- .` always did. One named
file (`git checkout -- a.py`) is how an agent undoes its own edit: no decision.
"""
from __future__ import annotations

import os

import pytest

pytest.importorskip("tree_sitter_bash")

from boxdawn_guard import powershell_guard  # noqa: E402
from boxdawn_guard.command_guard import evaluate  # noqa: E402
from boxdawn_guard.command_rules_source import default_command_rules  # noqa: E402

RULES = default_command_rules()


def judge(command):
    return evaluate(command, cwd="/home/u/proj", home="/home/u", rules=RULES)


@pytest.mark.parametrize("command", [
    "git checkout HEAD -- src", "git checkout -- src", "git checkout -q -- boxdawn_guard",
    "git checkout HEAD~3 -- src lib", "git checkout --theirs -- src", "git checkout -- lib/x",
    "git checkout -- '*.py'", "git checkout -- *.py", "git checkout main -- Makefile",
    "git checkout .", "git checkout src/", "git checkout HEAD .", "git checkout HEAD src",
    "git checkout --ours .", "git checkout --pathspec-from-file=list.txt",
    "git restore src", "git restore --source=HEAD~2 src", "git restore -s HEAD src lib",
    "git restore --worktree src", "git restore -SW src", "git restore '*.py'", "git restore -sSTABLE .", "git restore -WsSTAGE src",
    "git switch -f main", "git switch --discard-changes main", "git switch -fq main", "git checkout -qf main",
    "git checkout ./src", "git restore -sSTABLE src/",
])
def test_a_folder_or_many_files_ask(command):
    v = judge(command)
    assert v.decision == "ask", (command, v.reasons)
    assert {f.rule for f in v.findings} == {"git.discard_changes"}


@pytest.mark.parametrize("command", [
    "git checkout -- a.py", "git checkout -- src/a.py", "git checkout HEAD~1 a.py",
    "git checkout HEAD -- .gitignore", "git restore a.py", "git restore -s HEAD a.py b.py",
    "git restore --staged src", "git restore -S .",
    "git checkout main", "git checkout feature/x", "git checkout -b feat", "git checkout -b feat origin/feat",
    "git checkout -B feat main", "git checkout --orphan gh-pages", "git checkout -t origin/x",
    "git switch main", "git switch -c feat", "git switch -",
    'git checkout "$BRANCH"', 'git checkout "$(git rev-parse --abbrev-ref HEAD)"', "git checkout src",
])
def test_one_file_or_a_branch_has_no_decision(command):
    assert judge(command).decision is None, (command, judge(command).reasons)


@pytest.fixture
def project(tmp_path):
    for d in ("src/components", ".github/workflows", "lib/v1.2", "sub/lib"):
        (tmp_path / d).mkdir(parents=True)
    for f in ("Makefile", "bin/run", ".husky/pre-commit", "sub/Dockerfile"):
        (tmp_path / f).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / f).write_text("x")
    return str(tmp_path)


@pytest.mark.parametrize("command", [
    "git checkout src", "git checkout HEAD -- .github", "git restore .github", "git restore lib/v1.2",
    "git checkout src/components", "git -C sub checkout -- lib", "git restore Makefile src",
    "git checkout src Makefile", "git restore ':(top)lib/v1.2'", "git restore ':!Makefile'",
    "git checkout -- ':(exclude)Makefile'",
])
def test_a_folder_on_disk_asks(project, command):
    v = evaluate(command, cwd=project, home=project + "/nobody", rules=RULES)
    assert v.decision == "ask", (command, v.reasons)


@pytest.mark.parametrize("command", [
    "git checkout HEAD -- Makefile", "git restore Makefile", "git restore bin/run", "git restore .husky/pre-commit",
    "git -C sub restore Dockerfile", "git checkout main",
])
def test_a_file_on_disk_has_no_decision(project, command):
    v = evaluate(command, cwd=project, home=project + "/nobody", rules=RULES)
    assert v.decision is None, (command, v.reasons)


@pytest.mark.parametrize("command", [
    "cd sub && git restore Makefile", "git --work-tree=sub restore Makefile", "git --work-tree sub restore Makefile",
])
def test_the_disk_is_not_read_from_another_folder(project, tmp_path, command):
    # `./Makefile` is a file, `sub/Makefile` a folder: the disk here says nothing about there.
    (tmp_path / "sub" / "Makefile").mkdir()
    v = evaluate(command, cwd=project, home=project + "/nobody", rules=RULES)
    assert v.decision == "ask", (command, v.reasons)


_helper = os.environ.get("BDX_PSPARSE")


@pytest.mark.skipif(not (_helper and os.path.isfile(_helper)), reason="BDX_PSPARSE (bdxpsparse.exe) not built")
@pytest.mark.parametrize("command,decision", [
    ("git checkout HEAD -- src", "ask"), ("git restore src", "ask"), ("git checkout -- a.py", None),
])
def test_powershell_reads_it_the_same(command, decision):
    v = powershell_guard.evaluate_powershell(command, cwd=r"C:\work\proj", home=r"C:\Users\me", rules=RULES)
    assert v.decision == decision, v.reasons
