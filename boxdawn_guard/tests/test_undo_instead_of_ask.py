"""With `undo` on, an ask about git rewriting the files of the project's own repository
(`git reset --hard`, `git checkout -- .`, `git restore .`, `git stash`) is answered by a
snapshot taken there and then: the command goes on with no decision, and the files can be
put back. Anything else on the line, any doubt about which files git reaches, or a
snapshot that is late or leaves a file out keeps the ask. Undo off: nothing changes.
"""
from __future__ import annotations

import os
import shutil
import sys

import pytest

from boxdawn_guard import command_hook, undo
from boxdawn_guard.tests.test_undo import _git, _payload, _write, project  # noqa: F401 - `project` is a fixture

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")

@pytest.fixture(autouse=True)
def _its_own_setting_on(monkeypatch):
    monkeypatch.setenv("CLAUDE_PLUGIN_OPTION_UNDO_INSTEAD_OF_GIT_ASKS", "true")


COVERED = ["git reset --hard", "git reset --hard HEAD", "git checkout -- .", "git restore .", "git checkout .",
           "git stash", "git stash push -u", "git stash pop"]


def _decision(payload):
    out = command_hook.decide(payload)
    return (out or {}).get("hookSpecificOutput", {}).get("permissionDecision")


def _snapshots(project):
    return undo.Store(os.path.realpath(project), os.environ["CLAUDE_PLUGIN_DATA"]).snapshots()


@pytest.mark.parametrize("command", COVERED)
def test_a_snapshot_stands_in_for_the_ask(project, command):
    assert _decision(_payload(project, command)) is None
    assert len(_snapshots(project)) == 1


@pytest.mark.parametrize("command", ["git reset --hard", "git stash"])
def test_with_nobody_there_it_goes_on_too(project, command):
    payload = dict(_payload(project, command), permission_mode="bypassPermissions")
    assert _decision(payload) is None


def test_powershell_too(project):
    assert _decision(_payload(project, "git reset --hard", "PowerShell")) is None


def test_the_work_comes_back_after_reset_hard(project):
    before = open(os.path.join(project, "src", "app.py"), "rb").read()
    payload = _payload(project, "git reset --hard")
    assert _decision(payload) is None
    command_hook._snapshot_before(payload, None)  # as `main` calls it next: no second snapshot
    assert len(_snapshots(project)) == 1
    _git(project, "reset", "-q", "--hard")
    assert open(os.path.join(project, "src", "app.py"), "rb").read() != before
    store = undo.Store(os.path.realpath(project), os.environ["CLAUDE_PLUGIN_DATA"])
    assert store.acquire()
    try:
        store.restore(_snapshots(project)[0]["n"])
    finally:
        store.release()
    assert open(os.path.join(project, "src", "app.py"), "rb").read() == before


@pytest.mark.parametrize("command", [
    "git stash drop", "git stash clear", "git branch -D x", "git clean -fd",     # `.git` itself, or files left out
    "git filter-branch --tree-filter true HEAD", "rm -rf .git",
    "git -C sub reset --hard", "cd sub && git reset --hard",                    # not the project's root
    "git --git-dir=/x/.git reset --hard", "git --work-tree=/x reset --hard",
    "GIT_WORK_TREE=/x git reset --hard", "GIT_DIR=/x/.git git stash",
    "git -c core.worktree=/x reset --hard",
    "git reset --hard; cat .env",                                                # another ask on the line
])
def test_these_still_ask(project, command):
    os.makedirs(os.path.join(project, "sub"), exist_ok=True)
    assert _decision(_payload(project, command)) == "ask"


def test_a_deny_on_the_line_stays_a_deny(project):
    assert _decision(_payload(project, "git reset --hard && rm -rf ~")) == "deny"


def test_undo_off_changes_nothing(project, monkeypatch):
    monkeypatch.setenv("CLAUDE_PLUGIN_OPTION_UNDO", "false")
    assert _decision(_payload(project, "git reset --hard")) == "ask"
    assert _snapshots(project) == []


def test_copilot_has_no_undo_even_by_default(project, monkeypatch):
    # Copilot has no way to list, restore or turn snapshots off: its ask stays an ask.
    from boxdawn_guard import copilot_hook
    monkeypatch.setenv("CLAUDE_PLUGIN_OPTION_UNDO", "")  # on by default; recorded, so put back afterwards
    out = copilot_hook.decide({"toolName": "bash", "toolArgs": {"command": "git reset --hard"}, "cwd": project})
    assert out["permissionDecision"] == "ask"
    assert _snapshots(project) == []


def test_a_git_variable_in_the_environment_keeps_the_ask(project, monkeypatch):
    monkeypatch.setenv("GIT_WORK_TREE", "/elsewhere")
    assert _decision(_payload(project, "git reset --hard")) == "ask"


def test_the_git_variables_claude_code_sets_do_not_count(project, monkeypatch):
    for name in ("GIT_ASKPASS", "GIT_EDITOR", "GIT_TERMINAL_PROMPT"):
        monkeypatch.setenv(name, "x")
    assert _decision(_payload(project, "git reset --hard")) is None


def test_a_folder_inside_a_larger_repository_keeps_the_ask(project, monkeypatch):
    inner = os.path.join(project, "pkg")
    _write(inner, "a.txt", b"x\n")
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", inner)
    assert _decision(_payload(inner, "git reset --hard")) == "ask"


def test_a_line_run_outside_the_project_keeps_the_ask(project, tmp_path):
    other = str(tmp_path / "other")
    os.makedirs(os.path.join(other, ".git"))
    assert _decision(_payload(other, "git reset --hard")) == "ask"


def test_a_snapshot_that_leaves_a_file_out_keeps_the_ask(project, monkeypatch):
    monkeypatch.setattr(undo, "MAX_FILE_BYTES", 4)  # src/app.py is now too large to save
    assert _decision(_payload(project, "git reset --hard")) == "ask"


# What a review found a restore could not put back: each keeps the ask.

def test_a_tracked_file_in_a_folder_the_snapshot_leaves_out_keeps_the_ask(project):
    _git(project, "add", "-f", "node_modules/pkg/index.js")
    _git(project, "commit", "-q", "-m", "vendored")
    _write(project, "node_modules/pkg/index.js", b"patched\n")
    assert _decision(_payload(project, "git checkout .")) == "ask"


def test_untracked_folders_the_snapshot_leaves_out_do_not_count(project):
    # the fixture's node_modules/ and data/ are ignored and untracked: git does not reach them
    assert _decision(_payload(project, "git checkout .")) is None


@pytest.mark.parametrize("key, value", [("core.worktree", "../elsewhere"), ("submodule.recurse", "true"),
                                        ("include.path", "../other.gitconfig")])
def test_a_setting_that_sends_git_elsewhere_keeps_the_ask(project, key, value):
    _git(project, "config", key, value)
    assert _decision(_payload(project, "git reset --hard")) == "ask"


def test_submodules_keep_the_ask(project):
    _write(project, ".gitmodules", b'[submodule "lib"]\n\tpath = lib\n\turl = ../lib\n')
    assert _decision(_payload(project, "git reset --hard")) == "ask"


@pytest.mark.parametrize("command", ["builtin cd sub && git reset --hard", "command cd sub; git reset --hard",
                                     "eval 'cd sub'; git reset --hard", "pushd sub && git stash",
                                     "Set-Location sub; git reset --hard"])
def test_a_folder_change_the_guard_may_not_follow_keeps_the_ask(project, command):
    os.makedirs(os.path.join(project, "sub"), exist_ok=True)
    assert _decision(_payload(project, command)) == "ask"


def test_something_staged_keeps_the_ask(project):
    _write(project, "src/app.py", b"STAGED VERSION\n")
    _git(project, "add", "src/app.py")
    _write(project, "src/app.py", b"WORKING VERSION\n")
    assert _decision(_payload(project, "git reset --hard")) == "ask"


@pytest.mark.parametrize("command", ["git stash -a", "git stash --all", "git stash push --all",
                                     "git reset --hard HEAD~1", "git reset --hard origin/main"])
def test_what_takes_ignored_files_or_moves_head_keeps_the_ask(project, command):
    assert _decision(_payload(project, command)) == "ask"


# A second review: anything beside the git command, or a repository that runs code on checkout.

@pytest.mark.parametrize("command", [
    "export GIT''_WORK_TREE=../x; git reset --hard",
    "ev''al 'c''d ../x'; git reset --hard",
    "find ../x/a.txt -execdir git reset --hard \\;",
    "git config core.worktree ../../x; git reset --hard",
    "printf 'x' > .git/hooks/post-checkout; git checkout -- .",
    "git add -f node_modules; git reset --hard",
    "git checkout other -- .",
    "git checkout -f other",
    "git switch --discard-changes other",
    "git stash branch nb",
    "git reset --hard; echo done",
    "  git reset --hard && true",
])
def test_only_the_git_command_alone_on_the_line(project, command):
    assert _decision(_payload(project, command)) == "ask"


@pytest.mark.parametrize("key, value", [("core.hooksPath", "../hooks"), ("filter.z.smudge", "cat")])
def test_settings_that_run_code_on_checkout_keep_the_ask(project, key, value):
    _git(project, "config", key, value)
    assert _decision(_payload(project, "git checkout -- .")) == "ask"


def test_a_hook_in_the_repository_keeps_the_ask(project):
    _write(project, ".git/hooks/post-checkout", b"#!/bin/sh\necho elsewhere > ../x.txt\n")
    assert _decision(_payload(project, "git checkout -- .")) == "ask"


def test_a_tracked_folder_renamed_only_in_letter_case_keeps_the_ask(project):
    if os.path.normcase("A") != "a" and sys.platform != "darwin":
        pytest.skip("a case-sensitive file system keeps both names apart")
    _git(project, "add", "-f", "node_modules/pkg/index.js")
    _git(project, "commit", "-q", "-m", "vendored")
    os.rename(os.path.join(project, "node_modules"), os.path.join(project, "Node_Modules_tmp"))
    os.rename(os.path.join(project, "Node_Modules_tmp"), os.path.join(project, "Node_Modules"))
    _write(project, "Node_Modules/pkg/index.js", b"edited\n")
    assert _decision(_payload(project, "git reset --hard")) == "ask"


def test_quiet_flags_are_fine(project):
    for command in ("git reset -q --hard", "git checkout -q -- .", "git stash -q", "git stash pop --quiet"):
        assert _decision(_payload(project, command)) is None, command


def test_a_snapshot_that_cannot_be_taken_keeps_the_ask(project, monkeypatch):
    monkeypatch.setattr(undo, "SUPPORTED", ())
    assert _decision(_payload(project, "git reset --hard")) == "ask"
