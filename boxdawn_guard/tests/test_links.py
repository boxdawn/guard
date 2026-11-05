"""A link inside the project that points outside it: real links on the disk."""
import dataclasses
import os
import subprocess
import sys

import pytest

from boxdawn_guard.command_guard import evaluate
from boxdawn_guard.command_rules_source import default_command_rules
from boxdawn_guard.powershell_guard import evaluate_powershell

# pytest's tmp_path sits under a temp root, which counts as inside.
RULES = dataclasses.replace(default_command_rules(), scratch_dirs=())


def link(path, to):
    if sys.platform == "win32":
        subprocess.run(["cmd", "/c", "mklink", "/J", str(path), str(to)], check=True, capture_output=True)
    else:
        os.symlink(to, path)


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "repo"
    (root / "own").mkdir(parents=True)
    (tmp_path / "home" / "sub").mkdir(parents=True)
    link(root / "link", tmp_path / "home")
    link(root / "near", root / "own")
    return root


def bash(command, repo):
    return evaluate(command, cwd=str(repo), home=str(repo.parent / "nobody"), rules=RULES).decision


def powershell(command, repo):
    return evaluate_powershell(command, cwd=str(repo), home=str(repo.parent / "nobody"), rules=RULES).decision


@pytest.mark.parametrize("command", ["rm -rf link/", "rm -rf link/sub", "rm -rf link/*", "cd link && rm -rf sub",
                                     "cd link && rm -rf .", "rm -rf link/../x"])
def test_delete_through_a_link_is_denied(repo, command):
    assert bash(command, repo) == "deny"


def test_removing_the_link_itself_leaves_the_target(repo):
    assert bash("rm -rf link", repo) is None
    assert bash("rm link", repo) is None


@pytest.mark.parametrize("command", ["rm -rf near/", "rm -rf near/x", "rm -rf own/", "rm -rf missing/x"])
def test_staying_inside_is_unchanged(repo, command):
    assert bash(command, repo) is None


@pytest.mark.parametrize("command", ["cp x link/y", "mv x link/y", "echo x > link/y", "dd if=/dev/zero of=link/y"])
def test_write_through_a_link_is_stopped(repo, command):
    assert bash(command, repo) in ("ask", "deny")


def test_write_onto_the_link_itself_follows_it(repo):
    assert bash("cp x link", repo) == "ask"


@pytest.mark.parametrize("command", ["Remove-Item -Recurse -Force link\\sub", "Remove-Item -Recurse -Force link\\*",
                                     "Remove-Item -Recurse -Force link\\"])
def test_powershell_delete_through_a_link_is_denied(repo, command):
    assert powershell(command, repo) == "deny"


def test_powershell_removing_the_link_itself_leaves_the_target(repo):
    assert powershell("Remove-Item link -Recurse -Force", repo) is None


@pytest.mark.parametrize("command", ["Copy-Item x link\\y -Force", "Move-Item x link\\y -Force", "New-Item link\\y -Force"])
def test_powershell_write_through_a_link_asks(repo, command):
    assert powershell(command, repo) == "ask"


def test_project_reached_through_a_link_is_still_the_project(repo, tmp_path):
    alias = tmp_path / "alias"
    link(alias, repo)
    assert evaluate("rm -rf own/", cwd=str(alias), home=str(tmp_path / "nobody"), rules=RULES).decision is None


@pytest.mark.parametrize("command", ["ln -s ../home x && rm -rf x/", "ln -sf ../home x; rm -rf x/sub", "ln -s ../home x && cp a x/y"])
def test_link_made_by_the_same_command_asks(repo, command):
    assert bash(command, repo) == "ask"


def test_link_made_and_removed_itself_passes(repo):
    assert bash("ln -s own x && rm x", repo) is None


def test_powershell_link_made_by_the_same_command_asks(repo):
    command = "New-Item -ItemType Junction -Path x -Target ..\\home; Remove-Item -Recurse -Force x\\sub"
    assert powershell(command, repo) == "ask"
