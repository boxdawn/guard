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
    verdict = evaluate_powershell(command, cwd=str(repo), home=str(repo.parent / "nobody"), rules=RULES)
    if verdict is None:
        pytest.skip("no PowerShell parser on this machine")
    return verdict.decision


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


@pytest.mark.parametrize("command", ["Remove-Item 'link\\my sub' -Recurse -Force", "Remove-Item -LiteralPath 'link\\my sub' -Recurse -Force",
                                     "Remove-Item '.\\link\\my sub' -Recurse -Force", "Remove-Item 'link\\my sub\\*' -Recurse -Force"])
def test_powershell_space_in_the_path_is_still_seen(repo, command):
    assert powershell(command, repo) == "deny"


@pytest.mark.skipif(sys.platform != "win32", reason="a backslash is a separator only on Windows")
def test_backslash_in_a_bash_path_on_windows(repo):
    assert bash("rm -rf 'link\\sub'", repo) == "deny"


@pytest.mark.parametrize("command", ["Remove-Item link -Recurse -Force -Include *", "Remove-Item -Path link -Include *.txt -Recurse -Force",
                                     "Remove-Item link -Exclude nothing -Recurse -Force", "Remove-Item link -Exclude a.txt -Recurse -Force"])
def test_powershell_include_deletes_inside_the_link(repo, command):
    assert powershell(command, repo) == "deny"


def test_cd_after_cd_reaches_a_link(repo, tmp_path):
    link(repo / "own" / "nest", tmp_path / "home")
    assert bash("cd own && cd nest && rm -rf sub", repo) == "deny"
    assert powershell("Set-Location own; Set-Location nest; Remove-Item sub -Recurse -Force", repo) == "deny"


def test_renaming_a_link_leaves_the_target(repo):
    assert bash("mv link x", repo) is None


@pytest.mark.parametrize("command", ["New-Item -ItemType j -Path x -Target ..\\home; Remove-Item -Recurse -Force x\\sub",
                                     "New-Item -ItemType sym -Path x -Target ..\\home; Remove-Item -Recurse -Force x\\sub",
                                     "New-Item -ItemType Junction -Name x -Target ..\\home; Remove-Item -Recurse -Force x\\sub"])
def test_powershell_link_forms_ask(repo, command):
    assert powershell(command, repo) == "ask"


@pytest.mark.skipif(sys.platform != "win32", reason="names differ only by case on Windows")
def test_made_link_in_another_case_asks(repo):
    assert bash("ln -s ../home X && rm -rf x/sub", repo) == "ask"
    assert powershell("New-Item -ItemType Junction -Path X -Target ..\\home; Remove-Item -Recurse -Force x\\sub", repo) == "ask"


def test_ln_with_one_operand_or_unknown_name_asks(repo):
    assert bash("ln -s ../home && rm -rf home/sub", repo) == "ask"
    assert bash('ln -s ../home "$N"', repo) == "ask"


@pytest.mark.skipif(sys.platform != "win32", reason="UNC paths")
def test_project_on_a_network_path_is_still_the_project(repo):
    drive, rest = str(repo).split(":", 1)
    share = f"\\\\localhost\\{drive}$" + rest
    if not os.path.isdir(share):
        pytest.skip("no admin share here")
    nobody = str(repo.parent / "nobody")
    for command in ["rm -rf own/inner", f"rm -rf '{share}\\own\\x'", f"cd '{share}\\own' && rm -rf x"]:
        assert evaluate(command, cwd=share, home=nobody, rules=RULES).decision is None
    assert evaluate("rm -rf link/sub", cwd=share, home=nobody, rules=RULES).decision == "deny"


def test_many_targets_stay_fast(repo):
    import time
    start = time.perf_counter()
    bash("rm -f " + " ".join(f"own/f{i}" for i in range(3000)), repo)
    assert time.perf_counter() - start < 5
