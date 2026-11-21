"""A PowerShell script the line runs (`.\\x.ps1`, `& .\\x.ps1`, `pwsh -File x.ps1`) is
read from disk and judged as a PowerShell line typed in its folder, as a shell
script is (test_read_shell_scripts.py): only what would be refused asks, under
`script.refused`.

Needs the PowerShell reader (BDX_PSPARSE), like test_powershell_guard.py.
"""
from __future__ import annotations

import os

import pytest

pytest.importorskip("tree_sitter_bash")

from boxdawn_guard import powershell_guard  # noqa: E402
from boxdawn_guard.command_guard import evaluate  # noqa: E402
from boxdawn_guard.command_rules_source import default_command_rules  # noqa: E402

_helper = os.environ.get("BDX_PSPARSE")
pytestmark = pytest.mark.skipif(not (_helper and os.path.isfile(_helper)),
                                reason="BDX_PSPARSE (bdxpsparse.exe) not built")
RULES = default_command_rules()
HOME = os.path.expanduser("~")


@pytest.fixture
def project(tmp_path):
    p = tmp_path / "proj"
    (p / "scripts").mkdir(parents=True)
    for name, text in [("wipe.ps1", "Remove-Item -Recurse -Force ~\n"),
                       ("bom.ps1", "﻿Remove-Item -Recurse -Force ~\n"),
                       ("fmt.ps1", "Format-Volume -DriveLetter Z\n"),
                       ("ok.ps1", "Write-Host hi\nRemove-Item -Recurse .\\build\n")]:
        (p / "scripts" / name).write_text(text, encoding="utf-8")
    return p


def ps(project, command, unattended=False):
    return powershell_guard.evaluate_powershell(command, cwd=str(project), home=HOME, rules=RULES,
                                                unattended=unattended)


def rules_of(verdict):
    return {f.rule for f in verdict.findings}


@pytest.mark.parametrize("command", [
    r"& .\scripts\wipe.ps1", r".\scripts\wipe.ps1", r"& ./scripts/wipe.ps1 -Force",
    r"powershell -File .\scripts\wipe.ps1", r"pwsh .\scripts\wipe.ps1",
    r"powershell -ExecutionPolicy Bypass -File scripts\wipe.ps1", r"cd scripts; .\wipe.ps1",
    r".\scripts\bom.ps1",
])
def test_a_ps1_that_would_wipe_the_home_folder_asks(project, command):
    v = ps(project, command)
    assert v.decision == "ask", v.reasons
    assert {"script.refused", "rm.outside"} <= rules_of(v), v.reasons


def test_what_the_script_would_refuse_is_named(project):
    v = ps(project, r".\scripts\fmt.ps1")
    assert v.decision == "ask", v.reasons
    assert {"script.refused", "destroy.by_design"} <= rules_of(v), v.reasons
    assert any("scripts" in r and "would be refused" in r for r in v.reasons), v.reasons


def test_unattended_it_is_denied(project):
    assert ps(project, r".\scripts\wipe.ps1", unattended=True).decision == "deny"


@pytest.mark.parametrize("command", [r".\scripts\ok.ps1", r".\scripts\missing.ps1",
                                     r"Get-Content .\scripts\wipe.ps1"])
def test_these_get_no_decision(project, command):
    v = ps(project, command)
    assert v.decision is None, v.reasons


@pytest.mark.parametrize("command", [r"powershell -NoProfile .\scripts\wipe.ps1",
                                     r".\scripts\wipe.ps1; .\scripts\wipe.ps1"])
def test_a_script_reached_twice_on_the_line_is_read_once(project, command):
    v = ps(project, command)
    assert v.decision == "ask", v.reasons
    assert len(v.reasons) == len(set(v.reasons)), v.reasons


def test_a_script_with_many_folder_changes_stays_within_its_time(project):
    import time
    (project / "scripts" / "cd400.ps1").write_text(
        "".join(f"Set-Location d{i}\n" for i in range(400)) + "Write-Host done\n", encoding="utf-8")
    started = time.monotonic()
    ps(project, r".\scripts\cd400.ps1")
    assert time.monotonic() - started < 4


@pytest.mark.parametrize("command", ["pwsh -File scripts/wipe.ps1", "powershell.exe -File scripts/wipe.ps1"])
def test_from_bash_a_ps1_given_to_powershell_is_read_too(project, command):
    v = evaluate(command, cwd=str(project), home=HOME, rules=RULES)
    assert v.decision == "ask", v.reasons
    assert "script.refused" in rules_of(v), v.reasons


def test_from_bash_a_ps1_run_by_path_is_not_powershell(project):
    # bash runs `./x.ps1` only through a `#!` line; it is not read as PowerShell
    assert "script.refused" not in rules_of(evaluate("./scripts/wipe.ps1", cwd=str(project), home=HOME, rules=RULES))
