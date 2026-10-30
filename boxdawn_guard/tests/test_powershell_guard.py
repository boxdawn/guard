"""PowerShell commands, read by PowerShell's own parser (packaging/psparse).

Needs the helper: set BDX_PSPARSE to a built bdxpsparse.exe (Windows only).
CI's Windows job builds it and asserts it exists before running these, so a
skip there cannot pass as a green check.
"""
from __future__ import annotations

import os

import pytest

pytest.importorskip("tree_sitter_bash")

from boxdawn_guard import command_hook, powershell_guard  # noqa: E402
from boxdawn_guard.command_rules_source import default_command_rules  # noqa: E402

CWD, HOME = r"C:\work\proj", r"C:\Users\me"
ENV = {"TEMP": r"C:\Users\me\AppData\Local\Temp"}
_helper = os.environ.get("BDX_PSPARSE")
if os.environ.get("BDX_REQUIRE_PSPARSE") and not (_helper and os.path.isfile(_helper)):
    raise RuntimeError(f"BDX_REQUIRE_PSPARSE is set but the reader is missing: {_helper!r}")
needs_helper = pytest.mark.skipif(not (_helper and os.path.isfile(_helper)),
                                  reason="BDX_PSPARSE (bdxpsparse.exe) not built")


def judge(command, unattended=False):
    return powershell_guard.evaluate_powershell(
        command, cwd=CWD, home=HOME, rules=default_command_rules(),
        unattended=unattended, known_env=ENV)


CASES = [
    # (command, decision, rule ids)
    (r"Get-ChildItem -Recurse | Select-Object -First 5", None, []),
    (r"Remove-Item -Recurse -Force C:\Windows", "deny", ["rm.outside"]),
    (r"rm -r -fo ..\other", "deny", ["rm.outside"]),
    (r"Remove-Item .\build -Recurse", None, []),
    (r"Remove-Item . -Recurse -Force", "ask", ["rm.project_root"]),
    (r"""$d = 'C:\x'; Remove-Item "$d\y" -Recurse""", "deny", ["rm.outside"]),
    (r"""$d = 'build'; Remove-Item "$d\y" -Recurse""", None, []),
    (r"""foreach ($i in 1) { $d = 'C:\' }; $d='build'; Remove-Item $d -Recurse""", "deny", ["rm.runtime"]),
    (r"""$d = 'build'; $d += '\..\..'; Remove-Item $d -Recurse""", "deny", ["rm.runtime"]),
    (r"""$d = 'build'; Set-Variable d C:\; Remove-Item $d -Recurse""", "deny", ["rm.runtime"]),
    (r"""$d = 'build'; Get-Date -OutVariable d; Remove-Item $d -Recurse""", "deny", ["rm.runtime"]),
    (r"""$d = 'build'; Remove-Item variable:d; Remove-Item "$d\x" -Recurse""", "deny",
     ["rm.outside", "rm.runtime"]),
    (r"""Remove-Item "$env:TEMP\x" -Recurse -Force""", None, []),
    (r"Remove-Item $HOME -Recurse -Force", "deny", ["rm.outside"]),
    (r"Remove-Item $nobody -Recurse -Force", "deny", ["rm.runtime"]),
    (r"Remove-Item @p", "ask", ["rm.runtime"]),
    (r"Remove-Item HKCU:\Software\X -Recurse", "deny", ["rm.outside"]),
    (r"Remove-Item Registry::HKEY_CURRENT_USER\X", "ask", ["rm.outside"]),
    (r"Remove-Item C:x -Recurse", "deny", ["rm.runtime"]),
    (r"Remove-Item C:\x -Recurse -WhatIf", None, []),
    (r"Remove-Item C:\x -Recurse:$false", "ask", ["rm.outside"]),
    (r"Remove-Item -Rec -Fo C:\x", "deny", ["rm.outside"]),
    (r"Remove-Item C:\a, .\b -Recurse", "deny", ["rm.outside"]),
    (r"Microsoft.PowerShell.Management\Remove-Item C:\x -Recurse", "deny", ["rm.outside"]),
    (r"cd C:\; Remove-Item Windows -Recurse -Force", "deny", ["rm.outside"]),
    (r"Get-ChildItem build | Remove-Item -Recurse -Force", "deny", ["rm.runtime"]),
    (r"& { Remove-Item C:\x -Recurse -Force }", "deny", ["rm.outside"]),
    (r"Get-Date | ForEach-Object { Remove-Item C:\x -Recurse }", "deny", ["rm.outside"]),
    (r"git reset --hard", "ask", ["git.reset_hard"]),
    (r"git push -f origin main", "deny", ["git.push_force"]),
    (r"& 'C:\Program Files\Git\cmd\git.exe' clean -fdx", "ask", ["git.clean"]),
    (r"$g = 'git'; & $g reset --hard", "ask", ["git.reset_hard"]),
    (r"& $exe --flag", "ask", ["name.runtime"]),
    (r"iex 'Remove-Item C:\x -Recurse -Force'", "deny", ["rm.outside"]),
    (r"'Remove-Item C:\x -Recurse -Force' | Invoke-Expression", "deny", ["rm.outside"]),
    (r"Invoke-Expression $cmd", "ask", ["eval.runtime"]),
    (r"""powershell -NoProfile -Command "Remove-Item C:\x -Recurse -Force" """, "deny", ["rm.outside"]),
    # Remove-Item C:\x -Recurse -Force, as UTF-16LE base64
    ("pwsh -enc UgBlAG0AbwB2AGUALQBJAHQAZQBtACAAQwA6AFwAeAAgAC0AUgBlAGMAdQByAHMAZQAgAC0ARgBvAHIAYwBlAA==",
     "deny", ["rm.outside"]),
    (r"pwsh -c 'Get-Date'", None, []),
    (r"pwsh -File .\build.ps1", None, []),
    (r"cmd /c rd /s /q C:\x", "ask", ["code.inline_unknown_language"]),
    (r"bash -c 'rm -rf /'", "deny", ["rm.outside"]),
    (r"""python -c "import shutil; shutil.rmtree('x')" """, "ask", ["code.inline_risky"]),
    ("@'\nimport os\nos.remove('x')\n'@ | python -", "ask", ["code.inline_risky"]),
    (r"Get-Content x.py | python", "ask", ["pipe.into_interpreter"]),
    (r"'hello' > C:\out.txt", "ask", ["redirect.outside"]),
    (r"'hello' > out.txt", None, []),
    (r"'hello' >> C:\out.txt", None, []),
    (r"Get-Date > $null; Get-Date 2>&1", None, []),
    (r"cd C:\elsewhere; Get-Date 2> $null", None, []),
    (r"Set-Content -Path C:\x.txt -Value hi", "ask", ["redirect.outside"]),
    (r"Set-Content C:\x.txt hi", "ask", ["redirect.outside"]),
    (r"'a' | Out-File C:\x.txt", "ask", ["redirect.outside"]),
    (r"'a' | Out-File -Append C:\x.txt", None, []),
    (r"'a' | Tee-Object -FilePath $where", "ask", ["redirect.runtime"]),
    (r"Clear-Content .\log.txt", "ask", ["truncate.file"]),
    (r"Clear-Content C:\x.log", "deny", ["truncate.outside"]),
    (r"Format-Volume -DriveLetter D", "deny", ["destroy.by_design"]),
    (r"Start-Process powershell -Verb RunAs", "ask", ["privilege.elevated"]),
    (r"Start-Process cmd -ArgumentList '/c rd /s /q C:\x'", "ask", ["code.inline_unknown_language"]),
    (r"Start-Process git -ArgumentList 'push','--force'", "deny", ["git.push_force"]),
    (r"terraform destroy -auto-approve", "deny", ["iac.destroy"]),
    (r"redis-cli FLUSHALL", "deny", ["db.destructive"]),
    (r". .\venv\Scripts\Activate.ps1", "ask", ["source.script"]),
    (r"Stop-Process -Name node -Force", None, []),
    # Windows PowerShell 5.1 has no `&&`: unreadable, and still judged.
    (r"git status && Remove-Item C:\x", "ask", ["parse.unreadable", "rm.outside"]),
]


@needs_helper
@pytest.mark.parametrize("command,decision,rules", CASES)
def test_case(command, decision, rules):
    v = judge(command)
    assert (v.decision, [f.rule for f in v.findings]) == (decision, rules)


@needs_helper
def test_unattended_turns_ask_into_deny():
    v = judge("git reset --hard", unattended=True)
    assert v.decision == "deny" and v.escalated


@needs_helper
def test_hook_judges_the_powershell_tool():
    out = command_hook.decide({"tool_name": "PowerShell", "cwd": CWD, "permission_mode": "default",
                               "tool_input": {"command": r"Remove-Item C:\x -Recurse -Force"}})
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert out["hookSpecificOutput"]["permissionDecisionReason"].startswith("Boxdawn guard: ")


def test_no_reader_off_windows_is_no_decision(monkeypatch):
    def missing(_):
        raise powershell_guard.HelperMissing("none")
    monkeypatch.setattr(powershell_guard.os, "name", "posix")
    v = powershell_guard.evaluate_powershell("Remove-Item / -Recurse -Force", cwd="/w", home="/h",
                                             rules=default_command_rules(), parse=missing)
    assert v is None


def test_no_reader_on_windows_asks(monkeypatch):
    def missing(_):
        raise powershell_guard.HelperMissing("none")
    monkeypatch.setattr(powershell_guard.os, "name", "nt")
    v = powershell_guard.evaluate_powershell("Get-Date", cwd=CWD, home=HOME,
                                             rules=default_command_rules(), parse=missing)
    assert (v.decision, [f.rule for f in v.findings]) == ("ask", ["guard.crashed"])


def test_a_broken_reader_asks():
    def broken(_):
        raise ValueError("bad json")
    v = powershell_guard.evaluate_powershell("Get-Date", cwd=CWD, home=HOME,
                                             rules=default_command_rules(), parse=broken)
    assert (v.decision, [f.rule for f in v.findings]) == ("ask", ["guard.crashed"])
