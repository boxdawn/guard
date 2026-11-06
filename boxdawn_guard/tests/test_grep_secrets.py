"""`grep -r` in Bash: flags go in after the name, and the search really leaves the files out."""
from __future__ import annotations

import shutil
import subprocess

import pytest

from boxdawn_guard import command_hook, secret_files

FLAGS = " ".join(secret_files.GREP_EXCLUDES)


def decide(command, cwd="/work/proj"):
    return command_hook.decide({"tool_name": "Bash", "tool_input": {"command": command, "description": "d"},
                                "cwd": cwd, "permission_mode": "default"})


def changed(command):
    return decide(command)["hookSpecificOutput"]["updatedInput"]["command"]


@pytest.mark.parametrize("before, after", [
    ("grep -rn KEY .", f"grep {FLAGS} -rn KEY ."),
    ("grep -R KEY", f"grep {FLAGS} -R KEY"),
    ("egrep --recursive KEY src", f"egrep {FLAGS} --recursive KEY src"),
    ("grep -d recurse KEY .", f"grep {FLAGS} -d recurse KEY ."),
    ("cd src && grep -rn KEY . | head -20", f"cd src && grep {FLAGS} -rn KEY . | head -20"),
    ("echo 한글; grep -r KEY .", f"echo 한글; grep {FLAGS} -r KEY ."),
    ("grep -r A . ; grep -r B .", f"grep {FLAGS} -r A . ; grep {FLAGS} -r B ."),
    ("echo $(grep -r KEY .)", f"echo $(grep {FLAGS} -r KEY .)"),
])
def test_a_recursive_grep_gets_the_flags_after_its_name(before, after):
    assert changed(before) == after


@pytest.mark.parametrize("command", [
    "grep KEY notes.txt",
    "grep -n KEY src/a.py",
    "echo 'grep -r KEY .'",
    "rg KEY",
    "git grep KEY",
    "ls -R",
])
def test_anything_else_is_left_alone(command):
    assert decide(command) is None


@pytest.mark.parametrize("command", ["grep -r KEY .env", "grep -r KEY . && rm -rf /etc/x"])
def test_a_decision_keeps_the_command_as_written(command):
    out = decide(command)["hookSpecificOutput"]
    assert "updatedInput" not in out and out["permissionDecision"] in ("ask", "deny")


def test_the_input_keeps_its_other_fields():
    assert decide("grep -r K .")["hookSpecificOutput"]["updatedInput"]["description"] == "d"


def test_a_command_sent_back_as_changed_is_not_changed_again():
    assert decide(changed("grep -r K .")) is None


@pytest.mark.skipif(shutil.which("grep") is None or shutil.which("sh") is None, reason="needs grep")
def test_the_real_grep_leaves_the_secrets_out(tmp_path):
    secrets = [".env", ".env.local", "CERT.PFX", "id_rsa", ".netrc", ".npmrc", "src/.env", ".ssh/key", ".aws/credentials",
               ".kube/config", ".docker/config.json", ".config/gh/hosts.yml", ".claude/.credentials.json"]
    plain = ["notes.txt", "src/app.txt", "src/config", "id_rsa_helper.py"]
    for name in secrets + plain:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("BDXFAKE\n")
    run = subprocess.run(["sh", "-c", changed("grep -rl BDXFAKE .")], cwd=tmp_path, capture_output=True, text=True)
    found = {line[2:].replace("\\", "/") for line in run.stdout.split()}
    assert found == set(plain)


def test_the_line_stays_short():
    assert len(FLAGS) < 400


def test_it_can_be_turned_off(monkeypatch):
    monkeypatch.setenv("CLAUDE_PLUGIN_OPTION_KEEP_SECRETS_OUT_OF_GREP", "false")
    assert decide("grep -r K .") is None
