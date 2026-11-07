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
    ("grep -rA2 KEY .", f"grep {FLAGS} -rA2 KEY ."),
    ("grep -rnC2 KEY .", f"grep {FLAGS} -rnC2 KEY ."),
    ("grep -1r KEY .", f"grep {FLAGS} -1r KEY ."),
    ("grep --rec KEY .", f"grep {FLAGS} --rec KEY ."),
    ("grep --dir=recurse KEY .", f"grep {FLAGS} --dir=recurse KEY ."),
    ("grep -nd recurse KEY .", f"grep {FLAGS} -nd recurse KEY ."),
    ("\\grep -r KEY .", f"\\grep {FLAGS} -r KEY ."),
    ("/usr/bin/grep -r KEY .", f"/usr/bin/grep {FLAGS} -r KEY ."),
    ("rgrep KEY .", f"rgrep {FLAGS} KEY ."),
    ("grep -r KEY . # note", f"grep {FLAGS} -r KEY . # note"),
    (f"grep {FLAGS} -r A . ; grep -rl KEY .", f"grep {FLAGS} -r A . ; grep {FLAGS} -rl KEY ."),
    (f"grep -r KEY . # {FLAGS}", f"grep {FLAGS} -r KEY . # {FLAGS}"),
])
def test_a_recursive_grep_gets_the_flags_after_its_name(before, after):
    assert changed(before) == after


@pytest.mark.parametrize("command", [
    "grep KEY notes.txt",
    "grep -e -r notes.txt",
    "grep -f -r notes.txt",
    "grep -- -r notes.txt",
    "grep -rl --include='*.py' KEY .",
    "grep --include='*.py' -rl KEY .",
    "grep -r --include=.env KEY .",
    "grep -rl KEY .env.example",
    "grep -rl KEY inv/hosts.yml",
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


@pytest.mark.parametrize("command, cwd", [
    ("grep -rl KEY .kube", "/work/proj"),
    ("grep -rl KEY .kube/", "/work/proj"),
    ("grep -rl KEY ./.docker/", "/work/proj"),
    ("grep -rl KEY .", "/home/me/.kube"),
])
def test_a_search_that_starts_in_a_credentials_folder_asks(command, cwd):
    assert decide(command, cwd)["hookSpecificOutput"]["permissionDecision"] == "ask"


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


def verdict(command, cwd="/work/proj"):
    out = decide(command, cwd)
    return out and out["hookSpecificOutput"]


@pytest.mark.parametrize("command", [
    "grep -r .docker .", "grep -rn '\\.docker' src", "grep -r KEY . --exclude-dir .kube",
    "grep -rni .env .", "grep -r -e KEY -e .env .", "grep -rn hosts.yml .",
    "grep -r id_rsa src", "grep -r --exclude=.env KEY .", "grep --di=recurse KEY .", "GREP -r KEY .",
])
def test_found_in_review_the_flags_go_in(command):
    assert "updatedInput" in verdict(command)


@pytest.mark.parametrize("command", ["grep --inc='*' -r KEY .", "grep --inc '*.py' -r KEY ."])
def test_any_start_of_include_stays(command):
    assert decide(command) is None


@pytest.mark.parametrize("command, cwd", [
    ("cd .kube && grep -r KEY .", "/work/proj"), ("cd .docker; grep -r KEY", "/work/proj"),
    ("grep -r KEY .ku*/", "/work/proj"), ("grep -r KEY ./.d*/", "/work/proj"), ("grep -r KEY .aw*/", "/work/proj"),
    ("grep -r KEY", "/home/me/.aws"), ("grep -r KEY", "/home/me/.ssh"), ("grep -r KEY .", "/home/me/.docker/app"),
])
def test_a_search_that_starts_in_a_credentials_folder_asks(command, cwd):
    assert verdict(command, cwd)["permissionDecision"] == "ask"


def test_a_plain_glob_is_no_credentials_folder():
    assert "updatedInput" in verdict("grep -r KEY *")


def test_a_line_with_every_flag_is_left_alone():
    assert decide(f"grep {FLAGS} -r KEY .") is None


def test_named_files_only_stay():
    assert decide("grep -r KEY .env.example src") is None
    assert decide("grep -r KEY src inventory/hosts.yml") is None
    assert verdict("grep -r KEY src inventory/.env.prod")["permissionDecision"] == "ask"


def test_busybox_grep_is_left_alone(monkeypatch):
    monkeypatch.setattr(command_hook, "_busybox_grep", lambda: True)
    assert decide("grep -r KEY .") is None


@pytest.mark.parametrize("command", [
    "grep -r --group-separator XX .docker docs", "grep -r --m 1 .docker docs", "grep -r --a 2 .docker docs",
    "grep -r --be 2 .docker docs", "grep -r --la x .docker docs", "grep -r --gr x .docker docs",
])
def test_an_option_value_is_no_path(command):
    assert "updatedInput" in verdict(command)


def test_an_ambiguous_start_of_an_option_is_no_option():
    assert secret_files.grep_reads(["--e", "x", "-r", "KEY", "."])[0] is True
