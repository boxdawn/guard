"""`grep -r` in Bash: flags go in after the name, and the search really leaves the files out."""
from __future__ import annotations

import json
import pathlib
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




def _rules(where, permissions):
    path = pathlib.Path(command_hook._settings_files(None)[where])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"permissions": permissions}), encoding="utf-8")


@pytest.mark.parametrize("where", ["managed", "user", "project", "local"])
@pytest.mark.parametrize("command, permissions", [
    ("grep -rn KEY .", {"deny": ["Bash(grep -rn:*)"]}),
    ("grep -rn KEY .", {"ask": ["Bash(grep -r*)"]}),
    ("grep -rn KEY .", {"deny": ["Read", "Bash(rm:*)", "Bash(cd src && grep -rn *)", "Bash(grep -rn KEY .)"]}),
    ("cd src && grep -rn KEY . | head", {"ask": ["Bash(grep -rn:*)"]}),
    ("egrep --recursive KEY src", {"ask": ["Bash(egrep --recursive *)"]}),
    ("grep.exe -rn KEY .", {"deny": ["Bash(grep.exe -rn:*)"]}),
    ("GREP -rn KEY .", {"deny": ["Bash(GREP -rn:*)"]}),
    ("\\grep -rn KEY .", {"deny": ["Bash(\\grep -rn:*)"]}),
    ("/usr/bin/grep -r KEY .", {"deny": [" Bash(/usr/bin/grep -r:*) "]}),
])
def test_a_rule_the_flags_would_undo_keeps_the_command_as_written(where, command, permissions):
    """Claude Code matches its rules to the changed command, so the flags would undo the person's rule."""
    assert "updatedInput" in verdict(command)  # the flags go in without the rule
    _rules(where, permissions)
    assert decide(command) is None


@pytest.mark.parametrize("permissions", [
    {"allow": ["Bash(grep -rn:*)"]}, {"deny": ["Bash(rm:*)"], "ask": ["Bash(git push:*)"]}, {"deny": []}, {},
    {"deny": ["Bash(grep:*)"]}, {"ask": ["Bash(grep *)", "Bash(grep*)", "Bash"]},  # still match the changed command
    {"ask": ["Bash(git grep:*)", "Bash(git  grep -rn KEY .)"]},
    {"deny": ["Bash(pgrep -f x)", "Bash(ps aux | grep -v grep:*)", "Bash(grep -rn KEY /etc:*)"]},
    {"deny": ["Grep(.env)", "Read(grep -rn KEY .)", 3, None]},
])
def test_other_rules_still_get_the_flags(permissions):
    _rules("project", permissions)
    assert changed("grep -rn KEY .") == f"grep {FLAGS} -rn KEY ."


@pytest.mark.parametrize("text", [
    "{not json", '{"permissions": ["deny"]}', '{"permissions": {"deny": 3}}', "[]",
    '{"permissions": {"deny": "Bash(grep -rn:*)"}}', "[" * 100000, "\xff\xfe",
])
def test_a_file_claude_code_could_not_read_holds_no_rule(text):
    path = pathlib.Path(command_hook._settings_files(None)["user"])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="latin-1")
    assert changed("grep -rn KEY .") == f"grep {FLAGS} -rn KEY ."


def test_a_folder_where_a_settings_file_would_be_holds_no_rule():
    pathlib.Path(command_hook._settings_files(None)["project"]).mkdir(parents=True)
    assert changed("grep -rn KEY .") == f"grep {FLAGS} -rn KEY ."


def test_without_the_project_variable_the_session_folder_counts(tmp_path, monkeypatch):
    monkeypatch.delenv("CLAUDE_PROJECT_DIR")
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text(json.dumps({"permissions": {"deny": ["Bash(grep -rn:*)"]}}))
    assert decide("grep -rn KEY .", cwd=str(tmp_path)) is None
    assert "updatedInput" in verdict("grep -rn KEY .", str(tmp_path / "sub"))  # Claude Code reads no folder above


def test_without_the_config_variable_the_home_folder_counts(tmp_path, monkeypatch):
    monkeypatch.delenv("CLAUDE_CONFIG_DIR")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    _rules("user", {"deny": ["Bash(grep -rn:*)"]})
    assert command_hook._settings_files(None)["user"] == str(tmp_path / ".claude" / "settings.json")
    assert decide("grep -rn KEY .") is None


def test_a_settings_file_with_a_byte_order_mark_is_read():
    path = pathlib.Path(command_hook._settings_files(None)["project"])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"\xef\xbb\xbf" + json.dumps({"permissions": {"ask": ["Bash(grep -rn:*)"]}}).encode())
    assert decide("grep -rn KEY .") is None


def test_a_decision_on_another_tool_does_not_read_the_rules(monkeypatch):
    monkeypatch.setattr(command_hook, "_deny_and_ask_rules", lambda cwd: 1 / 0)
    assert decide("grep -n KEY notes.txt") is None
    out = command_hook.decide({"tool_name": "PowerShell", "tool_input": {"command": "Get-ChildItem -Recurse"},
                               "cwd": "/work/proj", "permission_mode": "default"})
    assert "updatedInput" not in (out or {}).get("hookSpecificOutput", {})



@pytest.mark.parametrize("command", [
    "if grep -rn KEY .; then echo y; fi", "! grep -rn KEY .", "grep  -rn KEY .", "grep\t-rn KEY .",
    "FOO=1 grep -rn KEY .", "LC_ALL=C grep -rn KEY .", "(grep -rn KEY .)", "{ grep -rn KEY .; }",
    "grep -rn KEY . & wait", "grep -rn KEY . 2>/dev/null", "echo a && grep -rn KEY . | head", "echo $(grep -rn KEY .)",
    "grep -r A . ; grep -rn B .",
])
def test_the_forms_claude_code_catches_with_a_rule_keep_the_command_as_written(command):
    """Measured: each of these meets a deny `Bash(grep -rn:*)` in Claude Code 2.1.318 when run as written."""
    assert "updatedInput" in verdict(command)
    _rules("project", {"deny": ["Bash(grep -rn:*)"]})
    assert decide(command) is None


@pytest.mark.parametrize("command", ["grep -rnw KEY .", "grep -rl KEY ."])
def test_a_rule_is_matched_by_words(command):
    """Measured: `Bash(grep -rn:*)` does not catch `grep -rnw` in Claude Code."""
    _rules("project", {"deny": ["Bash(grep -rn:*)"], "ask": [" Bash( grep  -rn :*) "]})
    assert "updatedInput" in verdict(command)


@pytest.mark.parametrize("rule", ["Bash(* * * * * * .env)", "Bash(" + "*a" * 12 + "b)", "Bash(*" + "-" * 30 + "*)"])
def test_many_stars_take_no_time(rule):
    import time
    _rules("project", {"deny": [rule] * 50})
    command = "grep -rn " + " ".join(f"w{i}" for i in range(400)) + " ."
    start = time.perf_counter()
    decide(command)
    assert time.perf_counter() - start < 1


@pytest.mark.parametrize("rule, line, hit", [
    ("grep -rn:*", "grep -rn KEY .", True), ("grep -rn:*", "grep -rn", True), ("grep -rn:*", "grep -rnw K .", False),
    ("grep -rn *", "grep -rn KEY .", True), ("grep*", "grep -rn KEY .", True), ("*-rn*", "x=1 grep -rn K", True),
    ("grep -rn KEY .", "cd a && grep -rn KEY .", True), ("grep -rn KEY .", "grep -rn KEY .x", False),
    ("a*b*c", "abc", True), ("a*b*c", "acb", False), ("ab*ba", "aba", False),
])
def test_how_a_rule_is_read(rule, line, hit):
    assert command_hook._rule_matches(rule, line) is hit
