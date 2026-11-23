"""`undo` on by default (11-23): snapshots for everyone, but the guard's decisions stay as they
were unless the user turned undo on; build output the project ignores stays out of the copy;
the home's catch-all folders are not projects; a restore always asks; old stores go."""
from __future__ import annotations

import os
import shutil
import time

import pytest

from boxdawn_guard import command_hook, undo
from boxdawn_guard.tests.test_undo import _payload, _store, _write, project  # noqa: F401 - `project` is a fixture

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")


def _decision(payload):
    out = command_hook.decide(payload)
    return (out or {}).get("hookSpecificOutput", {}).get("permissionDecision")


@pytest.mark.parametrize("mode, expected", [("default", "ask"), ("bypassPermissions", "deny")])
def test_on_by_default_keeps_the_ask_and_the_unattended_deny(project, monkeypatch, mode, expected):
    monkeypatch.delenv("CLAUDE_PLUGIN_OPTION_UNDO")
    payload = dict(_payload(project, "git reset --hard"), permission_mode=mode)
    assert _decision(payload) == expected


@pytest.mark.parametrize("undo_value", ["true", ""])
def test_undo_on_alone_never_stands_in_for_an_ask(project, monkeypatch, undo_value):
    # Even `undo` saved as true (as a settings dialog might save a default) changes no decision.
    monkeypatch.setenv("CLAUDE_PLUGIN_OPTION_UNDO", undo_value)
    assert _decision(_payload(project, "git reset --hard")) == "ask"


def test_its_own_setting_lets_a_snapshot_stand_in(project, monkeypatch):
    monkeypatch.setenv("CLAUDE_PLUGIN_OPTION_UNDO_INSTEAD_OF_GIT_ASKS", "true")
    assert _decision(_payload(project, "git reset --hard")) is None
    monkeypatch.setenv("CLAUDE_PLUGIN_OPTION_UNDO", "false")  # and never with snapshots off
    assert _decision(_payload(project, "git reset --hard")) == "ask"


@pytest.mark.parametrize("value", ["false", "", "true"])
def test_a_restore_asks_while_there_are_copies(project, monkeypatch, value):
    undo.before_command(_payload(project), os.environ["CLAUDE_PLUGIN_DATA"])  # copies exist
    monkeypatch.setenv("CLAUDE_PLUGIN_OPTION_UNDO", value)
    line = f'"{os.environ["CLAUDE_PLUGIN_DATA"]}/current/bdxguard.exe" undo restore 1 "{project}"'
    assert _decision(_payload(project, line)) == "ask"
    assert _decision(dict(_payload(project, line), permission_mode="bypassPermissions")) == "deny"


def test_undo_off_and_no_copies_a_line_naming_restore_gets_no_decision(project, monkeypatch):
    monkeypatch.setenv("CLAUDE_PLUGIN_OPTION_UNDO", "false")
    assert _decision(_payload(project, 'grep -rn "bdxguard undo restore" README.md')) is None


def _left_out(project):
    undo.before_command(_payload(project), os.environ["CLAUDE_PLUGIN_DATA"])
    row = _store(project).snapshots()[-1]
    return row, _store(project)._names(row["commit"])


def test_build_output_the_project_ignores_stays_out(project):
    with open(os.path.join(project, ".gitignore"), "ab") as f:
        f.write(b"target/\nobj/\n")
    _write(project, "target/debug/app.bin", b"x" * 1000)
    _write(project, "src/obj/o.bin", b"y")  # any depth
    _write(project, "bin/run.sh", b"echo source\n")  # not ignored: source, kept
    row, names = _left_out(project)
    assert "bin/run.sh" in names
    assert not any(n.startswith(("target/", "src/obj/")) for n in names)
    assert any("target" in f and "build output" in f for f in row["folders"])


def test_an_ignored_build_folder_with_a_tracked_file_is_kept(project):
    from boxdawn_guard.tests.test_undo import _git
    with open(os.path.join(project, ".gitignore"), "ab") as f:
        f.write(b"bin/\n")
    _write(project, "bin/rails", b"#!/usr/bin/env ruby\n")
    _git(project, "add", "-f", "bin/rails")
    _write(project, "bin/local.txt", b"x")
    _, names = _left_out(project)
    assert "bin/rails" in names and "bin/local.txt" in names


def test_the_accounts_global_ignore_file_does_not_count(project, tmp_path, monkeypatch):
    global_ignore = tmp_path / "global-ignore"
    global_ignore.write_text("out/\n")
    config = tmp_path / "gitconfig"
    config.write_text(f"[core]\n\texcludesFile = {str(global_ignore).replace(chr(92), '/')}\n")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(config))
    _write(project, "out/src_code.py", b"print(1)\n")
    _, names = _left_out(project)
    assert "out/src_code.py" in names


def test_without_a_repository_build_folders_are_kept(project):
    shutil.rmtree(os.path.join(project, ".git"), onerror=lambda f, p, e: (os.chmod(p, 0o700), f(p)))
    _write(project, "target/a.bin", b"x")
    _, names = _left_out(project)
    assert "target/a.bin" in names


@pytest.mark.parametrize("rel, refused", [
    ("Desktop", True), ("Documents", True), ("Downloads", True), ("OneDrive - Org", True),
    ("Desktop/my-app", False), ("OneDrive - Org/app", False), ("OneDriveClientProject", False), ("code", False)])
def test_the_homes_catch_all_folders_are_not_projects(tmp_path, monkeypatch, rel, refused):
    home = tmp_path / "home"
    folder = home / rel
    folder.mkdir(parents=True)
    (home / "OneDrive - Org").mkdir(exist_ok=True)
    monkeypatch.setenv("OneDriveCommercial", str(home / "OneDrive - Org"))
    got = undo._shared_folder(os.path.realpath(str(folder)), [str(home)])
    assert got is refused


@pytest.mark.skipif(os.name != "nt", reason="Windows known folders")
def test_where_windows_keeps_the_desktop_is_not_a_project():
    known = undo._windows_known_folders()
    assert len(known) == 3
    assert undo._shared_folder(os.path.realpath(known[0]), [])
    assert not undo._shared_folder(os.path.realpath(os.path.join(known[0], "my-app")), [])


def _store_files(data, key, age_days):
    root = os.path.join(os.path.realpath(data), "undo")
    os.makedirs(os.path.join(root, key + ".git", "objects"), exist_ok=True)
    obj = os.path.join(root, key + ".git", "objects", "o")
    with open(obj, "w") as f:
        f.write("x")
    os.chmod(obj, 0o444)  # as git leaves its objects
    log = os.path.join(root, key + ".jsonl")
    with open(log, "w") as f:
        f.write("{}\n")
    old = time.time() - age_days * 86400
    os.utime(log, (old, old))
    return root


def test_stores_of_projects_not_used_for_30_days_go(tmp_path):
    data = str(tmp_path / "data")
    root = _store_files(data, "a" * 16, 31)
    _store_files(data, "b" * 16, 29)
    assert undo.clean_stale(data) == 1
    assert not os.path.exists(os.path.join(root, "a" * 16 + ".git"))
    assert not os.path.exists(os.path.join(root, "a" * 16 + ".jsonl"))
    assert os.path.exists(os.path.join(root, "b" * 16 + ".jsonl"))


def test_a_store_in_use_is_left(tmp_path):
    data = str(tmp_path / "data")
    root = _store_files(data, "c" * 16, 40)
    holder = undo.Store.__new__(undo.Store)
    holder.project, holder.root, holder._held, holder._special, holder.record_by = "", root, None, [], None
    holder.shadow, holder.log, holder.lock = (os.path.join(root, "c" * 16 + e) for e in (".git", ".jsonl", ".lock"))
    assert holder.acquire()
    try:
        assert undo.clean_stale(data) == 0
    finally:
        holder.release()
    assert os.path.exists(os.path.join(root, "c" * 16 + ".jsonl"))
    assert undo.clean_stale(data) == 1


@pytest.mark.skipif(os.name != "nt", reason="Windows: an open file cannot be removed")
def test_a_record_someone_has_open_keeps_its_copies_too(tmp_path):
    data = str(tmp_path / "data")
    root = _store_files(data, "e" * 16, 40)
    with open(os.path.join(root, "e" * 16 + ".jsonl")):
        assert undo.clean_stale(data) == 0
    assert os.path.isdir(os.path.join(root, "e" * 16 + ".git"))
    assert undo.clean_stale(data) == 1


def test_copies_left_without_a_record_go_too(tmp_path):
    data = str(tmp_path / "data")
    root = _store_files(data, "f" * 16, 40)
    os.remove(os.path.join(root, "f" * 16 + ".jsonl"))
    old = time.time() - 40 * 86400
    os.utime(os.path.join(root, "f" * 16 + ".git"), (old, old))
    assert undo.clean_stale(data) == 1
    assert not os.path.exists(os.path.join(root, "f" * 16 + ".git"))


def test_undo_clean_from_the_command_line(tmp_path, monkeypatch):
    data = str(tmp_path / "data")
    _store_files(data, "d" * 16, 31)
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", data)
    assert undo._cli(["undo-clean"]) == 0
    assert undo.clean_stale(data) == 0
