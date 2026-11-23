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


def test_turned_on_by_the_user_a_snapshot_still_stands_in(project):
    assert os.environ["CLAUDE_PLUGIN_OPTION_UNDO"] == "true"
    assert _decision(_payload(project, "git reset --hard")) is None


@pytest.mark.parametrize("value", ["false", "", "true"])
def test_a_restore_always_asks(project, monkeypatch, value):
    monkeypatch.setenv("CLAUDE_PLUGIN_OPTION_UNDO", value)
    line = f'"{os.environ["CLAUDE_PLUGIN_DATA"]}/current/bdxguard.exe" undo restore 1 "{project}"'
    assert _decision(_payload(project, line)) == "ask"
    assert _decision(dict(_payload(project, line), permission_mode="bypassPermissions")) == "deny"


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


def test_without_a_repository_build_folders_are_kept(project):
    shutil.rmtree(os.path.join(project, ".git"), onerror=lambda f, p, e: (os.chmod(p, 0o700), f(p)))
    _write(project, "target/a.bin", b"x")
    _, names = _left_out(project)
    assert "target/a.bin" in names


@pytest.mark.parametrize("rel, refused", [
    ("Desktop", True), ("Documents", True), ("downloads", True), ("OneDrive", True),
    ("OneDrive - Company", True), ("OneDrive/Desktop", True),
    ("Desktop/my-app", False), ("OneDrive/Documents/app", False), ("code", False)])
def test_the_homes_catch_all_folders_are_not_projects(tmp_path, monkeypatch, rel, refused):
    home = tmp_path / "home"
    folder = home / rel
    folder.mkdir(parents=True)
    got = undo._shared_folder(os.path.realpath(str(folder)), [str(home)])
    assert got is refused


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


def test_undo_clean_from_the_command_line(tmp_path, monkeypatch):
    data = str(tmp_path / "data")
    _store_files(data, "d" * 16, 31)
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", data)
    assert undo._cli(["undo-clean"]) == 0
    assert undo.clean_stale(data) == 0
