"""`undo`: snapshots before a command, and the way back."""
from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import time

import pytest

from boxdawn_guard import command_hook, undo

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")


def _write(root, rel, data: bytes):
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


def _state(root):
    out = {}
    for folder, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d != ".git"]
        for name in files:
            path = os.path.join(folder, name)
            with open(path, "rb") as f:
                out[os.path.relpath(path, root).replace("\\", "/")] = hashlib.sha256(f.read()).hexdigest()
    return out


def _git(root, *args):
    return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@localhost", *args], cwd=root, check=True,
                          capture_output=True, text=True).stdout


@pytest.fixture
def project(tmp_path, monkeypatch):
    """A repository with a committed file, an uncommitted change, an untracked file,
    ignored files and a heavy folder; `undo` on, the data folder next to it."""
    root = str(tmp_path / "proj")
    _write(root, ".gitignore", b".env\ndata/\nnode_modules/\n")
    _write(root, "src/app.py", b"print('v1')\n")
    _write(root, "mixed.txt", b"unix\nwindows\r\nlast")
    _write(root, ".gitattributes", b"*.txt text eol=crlf\n")
    _git(root, "init", "-q")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "first")
    _write(root, "src/app.py", b"print('v2, not committed')\n")
    _write(root, "notes.txt", b"untracked\n")
    _write(root, ".env", b"KEY=not-a-real-key\n")
    _write(root, "data/deep/rows.bin", os.urandom(4096))
    _write(root, "node_modules/pkg/index.js", b"module.exports = 1\n")
    monkeypatch.setenv("CLAUDE_PLUGIN_OPTION_UNDO", "true")
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(tmp_path / "data"))
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", root)
    monkeypatch.setattr(undo, "SUPPORTED", (sys.platform,))  # the mechanism is tested wherever the tests run
    return root


def _store(project):
    return undo.Store(os.path.realpath(project), os.environ["CLAUDE_PLUGIN_DATA"])


def _payload(project, command="ls", tool="Bash"):
    return {"tool_name": tool, "tool_input": {"command": command}, "cwd": project, "session_id": "s",
            "permission_mode": "default"}


def _hook(payload, monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(payload)))
    assert command_hook.main() == 0
    return capsys.readouterr().out


def test_every_kind_of_file_comes_back_byte_for_byte(project):
    before = _state(project)
    status = _git(project, "status", "--porcelain")
    undo.before_command(_payload(project, "python wipe.py"), os.environ["CLAUDE_PLUGIN_DATA"])
    assert _git(project, "status", "--porcelain") == status  # taking one wrote nothing in the project
    shutil.rmtree(os.path.join(project, "data"))
    shutil.rmtree(os.path.join(project, "src"))
    os.remove(os.path.join(project, ".env"))
    _write(project, "mixed.txt", b"ruined")
    _write(project, "made_later.txt", b"new")
    store = _store(project)
    assert store.acquire()
    target, present, skipped = store.restore(1)
    store.release()
    assert skipped == {}
    after = _state(project)
    assert {k: v for k, v in after.items() if k != "made_later.txt"} == before
    assert "made_later.txt" in after  # a file made since is not deleted
    assert (target["n"], present["n"]) == (1, 2)  # the present was kept too
    assert target["before"] == "python wipe.py"


def test_heavy_folders_are_left_out(project):
    undo.before_command(_payload(project), os.environ["CLAUDE_PLUGIN_DATA"])
    store = _store(project)
    names = store.git("ls-tree", "-r", "--name-only", store.snapshots()[0]["commit"]).decode().split()
    assert ".env" in names and "data/deep/rows.bin" in names
    assert not [n for n in names if n.startswith("node_modules/")]


def test_a_file_over_the_limit_is_left_out_and_named(project, monkeypatch):
    monkeypatch.setattr(undo, "MAX_FILE_BYTES", 1000)
    _write(project, "small.bin", b"x" * 10)
    data = os.environ["CLAUDE_PLUGIN_DATA"]
    undo.before_command(_payload(project), data)
    _write(project, "small.bin", b"y" * 2000)  # grew past the limit after it was saved once
    undo.before_command(_payload(project), data)
    store = _store(project)
    first, second = store.snapshots()
    assert "data/deep/rows.bin" in first["too_large"] and "small.bin" in second["too_large"]
    names = store.git("ls-tree", "-r", "--name-only", second["commit"]).decode().split()
    assert "small.bin" not in names  # the old, small version would otherwise come back over the new one


def test_nothing_changed_takes_no_new_commit(project):
    data = os.environ["CLAUDE_PLUGIN_DATA"]
    undo.before_command(_payload(project), data)
    undo.before_command(_payload(project), data)
    first, second = _store(project).snapshots()
    assert first["commit"] == second["commit"] and second["n"] == 2


def test_off_by_default(project, monkeypatch, capsys):
    monkeypatch.delenv("CLAUDE_PLUGIN_OPTION_UNDO")
    assert _hook(_payload(project), monkeypatch, capsys) == ""
    assert not os.path.exists(_store(project).root)


def test_the_hook_takes_one_and_says_nothing(project, monkeypatch, capsys):
    assert _hook(_payload(project, "ls -la"), monkeypatch, capsys) == ""
    _hook(_payload(project, "Get-ChildItem", tool="PowerShell"), monkeypatch, capsys)  # asks where its reader is missing
    assert [r["before"] for r in _store(project).snapshots()] == ["ls -la", "Get-ChildItem"]


def test_an_ask_still_asks_and_a_denied_command_takes_none(project, monkeypatch, capsys):
    ask = json.loads(_hook(_payload(project, "git reset --hard HEAD"), monkeypatch, capsys))
    assert ask["hookSpecificOutput"]["permissionDecision"] == "ask"
    assert len(_store(project).snapshots()) == 1
    deny = json.loads(_hook(_payload(project, "rm -rf ~"), monkeypatch, capsys))
    assert deny["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert len(_store(project).snapshots()) == 1


def test_other_tools_take_none(project, monkeypatch, capsys):
    _hook({"tool_name": "Read", "tool_input": {"file_path": "src/app.py"}, "cwd": project}, monkeypatch, capsys)
    assert not _store(project).snapshots()


def test_a_snapshot_that_fails_changes_nothing(project, monkeypatch, capsys):
    def boom(*a, **k):
        raise OSError("disk full")
    monkeypatch.setattr(undo, "before_command", boom)
    assert _hook(_payload(project, "ls"), monkeypatch, capsys) == ""
    ask = json.loads(_hook(_payload(project, "git reset --hard HEAD"), monkeypatch, capsys))
    assert ask["hookSpecificOutput"]["permissionDecision"] == "ask"


def test_over_the_budget_the_command_goes_on_and_the_rest_runs_in_the_background(project, monkeypatch):
    started = []
    monkeypatch.setattr(undo, "start_in_background", lambda *args: started.append(args))

    def slow(self, *args, **kwargs):
        raise subprocess.TimeoutExpired("git", 3)
    monkeypatch.setattr(undo.Store, "_changed", slow)
    undo.before_command(_payload(project), os.environ["CLAUDE_PLUGIN_DATA"])
    store = _store(project)
    assert started == [(os.path.realpath(project), "ls")]  # the late row will name the command
    assert "unprotected" in store.rows()[-1] and not store.snapshots()
    assert store.acquire()  # the lock was given back


def test_while_another_is_being_taken_the_command_does_not_wait(project):
    store = _store(project)
    assert store.acquire()
    undo.before_command(_payload(project), os.environ["CLAUDE_PLUGIN_DATA"])
    assert "unprotected" in store.rows()[-1] and not store.snapshots()


def test_a_lock_left_by_a_dead_process_is_taken_over(project):
    """A real process takes the lock and is killed while it holds it (as a hook stopped mid-snapshot)."""
    src = os.path.dirname(os.path.dirname(os.path.abspath(undo.__file__)))
    code = ("import sys, time; from boxdawn_guard import undo\n"
            "s = undo.Store(sys.argv[1], sys.argv[2]); assert s.acquire(); print('held', flush=True); time.sleep(60)\n")
    # The python itself: a venv's python.exe is a launcher, and killing it leaves its child holding the lock.
    python = getattr(sys, "_base_executable", None) or sys.executable
    holder = subprocess.Popen([python, "-c", code, os.path.realpath(project), os.environ["CLAUDE_PLUGIN_DATA"]],
                              stdout=subprocess.PIPE, env=dict(os.environ, PYTHONPATH=src), cwd=os.path.dirname(project))
    assert holder.stdout.readline().strip() == b"held"
    store = _store(project)
    assert not store.acquire()
    holder.kill()
    holder.wait()
    assert store.acquire()


@pytest.mark.parametrize("where", ["home", "above", "root"])
def test_the_home_folder_and_above_are_never_a_project(where, tmp_path, monkeypatch):
    home = tmp_path / "home" / "me"
    home.mkdir(parents=True)
    monkeypatch.setattr(os.path, "expanduser", lambda p: str(home) if p == "~" else p)
    project = {"home": str(home), "above": str(tmp_path / "home"),
               "root": os.path.abspath(os.sep)}[where]
    assert undo._refused(os.path.realpath(project), str(tmp_path / "data"))


def test_a_project_around_the_store_is_refused(tmp_path):
    assert undo._refused(str(tmp_path), str(tmp_path / "inside" / "data"))


def test_old_snapshots_are_dropped_and_the_newest_stays(project):
    data = os.environ["CLAUDE_PLUGIN_DATA"]
    for i in range(3):
        _write(project, "notes.txt", b"version %d\n" % i)
        undo.before_command(_payload(project), data)
    store = _store(project)
    assert store.acquire()
    assert store.prune(now=store.snapshots()[-1]["at"] + undo.KEEP_SECONDS + 5) == 2
    assert [r["n"] for r in store.snapshots()] == [3]
    store.restore(3)  # what is left still works
    with pytest.raises(LookupError):
        store.restore(1)


def test_over_the_size_limit_the_oldest_go(project, monkeypatch):
    data = os.environ["CLAUDE_PLUGIN_DATA"]
    for i in range(4):
        _write(project, "blob.bin", os.urandom(50_000))
        undo.before_command(_payload(project), data)
    store = _store(project)
    monkeypatch.setattr(undo, "MAX_STORE_BYTES", 150_000)
    assert store.acquire()
    assert store.prune() >= 1
    assert store.snapshots()[-1]["n"] == 4  # the newest stays whatever the size


def test_the_commands(project, monkeypatch, capsys):
    assert undo._cli(["undo-start", project]) == 0
    os.remove(os.path.join(project, ".env"))
    assert undo._cli(["undo", "list", project]) == 0
    assert "session start" in capsys.readouterr().out
    assert undo._cli(["undo", "restore", "1", project]) == 0
    assert os.path.exists(os.path.join(project, ".env"))
    assert undo._cli(["undo", "restore", "99", project]) == 1
    assert _store(project).acquire()  # a failed restore gave the lock back
