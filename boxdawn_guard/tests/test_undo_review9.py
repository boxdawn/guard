"""`undo`: what the ninth review found, each as a test."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time

import pytest

from boxdawn_guard import command_hook, undo
from boxdawn_guard.tests.test_undo import _payload, _store, _write, project  # noqa: F401 - `project` is a fixture

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")

SRC = os.path.dirname(os.path.dirname(os.path.abspath(undo.__file__)))
PYTHON = getattr(sys, "_base_executable", None) or sys.executable  # not a venv launcher: killing it kills it


def _data():
    return os.environ["CLAUDE_PLUGIN_DATA"]


def _running(pid: int) -> bool:
    out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/NH"], capture_output=True, text=True).stdout
    return str(pid) in out


@pytest.mark.skipif(os.name != "nt", reason="Windows jobs")
def test_a_program_the_store_runs_ends_when_the_process_that_ran_it_is_killed(tmp_path):
    """As a git under a hook that Claude Code stopped, or under a restore stopped with Ctrl+C."""
    pid_file = str(tmp_path / "child.pid")
    child = f"import os, time; open({pid_file!r}, 'w').write(str(os.getpid())); time.sleep(60)"
    holder_code = ("import sys; from boxdawn_guard import undo\n"
                   "undo._run([sys.argv[1], '-c', sys.argv[2]], cwd='.', env=None, stdin=None, timeout=None)\n")
    holder = subprocess.Popen([PYTHON, "-c", holder_code, PYTHON, child], env=dict(os.environ, PYTHONPATH=SRC),
                              cwd=str(tmp_path))
    deadline = time.monotonic() + 30
    while not (os.path.exists(pid_file) and open(pid_file).read()) and time.monotonic() < deadline:
        time.sleep(0.05)
    pid = int(open(pid_file).read())
    assert _running(pid)
    holder.kill()  # only the holder, as Claude Code ends a hook that ran over its time
    holder.wait()
    deadline = time.monotonic() + 5
    while _running(pid) and time.monotonic() < deadline:
        time.sleep(0.1)
    assert not _running(pid)


@pytest.mark.skipif(os.name != "nt", reason="Windows jobs")
def test_a_program_run_normally_still_gives_its_output():
    code, out, err = undo._run([sys.executable, "-c", "print('hi')"], cwd=os.getcwd(), env=dict(os.environ),
                               stdin=None, timeout=30)
    assert (code, out.strip()) == (0, b"hi")


@pytest.mark.parametrize("command, tool", [("&{.\\mark.cmd}bdxguard undo list", "PowerShell"),
                                           ("& {.\\mark.cmd}bdxguard.exe undo restore 1", "PowerShell"),
                                           ("PATH=.:/usr/bin:bdxguard undo list", "Bash"),
                                           ("./evilbdxguard undo list", "Bash"),
                                           ("*/bdxguard undo list", "Bash"),
                                           ("bdxguard undo list {a,b}", "Bash")])
def test_a_line_that_runs_something_else_gets_a_snapshot(project, command, tool):
    command_hook._snapshot_before(_payload(project, command, tool), None)
    assert _store(project).rows()[-1].get("before") == command


@pytest.mark.parametrize("command", ['"C:/Program Files/x/bdxguard.exe" undo list "C:/my project"',
                                     "C:/x/data/current/bdxguard.exe undo restore 3 C:/p",
                                     "bdxguard undo list"])
def test_the_undo_command_alone_still_takes_no_snapshot(project, command):
    command_hook._snapshot_before(_payload(project, command), None)
    assert _store(project).rows() == []


def test_looking_through_one_huge_folder_stops_at_the_budget(project, monkeypatch):
    for i in range(3000):  # folders, in the first folder the walk looks into: the project itself
        os.mkdir(os.path.join(project, f"d{i}"))
    store = _store(project)
    store._init()
    looked = []  # each folder entry is looked at for a `.git` in it
    lexists = os.path.lexists
    monkeypatch.setattr(os.path, "lexists", lambda p: looked.append(p) or lexists(p))
    calls = []

    def once_then_over():  # the first look at the clock is free; the second finds the budget spent
        calls.append(len(looked))
        if len(calls) > 1:
            raise subprocess.TimeoutExpired("snapshot", 0)
    with pytest.raises(subprocess.TimeoutExpired):
        store._folders_left_out(once_then_over)
    assert calls[-1] < 1000, calls  # the budget was looked at inside the folder, not after all its entries


def test_a_lock_git_left_when_its_holder_was_stopped_does_not_stop_the_next_snapshot(project):
    """Its git ended with its holder (the job): the lock it left is fresh, and only in the way."""
    undo.before_command(_payload(project, "echo one"), _data())
    store = _store(project)
    open(os.path.join(store.shadow, "index.lock"), "w").close()
    _write(project, "n.txt", b"changed")
    undo.before_command(_payload(project, "echo two"), _data())
    row = _store(project).rows()[-1]
    assert row.get("before") == "echo two" and isinstance(row.get("n"), int), row


def test_a_lock_file_that_cannot_be_opened_says_so(project):
    store = _store(project)
    os.makedirs(os.path.join(store.lock, "kept"))  # a folder with something in it: cannot be removed
    undo.before_command(_payload(project, "rm -rf src"), _data())
    row = _store(project).rows()[-1]
    assert "lock file cannot be opened" in row["unprotected"] and "still being taken" not in row["unprotected"]


def test_a_long_record_lists_quickly(project, capsys):
    store = _store(project)
    os.makedirs(store.root, exist_ok=True)
    now = time.time()
    with open(store.log, "w", encoding="utf-8") as f:
        for i in range(1, 16001):
            f.write(json.dumps({"at": now, "n": i, "commit": "a" * 40, "tree": "b" * 40, "before": f"echo {i}"}) + "\n")
    started = time.perf_counter()
    assert undo._cli(["undo", "list", project]) == 0
    assert time.perf_counter() - started < 2.0
    assert "before: echo 16000" in capsys.readouterr().out
