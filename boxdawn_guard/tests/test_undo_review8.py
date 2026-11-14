"""`undo`: what the eighth review found, each as a test."""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import threading
import time

import pytest

from boxdawn_guard import command_hook, undo
from boxdawn_guard.tests.test_undo import _payload, _store, _write, project  # noqa: F401 - `project` is a fixture

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")

SRC = os.path.dirname(os.path.dirname(os.path.abspath(undo.__file__)))  # the folder that holds boxdawn_guard


def _data():
    return os.environ["CLAUDE_PLUGIN_DATA"]


@pytest.mark.parametrize("command, tool", [("bdxguard undo list\nmake", "Bash"),
                                           ("bdxguard undo list\n{rm,-rf,.}", "Bash"),
                                           ("bdxguard.exe undo restore 1\n{rm,-rf,src}", "Bash"),
                                           ("bdxguard undo list\r\n.\\wipe.ps1", "PowerShell"),
                                           ('"C:/x/bdxguard.exe" undo list "C:/p\n./wipe.sh"', "Bash"),
                                           ("bdxguard undo list x\n", "Bash")])
def test_a_second_line_after_the_undo_command_gets_a_snapshot(project, command, tool):
    command_hook._snapshot_before(_payload(project, command, tool), None)
    assert _store(project).rows()[-1].get("before") == command


def test_one_holder_at_a_time_when_many_start_together(project, tmp_path):
    """Several processes try at once, with a lock file left by one that died: one gets it."""
    store = _store(project)
    os.makedirs(store.root, exist_ok=True)
    with open(store.lock, "w") as f:
        f.write("12345")  # what a process that died might have left
    go = str(tmp_path / "go")
    code = ("import os, sys, time; from boxdawn_guard import undo\n"
            "while not os.path.exists(sys.argv[3]): time.sleep(0.001)\n"
            "s = undo.Store(sys.argv[1], sys.argv[2]); got = s.acquire()\n"
            "print(got, flush=True); time.sleep(1.5)\n")
    env = dict(os.environ, PYTHONPATH=SRC, PYTHONDONTWRITEBYTECODE="1")
    for _ in range(5):
        procs = [subprocess.Popen([sys.executable, "-c", code, os.path.realpath(project), _data(), go], env=env,
                                  stdout=subprocess.PIPE, text=True, cwd=str(tmp_path)) for _ in range(6)]
        time.sleep(1.0)
        open(go, "w").close()
        got = [p.communicate(timeout=60)[0].strip() for p in procs]
        os.remove(go)
        assert got.count("True") == 1, got


@pytest.mark.skipif(os.name != "nt", reason="an open file cannot be replaced on Windows only")
@pytest.mark.parametrize("held_for", [0.5, 1.0, 2.3, 2.5, 2.7])
def test_a_row_written_while_the_clean_up_waits_for_a_reader_is_kept(project, held_for):
    for i in range(3):
        _write(project, "n.txt", str(i).encode())
        undo.before_command(_payload(project, f"echo {i}"), _data())
    store = _store(project)
    reader = open(store.log, encoding="utf-8")
    threading.Timer(held_for, reader.close).start()
    writer = threading.Timer(0.45, lambda: _store(project).note({"unprotected": "x", "before": "the writer"}))
    writer.start()
    assert store.acquire()
    try:
        try:
            store.prune(now=store.rows()[-1]["at"] + undo.KEEP_SECONDS + 100)
        except PermissionError:
            pass  # the reader held on: nothing dropped, to be tried next time
    finally:
        store.release()
    writer.join()
    time.sleep(max(0.0, held_for - 0.5) + 0.2)
    assert "the writer" in [r.get("before") for r in _store(project).rows()]
    assert [r["n"] for r in _store(project).snapshots()] in ([3], [1, 2, 3])


@pytest.mark.skipif(os.name != "nt", reason="an open file cannot be replaced on Windows only")
def test_the_clean_up_holds_the_record_well_under_what_a_writer_waits(project):
    """The cause of a lost row: a writer that waited `LOG_WAIT` for its turn writes anyway."""
    for i in range(3):
        _write(project, "n.txt", str(i).encode())
        undo.before_command(_payload(project, f"echo {i}"), _data())
    store = _store(project)
    with open(store.log, encoding="utf-8"):  # a reader for the whole clean-up
        assert store.acquire()
        started = time.perf_counter()
        try:
            with pytest.raises(PermissionError):
                store.prune(now=store.rows()[-1]["at"] + undo.KEEP_SECONDS + 100)
        finally:
            store.release()
        held = time.perf_counter() - started
    assert held < undo.LOG_WAIT / 2, held


def test_the_list_says_before_only_for_a_command(project, capsys):
    undo.start(project, _data())
    undo.before_command(_payload(project, "echo hi"), _data())
    capsys.readouterr()
    undo._cli(["undo", "list", project])
    out = capsys.readouterr().out
    assert "  session start" in out and "before: session start" not in out and "before: echo hi" in out


def test_a_git_stopped_over_budget_leaves_no_lock_for_the_next_snapshot(project, monkeypatch):
    undo.before_command(_payload(project), _data())
    store = _store(project)
    real = undo.Store.git

    def stopped(self, *args, **kw):
        if "write-tree" in args:  # as a git killed mid-way would: its lock stays behind
            open(os.path.join(self.shadow, "index.lock"), "w").close()
            raise subprocess.TimeoutExpired("git", 1)
        return real(self, *args, **kw)
    monkeypatch.setattr(undo.Store, "git", stopped)
    monkeypatch.setattr(undo, "start_in_background", lambda *a: None)
    _write(project, "n.txt", b"changed")
    undo.before_command(_payload(project, "echo two"), _data())
    monkeypatch.setattr(undo.Store, "git", real)
    assert not os.path.exists(os.path.join(store.shadow, "index.lock"))
    undo.before_command(_payload(project, "echo three"), _data())
    assert _store(project).rows()[-1].get("before") == "echo three" and "n" in _store(project).rows()[-1]
