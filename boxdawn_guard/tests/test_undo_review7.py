"""`undo`: what the seventh review found, each as a test."""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import threading

import pytest

from boxdawn_guard import command_hook, undo
from boxdawn_guard.tests.test_undo import _payload, _store, _write, project  # noqa: F401 - `project` is a fixture
from boxdawn_guard.tests.test_undo_review6 import _held_open

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")


def _data():
    return os.environ["CLAUDE_PLUGIN_DATA"]


def _read(root, rel):
    with open(os.path.join(root, rel), "rb") as f:
        return f.read()


def _small(tmp_path, monkeypatch, files):
    root = str(tmp_path / "small")
    for rel, data in files.items():
        _write(root, rel, data)
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", root)
    return os.path.realpath(root)


def test_going_back_after_a_wipe_that_left_a_file_too_large_to_save(project, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(undo, "MAX_FILE_BYTES", 1000)
    root = _small(tmp_path, monkeypatch, {"a.txt": b"a1", "src/b.txt": b"b1", "model.bin": b"m" * 5000})
    undo.before_command(_payload(root, "rm -rf ./*"), _data())
    for rel in ("a.txt", "src/b.txt"):
        os.remove(os.path.join(root, rel))
    undo.before_command(_payload(root, "ls"), _data())  # nothing it can save: no numbered snapshot
    capsys.readouterr()
    assert undo._cli(["undo", "restore", "1", root]) == 0, capsys.readouterr()
    assert _read(root, "a.txt") == b"a1" and _read(root, "src/b.txt") == b"b1"
    assert _read(root, "model.bin") == b"m" * 5000


@pytest.mark.skipif(os.name != "nt", reason="files held with no sharing are a Windows thing")
def test_going_back_after_a_wipe_that_left_a_file_held_open(project, tmp_path, monkeypatch, capsys):
    root = _small(tmp_path, monkeypatch, {"a.txt": b"a1", ".vs/idx/f0.vsidx": b"index"})
    with _held_open([os.path.join(root, ".vs", "idx", "f0.vsidx")]):
        undo.before_command(_payload(root, "dotnet build"), _data())
        os.remove(os.path.join(root, "a.txt"))
        capsys.readouterr()
        assert undo._cli(["undo", "restore", "1", root]) == 0, capsys.readouterr()
    assert _read(root, "a.txt") == b"a1"


def _three(project):
    for i in range(3):
        _write(project, "n.txt", str(i).encode())
        undo.before_command(_payload(project, f"echo {i}"), _data())
    return _store(project)


def test_the_clean_up_waits_for_a_reader_of_the_record(project):
    store = _three(project)
    reader = open(store.log, encoding="utf-8")
    threading.Timer(0.5, reader.close).start()
    assert store.acquire()
    try:
        assert store.prune(now=store.rows()[-1]["at"] + undo.KEEP_SECONDS + 100) == 2
    finally:
        store.release()
    assert [r["n"] for r in store.snapshots()] == [3]


@pytest.mark.skipif(os.name != "nt", reason="an open file cannot be replaced on Windows only")
def test_a_clean_up_that_cannot_rewrite_the_record_drops_nothing(project, capsys):
    store = _three(project)
    with open(store.log, encoding="utf-8"):
        assert store.acquire()
        try:
            with pytest.raises(PermissionError):
                store.prune(now=store.rows()[-1]["at"] + undo.KEEP_SECONDS + 100)
        finally:
            store.release()
    assert [r["n"] for r in store.snapshots()] == [1, 2, 3]
    capsys.readouterr()
    assert undo._cli(["undo", "restore", "1", project]) == 0, capsys.readouterr()  # still there to go back to
    assert _read(project, "n.txt") == b"0"


def test_the_session_start_snapshot_is_kept_when_the_clean_up_fails(project, monkeypatch):
    def broken(self, now=None):
        raise PermissionError("someone is reading the record")
    monkeypatch.setattr(undo.Store, "prune", broken)
    result = undo.start(project, _data())
    assert result.startswith("snapshot 1") and "left for next time" in result
    assert not [r for r in _store(project).rows() if "unprotected" in r]


def test_a_lock_left_by_a_process_that_is_gone_does_not_hold_snapshots_back(project):
    gone = subprocess.Popen([sys.executable, "-c", "pass"])
    gone.wait()
    store = _store(project)
    os.makedirs(store.root, exist_ok=True)
    with open(store.lock, "w") as f:
        f.write(str(gone.pid))
    undo.before_command(_payload(project, "rm -rf src"), _data())
    assert isinstance(_store(project).rows()[-1].get("n"), int)


def test_a_lock_held_by_a_running_process_still_holds(project):
    holder = _store(project)
    assert holder.acquire()
    try:
        assert not _store(project).acquire()
    finally:
        holder.release()
    assert _store(project).acquire()


def test_a_stop_part_way_also_names_what_was_left_as_it_is(project, monkeypatch, capsys):
    _write(project, "a.txt", b"a1")
    _write(project, "b.txt", b"b1")
    _write(project, "c.txt", b"c1")
    undo.before_command(_payload(project), _data())
    _write(project, "a.txt", b"a2")
    _write(project, "b.txt", b"b2")
    os.remove(os.path.join(project, "c.txt"))
    os.makedirs(os.path.join(project, "c.txt"))
    real = undo.Store.git

    def half(self, *args, **kw):
        if "checkout" in args:
            real(self, "checkout", args[args.index("checkout") + 1], "--", "a.txt")
            raise RuntimeError("git checkout: error: unable to unlink old 'b.txt'")
        return real(self, *args, **kw)
    monkeypatch.setattr(undo.Store, "git", half)
    capsys.readouterr()
    assert undo._cli(["undo", "restore", "1", project]) == 1
    err = capsys.readouterr().err
    assert "left as it is: c.txt (it is a folder now)" in err and "put back: a.txt" in err


@pytest.mark.parametrize("command", ['git commit -m "fix: bdxguard undo list said nothing"',
                                     "echo bdxguard undo restore 1; rm -rf src",
                                     'bdxguard undo list "$(rm -rf src)"'])
def test_a_line_that_only_mentions_the_undo_command_gets_a_snapshot(project, command):
    command_hook._snapshot_before(_payload(project, command), None)
    assert _store(project).rows()[-1].get("before") == command


@pytest.mark.parametrize("command", ['"C:/x/data/current/bdxguard.exe" undo list "C:/proj"',
                                     '& "C:\\x\\bdxguard.exe" undo restore 2 .',
                                     "bdxguard undo restore 1", "../data/current/bdxguard.exe undo list"])
def test_the_undo_command_alone_takes_no_snapshot(project, command):
    command_hook._snapshot_before(_payload(project, command), None)
    assert _store(project).rows() == []


def test_a_restore_line_still_keeps_secret_files_out_of_its_grep(project):
    out = command_hook.decide(_payload(project, "bdxguard undo restore 1; grep -r KEY ."))
    h = out["hookSpecificOutput"]
    assert h["permissionDecision"] == "ask"
    assert "--exclude" in h["updatedInput"]["command"]


def test_a_late_snapshot_names_the_command_it_was_for(project):
    assert undo._cli(["undo-start", project, "late", "echo first"]) == 0
    assert _store(project).snapshots()[-1]["note"].endswith("echo first")


def test_a_late_snapshot_that_cannot_be_taken_says_so(project):
    store = _store(project)
    assert store.acquire()
    try:
        undo._cli(["undo-start", project, "late", "echo first"])
    finally:
        store.release()
    row = _store(project).rows()[-1]
    assert row["before"] == "echo first" and "not taken" in row["unprotected"]
