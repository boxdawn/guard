"""`undo`: what the tenth review found, each as a test."""
from __future__ import annotations

import os
import shutil
import subprocess
import sys

import pytest

from boxdawn_guard import undo
from boxdawn_guard.tests.test_undo import _payload, _store, _write, project  # noqa: F401 - `project` is a fixture

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")


def _data():
    return os.environ["CLAUDE_PLUGIN_DATA"]


def _read(root, rel):
    with open(os.path.join(root, rel), "rb") as f:
        return f.read()


def _three(project):
    for i in range(3):
        _write(project, "n.txt", str(i).encode())
        undo.before_command(_payload(project, f"echo {i}"), _data())
    return _store(project)


def _refs(store):
    out = subprocess.run(["git", f"--git-dir={store.shadow}", "for-each-ref", "--format=%(refname)", "refs/snap/"],
                         capture_output=True, text=True, check=True).stdout.split()
    return sorted(int(ref.rsplit("/", 1)[1]) for ref in out)


def _plant(store, *rel):
    path = os.path.join(store.shadow, *rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w"):
        pass
    return path


# -- 1: a lock a stopped git left on a ref --------------------------------------------------
def test_a_ref_lock_left_by_a_stopped_git_does_not_stop_the_next_snapshot(project):
    store = _three(project)
    left = _plant(store, "refs", "snap", "4.lock")  # as a git killed inside `update-ref refs/snap/4`
    _write(project, "n.txt", b"later")
    undo.before_command(_payload(project, "echo later"), _data())
    row = store.rows()[-1]
    assert row.get("n") == 4 and "unprotected" not in row, row
    assert not os.path.exists(left)


def test_a_ref_lock_left_by_a_stopped_git_does_not_stop_going_back(project, capsys):
    store = _three(project)
    _plant(store, "refs", "snap", "4.lock")
    os.remove(os.path.join(project, "n.txt"))  # the mistake
    assert undo._cli(["undo", "restore", "1", project]) == 0, capsys.readouterr()
    assert _read(project, "n.txt") == b"0"


@pytest.mark.parametrize("rel", [("packed-refs.lock",), ("HEAD.lock",), ("refs", "snap", "deep", "x.lock"),
                                 ("objects", "info", "commit-graph.lock"), ("gc.pid",), ("gc.pid.lock",)])
def test_the_holder_of_the_lock_clears_what_a_stopped_git_left(project, rel):
    store = _three(project)
    left = _plant(store, *rel)
    assert store.acquire()
    store.release()
    assert not os.path.exists(left)


def test_nothing_but_lock_files_is_cleared(project):
    store = _three(project)
    before = sorted(os.path.join(f, n) for f, _, names in os.walk(store.shadow) for n in names)
    assert store.acquire()
    store.release()
    assert sorted(os.path.join(f, n) for f, _, names in os.walk(store.shadow) for n in names) == before


# -- 2: the clean-up after a lock on packed-refs, and what an earlier clean-up left ----------
def test_the_clean_up_works_after_a_lock_left_on_packed_refs(project):
    store = _three(project)
    _plant(store, "packed-refs.lock")  # as a `gc` killed mid-way
    assert store.acquire()
    try:
        assert store.prune(now=store.rows()[-1]["at"] + undo.KEEP_SECONDS + 100) == 2
    finally:
        store.release()
    assert [r["n"] for r in store.snapshots()] == [3] and _refs(store) == [3]


def test_a_clean_up_stopped_after_the_record_is_finished_by_the_next_one(project, monkeypatch):
    store = _three(project)
    real = undo.Store.git

    def no_deleting(self, *args, **kwargs):
        if "update-ref" in args and "--stdin" in args:
            raise RuntimeError("git update-ref: stopped here")
        return real(self, *args, **kwargs)
    monkeypatch.setattr(undo.Store, "git", no_deleting)
    assert store.acquire()
    try:
        with pytest.raises(RuntimeError):
            store.prune(now=store.rows()[-1]["at"] + undo.KEEP_SECONDS + 100)
    finally:
        store.release()
    assert [r["n"] for r in store.snapshots()] == [3] and _refs(store) == [1, 2, 3]  # the record went first
    monkeypatch.setattr(undo.Store, "git", real)
    assert store.acquire()
    try:
        assert store.prune() == 0  # nothing is old now; what the record does not list still goes
    finally:
        store.release()
    assert _refs(store) == [3]


def test_a_clean_up_with_nothing_to_drop_keeps_every_snapshot(project):
    store = _three(project)
    assert store.acquire()
    try:
        assert store.prune() == 0
    finally:
        store.release()
    assert [r["n"] for r in store.snapshots()] == [1, 2, 3] and _refs(store) == [1, 2, 3]


# -- 3: a record that cannot be read is not an empty record -----------------------------------
_REAL_READ = undo.Store._read_rows


def _held(self):
    raise PermissionError(13, "another program holds the record")


def test_a_record_that_cannot_be_read_is_not_taken_for_empty(project, monkeypatch):
    store = _three(project)
    monkeypatch.setattr(undo.Store, "_read_rows", _held)
    with pytest.raises(PermissionError):
        store.rows(wait=0.05)


def test_a_record_that_is_not_there_is_no_rows(project):
    assert _store(project).rows() == []


def test_a_record_held_for_a_moment_is_read_after_it(project, monkeypatch):
    store = _three(project)
    real, calls = undo.Store._read_rows, []

    def held_twice(self):
        calls.append(1)
        if len(calls) < 3:
            raise PermissionError(13, "held")
        return real(self)
    monkeypatch.setattr(undo.Store, "_read_rows", held_twice)
    assert [r["n"] for r in store.snapshots()] == [1, 2, 3]


def test_the_clean_up_leaves_a_record_it_cannot_read_as_it_is(project, monkeypatch):
    store = _three(project)
    with open(store.log, "rb") as f:
        before = f.read()
    now = store.rows()[-1]["at"] + undo.KEEP_SECONDS + 100
    monkeypatch.setattr(undo.Store, "_read_rows", _held)
    assert store.acquire()
    try:
        with pytest.raises(PermissionError):
            store.prune(now=now)
    finally:
        store.release()
    monkeypatch.setattr(undo.Store, "_read_rows", _REAL_READ)
    with open(store.log, "rb") as f:
        assert f.read() == before
    assert _refs(store) == [1, 2, 3]


def test_the_clean_up_does_not_empty_the_record_when_it_cannot_be_read_inside_its_turn(project, monkeypatch):
    """The reviewer's case: readable when the clean-up starts, held when it re-reads for the rewrite."""
    store = _three(project)
    now = store.rows()[-1]["at"] + undo.KEEP_SECONDS + 100
    real, calls = undo.Store._read_rows, []

    def held_from_the_second_read(self):
        calls.append(1)
        if len(calls) > 1:
            raise PermissionError(13, "held")
        return real(self)
    monkeypatch.setattr(undo.Store, "_read_rows", held_from_the_second_read)
    assert store.acquire()
    try:
        with pytest.raises(PermissionError):
            store.prune(now=now)
    finally:
        store.release()
    monkeypatch.setattr(undo.Store, "_read_rows", real)
    assert [r["n"] for r in store.snapshots()] == [1, 2, 3] and _refs(store) == [1, 2, 3]


def test_a_snapshot_does_not_start_again_at_one_when_the_record_cannot_be_read(project, monkeypatch):
    store = _three(project)
    monkeypatch.setattr(undo.Store, "_read_rows", _held)
    _write(project, "n.txt", b"later")
    undo.before_command(_payload(project, "echo later"), _data())
    monkeypatch.setattr(undo.Store, "_read_rows", _REAL_READ)
    rows = _store(project).rows()
    assert [r["n"] for r in rows if "n" in r] == [1, 2, 3]
    assert "PermissionError" in rows[-1]["unprotected"] and rows[-1]["before"] == "echo later"


def test_a_row_waits_for_a_record_that_is_held_for_a_moment(project, monkeypatch):
    store = _three(project)
    real, calls = undo.Store._write_new, []

    def held_twice(self, path, lines, append):
        calls.append(1)
        if len(calls) < 3:
            raise PermissionError(13, "held")
        return real(self, path, lines, append)
    monkeypatch.setattr(undo.Store, "_write_new", held_twice)
    store.note({"unprotected": "said after the wait"})
    assert store.rows()[-1]["unprotected"] == "said after the wait"


def test_a_row_gives_up_on_a_record_held_past_its_wait(project, monkeypatch):
    store = _three(project)
    monkeypatch.setattr(undo, "LOG_WAIT", 0.1)

    def held(self, path, lines, append):
        raise PermissionError(13, "held")
    monkeypatch.setattr(undo.Store, "_write_new", held)
    with pytest.raises(PermissionError):
        store.note({"unprotected": "never said"})


def test_the_list_says_so_when_the_record_cannot_be_read(project, monkeypatch, capsys):
    _three(project)
    monkeypatch.setattr(undo.Store, "_read_rows", _held)
    capsys.readouterr()
    assert undo._cli(["undo", "list", project]) == 1
    err = capsys.readouterr().err
    assert "cannot be read right now" in err and "No snapshots" not in err


def test_going_back_says_so_when_the_record_cannot_be_read(project, monkeypatch, capsys):
    _three(project)
    monkeypatch.setattr(undo.Store, "rows", lambda self, wait=0.25: _held(self))
    capsys.readouterr()
    assert undo._cli(["undo", "restore", "1", project]) == 1
    err = capsys.readouterr().err
    assert "cannot be read right now" in err and "Nothing was written" in err
    assert _read(project, "n.txt") == b"2"


# -- 4: the job is there before the git is ----------------------------------------------------
@pytest.mark.skipif(os.name != "nt", reason="Windows jobs")
def test_the_job_is_made_before_the_process_is(monkeypatch):
    monkeypatch.setattr(undo, "_JOB", None)
    real, seen = subprocess.Popen, []

    class Watched(real):
        def __init__(self, *args, **kwargs):
            seen.append(undo._JOB)
            super().__init__(*args, **kwargs)
    monkeypatch.setattr(undo.subprocess, "Popen", Watched)
    code, out, _ = undo._run([sys.executable, "-c", "print('hi')"], cwd=os.getcwd(), env=dict(os.environ),
                             stdin=None, timeout=30)
    assert (code, out.strip()) == (0, b"hi") and seen and seen[0]


def test_a_program_does_not_outlive_an_interrupt_of_the_one_that_ran_it(monkeypatch):
    real, made = subprocess.Popen, []

    class Interrupted(real):
        def communicate(self, *args, **kwargs):
            if not made:
                made.append(self)
                raise KeyboardInterrupt
            return super().communicate(*args, **kwargs)
    monkeypatch.setattr(undo.subprocess, "Popen", Interrupted)
    with pytest.raises(KeyboardInterrupt):
        undo._run([sys.executable, "-c", "import time; time.sleep(60)"], cwd=os.getcwd(), env=dict(os.environ),
                  stdin=None, timeout=None)
    assert made[0].wait(timeout=10) is not None


def test_going_back_interrupted_says_where_things_stand(project, monkeypatch, capsys):
    _three(project)

    def interrupted(self, n):
        raise KeyboardInterrupt
    monkeypatch.setattr(undo.Store, "restore", interrupted)
    capsys.readouterr()
    assert undo._cli(["undo", "restore", "1", project]) == 1
    assert "interrupted" in capsys.readouterr().err
    store = _store(project)
    assert store.acquire()  # the lock was let go
    store.release()


# -- 6, 7, 9: what the words say --------------------------------------------------------------
def test_a_name_git_does_not_take_is_not_called_unreadable(project):
    row = {"n": 1, "unreadable": ["nul", "aux.txt"]}
    assert "could not be saved: nul, aux.txt" in undo._left_out(row) and "read" not in undo._left_out(row)


def test_a_snapshot_with_nothing_saved_names_what_was_left_out(project, monkeypatch):
    monkeypatch.setattr(undo.Store, "_add", lambda self, paths, exclude_file, left: list(paths))
    undo.before_command(_payload(project), _data())
    said = _store(project).rows()[-1]["unprotected"]
    assert "no file could be saved" in said and "left out" in said
    assert any(name in said for name in (".env", ".gitattributes", ".gitignore", "mixed.txt", "notes.txt"))


def test_going_back_does_not_say_a_file_made_anew_stays(project, capsys):
    """A file deleted and made anew after the snapshot is in the snapshot: it goes back."""
    _write(project, "config.json", b'{"old": true}')
    undo.before_command(_payload(project, "echo one"), _data())
    os.remove(os.path.join(project, "config.json"))
    undo.before_command(_payload(project, "echo two"), _data())
    _write(project, "config.json", b'{"new": true}')
    _write(project, "made_since.txt", b"new")
    capsys.readouterr()
    assert undo._cli(["undo", "restore", "1", project]) == 0
    out = capsys.readouterr().out
    assert "Files that are not in snapshot 1 stay in place" in out and "made since" not in out
    assert _read(project, "config.json") == b'{"old": true}' and _read(project, "made_since.txt") == b"new"
