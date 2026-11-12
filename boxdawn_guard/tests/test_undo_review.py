"""`undo`: what the reviews found, each as a test."""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time

import pytest

from boxdawn_guard import undo
from boxdawn_guard.tests.test_undo import _git, _payload, _store, _write, project  # noqa: F401 - `project` is a fixture

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")


def _data():
    return os.environ["CLAUDE_PLUGIN_DATA"]


def _junction(link, target):
    subprocess.run(["cmd", "/c", "mklink", "/J", link, str(target)], check=True, capture_output=True)


def test_a_process_over_its_time_is_stopped_with_its_children():
    """A real process whose child keeps the pipes open, as the launcher git on Windows does."""
    child = ("import subprocess, sys, time; "
             "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)']); time.sleep(60)")
    started = time.perf_counter()
    with pytest.raises(subprocess.TimeoutExpired):
        undo._run([sys.executable, "-c", child], cwd=os.getcwd(), env=dict(os.environ), stdin=None, timeout=1)
    assert time.perf_counter() - started < 15


def test_a_file_that_grew_past_the_limit_is_not_overwritten_by_going_back(project, monkeypatch):
    monkeypatch.setattr(undo, "MAX_FILE_BYTES", 1000)
    _write(project, "model.bin", b"small-old")
    undo.before_command(_payload(project), _data())
    _write(project, "model.bin", b"NEW-BIG-" + b"z" * 5000)
    store = _store(project)
    assert store.acquire()
    _, _, skipped = store.restore(1)
    with open(os.path.join(project, "model.bin"), "rb") as f:
        assert f.read().startswith(b"NEW-BIG-")  # in no snapshot, so it must stay
    assert "model.bin" in skipped


def test_a_file_that_became_a_folder_and_a_folder_that_became_a_file(project):
    _write(project, "pkg", b"a file")
    _write(project, "lib/one.txt", b"one")
    undo.before_command(_payload(project), _data())
    os.remove(os.path.join(project, "pkg"))
    _write(project, "pkg/later.txt", b"later")
    _write(project, "pkg/node_modules/m/index.js", b"heavy, in no snapshot")
    shutil.rmtree(os.path.join(project, "lib"))
    _write(project, "lib", b"now a file")
    store = _store(project)
    assert store.acquire()
    _, _, skipped = store.restore(1)
    assert skipped.get("pkg") == "it is a folder now"
    assert os.path.isfile(os.path.join(project, "pkg", "node_modules", "m", "index.js"))
    with open(os.path.join(project, "lib", "one.txt"), "rb") as f:  # the file in its way was saved, so it gave way
        assert f.read() == b"one"


def test_a_nested_repository_with_no_commit_does_not_stop_snapshots(project):
    os.makedirs(os.path.join(project, "sub"))
    _git(os.path.join(project, "sub"), "init", "-q")
    _write(project, "sub/inner.txt", b"inside")
    undo.before_command(_payload(project), _data())
    _write(project, "notes.txt", b"changed\n")
    undo.before_command(_payload(project), _data())
    first, second = _store(project).snapshots()
    assert "sub (repository)" in first["folders"] and first["commit"] != second["commit"]


def test_only_folders_are_heavy_whatever_their_case(project):
    _write(project, "build", b"a script named build")
    _write(project, "src/build/x.py", b"source")
    _write(project, "tools/Node_Modules/pkg/i.js", b"heavy")
    undo.before_command(_payload(project), _data())
    store = _store(project)
    row = store.snapshots()[0]
    names = store._names(row["commit"])
    assert {"build", "src/build/x.py"} <= names
    assert not [n for n in names if "node_modules/" in n.lower()]
    assert {"node_modules (heavy)", "tools/Node_Modules (heavy)"} <= set(row["folders"])


@pytest.mark.skipif(os.name != "nt", reason="junctions are a Windows thing")
def test_a_junction_is_not_followed_out_of_the_project(project, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "o.txt").write_bytes(b"outside-v1")
    _junction(os.path.join(project, "j"), outside)
    undo.before_command(_payload(project), _data())
    store = _store(project)
    row = store.snapshots()[0]
    assert "j (link)" in row["folders"] and not [n for n in store._names(row["commit"]) if n.startswith("j/")]
    (outside / "o.txt").write_bytes(b"outside-v2")
    assert store.acquire()
    store.restore(1)
    assert (outside / "o.txt").read_bytes() == b"outside-v2"


@pytest.mark.skipif(os.name != "nt", reason="junctions are a Windows thing")
def test_a_saved_folder_swapped_for_a_junction_is_not_written_through(project, tmp_path):
    _write(project, "conf/a.txt", b"saved")
    undo.before_command(_payload(project), _data())
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "a.txt").write_bytes(b"not ours")
    shutil.rmtree(os.path.join(project, "conf"))
    _junction(os.path.join(project, "conf"), outside)
    undo.before_command(_payload(project), _data())  # must still be taken
    store = _store(project)
    assert len(store.snapshots()) == 2
    assert store.acquire()
    _, _, skipped = store.restore(1)
    assert (outside / "a.txt").read_bytes() == b"not ours" and "conf/a.txt" in skipped


@pytest.mark.skipif(os.name == "nt", reason="needs file modes")
def test_a_file_that_cannot_be_read_is_named_and_the_rest_is_saved(project):
    _write(project, "secret.db", b"x")
    os.chmod(os.path.join(project, "secret.db"), 0)
    undo.before_command(_payload(project), _data())
    store = _store(project)
    row = store.snapshots()[0]
    assert row.get("unreadable") == ["secret.db"] and "notes.txt" in store._names(row["commit"])


@pytest.mark.skipif(os.name == "nt", reason="needs symlinks")
def test_a_saved_folder_swapped_for_a_symlink_does_not_stop_snapshots(project, tmp_path):
    _write(project, "conf/a.txt", b"saved")
    undo.before_command(_payload(project), _data())
    shutil.rmtree(os.path.join(project, "conf"))
    os.symlink(str(tmp_path), os.path.join(project, "conf"))
    undo.before_command(_payload(project), _data())
    store = _store(project)
    assert len(store.snapshots()) == 2
    assert store.acquire()
    store.restore(1)


def test_any_failure_leaves_a_row_that_says_unprotected(project, monkeypatch, capsys):
    def boom(self, *a, **k):
        raise RuntimeError("git add: fatal: something")
    monkeypatch.setattr(undo.Store, "snapshot", boom)
    undo.before_command(_payload(project, "rm -rf src"), _data())
    store = _store(project)
    assert "the snapshot failed (RuntimeError" in store.rows()[-1]["unprotected"]
    assert store.acquire()  # and the lock was given back
    store.release()
    assert undo._cli(["undo", "list", project]) == 0
    out = capsys.readouterr().out
    assert "NO SNAPSHOT" in out and "rm -rf src" in out


@pytest.mark.parametrize("kind", ["folder", "link"])
def test_a_lock_that_is_not_a_plain_file_is_cleared(project, kind, tmp_path):
    store = _store(project)
    os.makedirs(store.root, exist_ok=True)
    if kind == "folder":
        os.mkdir(store.lock)
    else:
        try:
            os.symlink(str(tmp_path / "nowhere"), store.lock)
        except OSError:
            pytest.skip("no right to make a link here")
    undo.before_command(_payload(project), _data())
    assert len(store.snapshots()) == 1


def test_a_lock_that_cannot_be_cleared_is_said_in_the_record(project):
    store = _store(project)
    os.makedirs(os.path.join(store.lock, "kept"))  # a folder with something in it
    undo.before_command(_payload(project, "rm -rf src"), _data())
    assert "unprotected" in store.rows()[-1] and not store.snapshots()


def test_a_broken_line_in_the_record_is_skipped(project):
    undo.before_command(_payload(project), _data())
    store = _store(project)
    with open(store.log, "a", encoding="utf-8") as f:
        f.write('{"at": 1, "n": 2, "comm\n[1, 2]\n{"n": 5}\n')
    _write(project, "notes.txt", b"again\n")
    undo.before_command(_payload(project), _data())
    assert [r["n"] for r in store.snapshots()] == [1, 2]


def test_a_forged_row_is_not_a_snapshot(project):
    undo.before_command(_payload(project), _data())
    store = _store(project)
    store.note({"n": 7, "commit": "--pathspec-from-file=/etc/passwd"})
    store.note({"n": 8, "commit": "refs/heads/main"})
    assert [r["n"] for r in store.snapshots()] == [1]
    assert store.acquire()
    with pytest.raises(LookupError):
        store.restore(7)


def test_the_record_is_not_written_through_a_link(project, tmp_path):
    store = _store(project)
    os.makedirs(store.root, exist_ok=True)
    victim = tmp_path / "victim.txt"
    victim.write_text("precious")
    try:
        os.symlink(str(victim), store.log)
    except OSError:
        pytest.skip("no right to make a link here")
    undo.before_command(_payload(project), _data())
    assert victim.read_text() == "precious" and len(store.snapshots()) == 1


def test_a_network_path_is_never_a_project(tmp_path, monkeypatch):
    monkeypatch.setattr(os.path, "isdir", lambda p: True)
    assert undo._refused(r"\\localhost\c$\Users\me", str(tmp_path / "data")) == "a network path"


def test_a_restore_that_stops_part_way_says_so(project, monkeypatch, capsys):
    undo.before_command(_payload(project), _data())
    real = undo.Store.git

    def fail_checkout(self, *args, **kwargs):
        if "checkout" in args:
            raise RuntimeError("git checkout: error: unable to unlink old 'c.txt'")
        return real(self, *args, **kwargs)
    monkeypatch.setattr(undo.Store, "git", fail_checkout)
    _write(project, "notes.txt", b"changed\n")
    assert undo._cli(["undo", "restore", "1", project]) == 1
    err = capsys.readouterr().err
    assert "stopped part-way" in err and "snapshot 2" in err and "Traceback" not in err


def test_old_unprotected_notes_go_with_the_old_snapshots(project):
    store = _store(project)
    for i in range(2):
        _write(project, "notes.txt", b"version %d\n" % i)
        undo.before_command(_payload(project), _data())
    store.note({"unprotected": "x", "before": "y"})
    assert store.acquire()
    assert store.prune(now=store.rows()[-1]["at"] + undo.KEEP_SECONDS + 5) == 1
    assert [(r.get("n"), "unprotected" in r) for r in store.rows()] == [(2, False)]
