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


def test_a_process_over_its_time_is_stopped_with_its_children(tmp_path):
    """A real process whose child keeps the pipes open, as the launcher git on Windows does."""
    script = tmp_path / "parent.py"
    script.write_text(
        "import subprocess, sys, time\n"
        "p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
        "open(sys.argv[1], 'w').write(str(p.pid))\n"
        "time.sleep(60)\n")
    started = time.perf_counter()
    with pytest.raises(subprocess.TimeoutExpired):
        undo._run([sys.executable, str(script), str(tmp_path / "pid")], cwd=os.getcwd(), env=dict(os.environ),
                  stdin=None, timeout=3)
    assert time.perf_counter() - started < 15
    grandchild = int((tmp_path / "pid").read_text())
    time.sleep(0.5)
    if os.name == "nt":
        listed = subprocess.run(["tasklist", "/FI", f"PID eq {grandchild}", "/NH"], capture_output=True, text=True)
        assert str(grandchild) not in listed.stdout
    else:
        with pytest.raises(OSError):
            os.kill(grandchild, 0)


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
    # Review 6: the file in its way was made since, and "files made since stay" (it used to give way).
    with open(os.path.join(project, "lib"), "rb") as f:
        assert f.read() == b"now a file"
    assert skipped.get("lib/one.txt") == "a file now stands where its folder was"


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
    assert "stopped" in err and "snapshot 2" in err and "Traceback" not in err


def test_old_unprotected_notes_go_with_the_old_snapshots(project):
    store = _store(project)
    for i in range(2):
        _write(project, "notes.txt", b"version %d\n" % i)
        undo.before_command(_payload(project), _data())
    store.note({"unprotected": "x", "before": "y"})
    assert store.acquire()
    assert store.prune(now=store.rows()[-1]["at"] + undo.KEEP_SECONDS + 5) == 1
    assert [(r.get("n"), "unprotected" in r) for r in store.rows()] == [(2, False)]


# -- what the second review found -------------------------------------------------

def _read(project, rel):
    with open(os.path.join(project, rel), "rb") as f:
        return f.read()


def test_going_back_can_itself_be_undone(project, capsys):
    _write(project, "f.txt", b"v1")
    undo.before_command(_payload(project, "one"), _data())
    _write(project, "f.txt", b"v2 - an hour of work")
    undo.before_command(_payload(project, "two"), _data())
    assert undo._cli(["undo", "restore", "1", project]) == 0
    assert _read(project, "f.txt") == b"v1"
    assert undo._cli(["undo", "restore", "3", project]) == 0  # 3 = the state just before going back
    assert _read(project, "f.txt") == b"v2 - an hour of work"
    assert "left as it is" not in capsys.readouterr().out


def test_the_snapshot_after_a_restore_is_of_what_is_on_disk(project):
    _write(project, "f.txt", b"v1")
    undo.before_command(_payload(project, "c1"), _data())
    _write(project, "f.txt", b"v2-longer")
    undo.before_command(_payload(project, "c2"), _data())
    store = _store(project)
    assert store.acquire()
    store.restore(1)
    store.release()
    undo.before_command(_payload(project, "rm f.txt"), _data())
    os.remove(os.path.join(project, "f.txt"))
    last = store.snapshots()[-1]
    assert last["before"] == "rm f.txt"
    assert store.git("show", f"{last['commit']}:f.txt") == b"v1"


def test_one_path_git_cannot_look_at_does_not_empty_the_snapshot(project, monkeypatch):
    real = undo.Store.git

    def add_dies_on_bad(self, *args, **kwargs):
        if "add" in args and b"bad.txt" in (kwargs.get("stdin") or b"").split(b"\0"):
            return 128, b"", b"fatal: unable to stat 'bad.txt': No such file or directory"
        return real(self, *args, **kwargs)
    monkeypatch.setattr(undo.Store, "git", add_dies_on_bad)
    _write(project, "bad.txt", b"x")
    undo.before_command(_payload(project), _data())
    store = _store(project)
    row = store.snapshots()[0]
    assert row["unreadable"] == ["bad.txt"]
    assert {"notes.txt", "src/app.py", ".env"} <= store._names(row["commit"])


def test_a_saved_file_that_became_a_heavy_folder_is_not_walked_into(project):
    _write(project, "tools/node_modules", b"a file with that name")
    undo.before_command(_payload(project), _data())
    os.remove(os.path.join(project, "tools", "node_modules"))
    _write(project, "tools/node_modules/pkg/index.js", b"heavy")
    undo.before_command(_payload(project), _data())
    store = _store(project)
    row = store.snapshots()[-1]
    assert "tools/node_modules (heavy)" in row["folders"]
    assert not [n for n in store._names(row["commit"]) if n.startswith("tools/node_modules")]


@pytest.mark.skipif(os.name != "nt", reason="junctions are a Windows thing")
def test_a_saved_file_that_became_a_junction_is_not_walked_into(project, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_bytes(b"not ours")
    _write(project, "f", b"a file")
    undo.before_command(_payload(project), _data())
    os.remove(os.path.join(project, "f"))
    _junction(os.path.join(project, "f"), outside)
    undo.before_command(_payload(project), _data())
    store = _store(project)
    assert not [n for n in store._names(store.snapshots()[-1]["commit"]) if n == "f" or n.startswith("f/")]


@pytest.mark.skipif(os.name != "nt", reason="junctions and the 260-character limit are Windows things")
def test_a_junction_below_a_very_long_path_is_not_followed(project, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "o.txt").write_bytes(b"OUT-v1")
    deep = os.path.join(project, *["d" * 46] * 6)
    os.makedirs("\\\\?\\" + deep)
    with open("\\\\?\\" + os.path.join(deep, "in.txt"), "wb") as f:
        f.write(b"inside")
    _junction("\\\\?\\" + os.path.join(deep, "jn"), outside)
    undo.before_command(_payload(project), _data())
    store = _store(project)
    row = store.snapshots()[0]
    names = store._names(row["commit"])
    assert any(n.endswith("/in.txt") for n in names) and not [n for n in names if "/jn/" in n]
    os.remove(outside / "o.txt")
    assert store.acquire()
    store.restore(1)
    assert not (outside / "o.txt").exists()


def test_looking_for_folders_stops_at_the_budget(project, monkeypatch):
    started = []
    monkeypatch.setattr(undo, "start_in_background", started.append)
    monkeypatch.setattr(undo, "HOOK_BUDGET", 0.0001)
    for i in range(50):
        os.makedirs(os.path.join(project, f"many/d{i}"))
    undo.before_command(_payload(project), _data())
    store = _store(project)
    assert "took over" in store.rows()[-1]["unprotected"] and started


def test_the_list_cannot_be_drawn_over_by_a_command(project, capsys):
    undo.before_command(_payload(project, "echo hi\n   7  11-12 09:00:00  before: FORGED"), _data())
    store = _store(project)
    store.note({"unprotected": "x\ry", "before": "rm -rf src\r   8  harmless \x1b[2J"})
    assert undo._cli(["undo", "list", project]) == 0
    out = capsys.readouterr().out
    assert len(out.splitlines()) == 3 and "\r" not in out.replace("\r\n", "\n") and "\x1b" not in out
    assert "\\n   7" in out and "\\r   8" in out


@pytest.mark.parametrize("row", [
    '{"at": NaN, "n": 9, "commit": "x"}', '{"at": 1e20, "unprotected": "x"}', '{"at": -1e20, "unprotected": "x"}',
    '{"at": true, "unprotected": "x"}',
])
def test_a_row_with_an_impossible_time_is_not_a_row(project, row, capsys):
    undo.before_command(_payload(project), _data())
    store = _store(project)
    with open(store.log, "a", encoding="utf-8") as f:
        f.write(row + "\n")
    assert len(store.rows()) == 1
    assert undo._cli(["undo", "list", project]) == 0


def test_a_row_with_odd_fields_does_not_stop_the_list(project, capsys):
    undo.before_command(_payload(project), _data())
    store = _store(project)
    good = store.rows()[0]
    for extra in ({"folders": 5}, {"too_large": [1, 2]}, {"before": ["a"]}, {"unreadable": "abc", "unreadable_more": "x"}):
        store.note({**good, **extra, "n": good["n"] + 1})
    assert undo._cli(["undo", "list", project]) == 0
    assert "not in it" in capsys.readouterr().out  # the real row's node_modules line is still shown


def test_settings_planted_in_the_store_do_not_change_what_is_saved(project):
    undo.before_command(_payload(project), _data())
    store = _store(project)
    with open(os.path.join(store.shadow, "config"), "a", encoding="utf-8") as f:
        f.write("[core]\n\tignoreStat = true\n\tautocrlf = true\n")
    marker = os.path.join(os.environ["CLAUDE_PLUGIN_DATA"], "hook-ran")
    hook = os.path.join(store.shadow, "hooks", "post-checkout")
    with open(hook, "w", encoding="utf-8", newline="\n") as f:
        f.write("#!/bin/sh\necho ran > '%s'\n" % marker.replace(os.sep, "/"))
    os.chmod(hook, 0o755)
    time.sleep(1.1)
    _write(project, "notes.txt", b"changed after the planting\r\n")
    undo.before_command(_payload(project), _data())
    last = store.snapshots()[-1]
    assert store.git("show", f"{last['commit']}:notes.txt") == b"changed after the planting\r\n"
    _write(project, "notes.txt", b"again")
    assert store.acquire()
    store.restore(last["n"])
    assert not os.path.exists(marker)


def test_no_git_and_a_refused_project_each_leave_one_row(project, monkeypatch):
    monkeypatch.setattr(undo, "_git_exe", lambda project=None: None)
    for _ in range(3):
        undo.before_command(_payload(project, "rm -rf src"), _data())
    rows = _store(project).rows()
    assert len(rows) == 1 and "git is not installed" in rows[0]["unprotected"]


def test_a_refused_project_leaves_a_row(project, monkeypatch):
    inside = os.path.join(project, "inside-data")
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", inside)
    undo.before_command(_payload(project), inside)
    assert "around the snapshot store" in _store(project).rows()[-1]["unprotected"]


def test_the_list_says_when_there_is_nothing(project, capsys):
    assert undo._cli(["undo", "list", os.path.join(project, "src")]) == 0
    assert "No snapshots of" in capsys.readouterr().out
    assert undo._cli(["undo", "restore", "1", project]) == 1


def test_a_stop_before_the_present_was_saved_says_nothing_was_written(project, monkeypatch, capsys):
    _write(project, "a.txt", b"a1")
    undo.before_command(_payload(project), _data())
    _write(project, "a.txt", b"a2")
    undo.before_command(_payload(project), _data())
    assert undo._cli(["undo", "restore", "1", project]) == 0  # leaves an earlier "before going back" row
    _write(project, "a.txt", b"a3-precious")

    def no_snapshot(self, *a, **k):
        raise RuntimeError("git add: Unable to create index.lock")
    monkeypatch.setattr(undo.Store, "snapshot", no_snapshot)
    capsys.readouterr()
    assert undo._cli(["undo", "restore", "2", project]) == 1
    assert "Nothing was written" in capsys.readouterr().err and _read(project, "a.txt") == b"a3-precious"


def test_the_clean_up_does_not_write_through_a_link_and_keeps_the_record_private(project, tmp_path):
    store = _store(project)
    for i in range(2):
        _write(project, "notes.txt", b"version %d\n" % i)
        undo.before_command(_payload(project), _data())
    victim = tmp_path / "victim.txt"
    victim.write_text("precious")
    try:
        os.symlink(str(victim), store.log + ".tmp")
    except OSError:
        with open(store.log + ".tmp", "w") as f:  # no right to make a link: a left-over file must not stop it either
            f.write("left over")
    assert store.acquire()
    assert store.prune(now=store.rows()[-1]["at"] + undo.KEEP_SECONDS + 5) == 1
    assert victim.read_text() == "precious" and [r["n"] for r in store.snapshots()] == [2]
    if os.name != "nt":
        assert os.stat(store.log).st_mode & 0o777 == 0o600


# -- third review ----------------------------------------------------------

@pytest.mark.skipif(os.name != "nt", reason="the current folder is searched for programs on Windows only")
@pytest.mark.parametrize("name", ["git.bat", "git.cmd"])
def test_a_git_file_in_the_project_is_not_run(project, tmp_path, monkeypatch, name):
    marker = tmp_path / "ran.txt"
    _write(project, name, f'@echo off\r\necho ran >> "{marker}"\r\nexit /b 1\r\n'.encode())
    monkeypatch.delenv("NoDefaultCurrentDirectoryInExePath", raising=False)
    monkeypatch.chdir(project)
    undo.before_command(_payload(project), _data())
    assert not marker.exists()
    assert [r["n"] for r in _store(project).snapshots()] == [1]


def test_git_is_not_taken_from_the_project_or_a_folder_not_written_in_full(project, monkeypatch):
    real = undo._on_path(None)
    name = os.path.basename(real)
    shutil.copy(sys.executable, os.path.join(project, name))
    os.makedirs(os.path.join(project, "bin"))
    shutil.copy(sys.executable, os.path.join(project, "bin", name))
    monkeypatch.chdir(project)
    monkeypatch.setenv("PATH", os.pathsep.join([".", "", "bin", os.path.join(project, "bin"), os.path.dirname(real)]))
    assert undo._on_path(project) == real


def test_a_git_too_old_for_the_snapshot_leaves_no_numbered_row(project, monkeypatch):
    real = undo.Store.git

    def old_git(self, *args, **kw):
        if "add" in args:
            return 129, b"", b"error: unknown option `pathspec-from-file=-'\nusage: git add"
        return real(self, *args, **kw)
    monkeypatch.setattr(undo.Store, "git", old_git)
    undo.before_command(_payload(project, "rm -rf src"), _data())
    store = _store(project)
    assert store.snapshots() == [] and "too old" in store.rows()[-1]["unprotected"]


def test_a_snapshot_git_took_nothing_into_is_not_numbered(project, monkeypatch):
    monkeypatch.setattr(undo.Store, "_add", lambda self, paths, exclude_file, left: list(paths))
    undo.before_command(_payload(project), _data())
    store = _store(project)
    assert store.snapshots() == [] and "no file could be saved" in store.rows()[-1]["unprotected"]


def test_a_system_that_is_not_supported_leaves_one_row(project, monkeypatch):
    monkeypatch.setattr(undo, "SUPPORTED", ())
    for _ in range(3):
        undo.before_command(_payload(project), _data())
    rows = _store(project).rows()
    assert len(rows) == 1 and "not supported" in rows[0]["unprotected"]
    assert "not supported" in undo.start(project, _data())


def test_rows_no_clock_or_text_can_hold_do_not_end_the_list(project, capsys):
    undo.before_command(_payload(project, "one"), _data())
    store = _store(project)
    with open(store.log, "ab") as f:
        f.write(b'{"at": ' + b"9" * 400 + b', "unprotected": "x"}\n')
        f.write(b'{"at": 1, "unprotected": "\xff\xfe"}\n')
        f.write(b"[" * 100000 + b"\n")
        f.write(b'{"at": 1700000000, "n": 999999999, "commit": "' + b"a" * 40 + b'", "before": "planted"}\n')
    assert undo._cli(["undo", "list", project]) == 0
    assert "one" in capsys.readouterr().out
    _write(project, "later.txt", b"x")
    undo.before_command(_payload(project, "two"), _data())  # no number past the last one that can be listed
    assert "damaged" in store.rows()[-1]["unprotected"]


def test_going_back_after_the_whole_folder_was_removed(project, capsys):
    undo.before_command(_payload(project, "rm -rf ."), _data())
    os.chdir(os.path.dirname(project))
    shutil.rmtree(project, onerror=lambda f, p, e: (os.chmod(p, 0o700), f(p)))
    assert undo._cli(["undo", "restore", "1", project]) == 0
    assert "of the" in capsys.readouterr().out and _read(project, "src/app.py") == b"print('v2, not committed')\n"


def test_a_file_changed_after_the_present_was_saved_is_left_alone(project, monkeypatch):
    _write(project, "a.txt", b"a1")
    undo.before_command(_payload(project), _data())
    _write(project, "a.txt", b"a2-longer")
    real = undo.Store.snapshot

    def then_another_program_writes(self, why, budget=None):
        row = real(self, why, budget)
        _write(project, "a.txt", b"a3-written-in-between")
        return row
    monkeypatch.setattr(undo.Store, "snapshot", then_another_program_writes)
    store = _store(project)
    assert store.acquire()
    _, _, skipped = store.restore(1)
    store.release()
    assert "a.txt" in skipped and _read(project, "a.txt") == b"a3-written-in-between"


@pytest.mark.skipif(os.name != "nt", reason="junctions are a Windows thing")
def test_going_back_does_not_write_through_a_junction_to_an_empty_folder(project, tmp_path):
    _write(project, "conf/app.ini", b"mine")
    undo.before_command(_payload(project), _data())
    outside = tmp_path / "outside"
    outside.mkdir()
    shutil.rmtree(os.path.join(project, "conf"))
    _junction(os.path.join(project, "conf"), outside)
    store = _store(project)
    assert store.acquire()
    _, _, skipped = store.restore(1)
    store.release()
    assert skipped.get("conf/app.ini") == "a link stands above it" and os.listdir(outside) == []


# -- fourth review -----------------------------------------------------------

def _small(tmp_path, monkeypatch, files):
    root = str(tmp_path / "small")
    for rel, data in files.items():
        _write(root, rel, data)
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", root)
    return root


def test_one_changed_file_git_could_not_take_is_not_a_numbered_snapshot(project, tmp_path, monkeypatch):
    root = _small(tmp_path, monkeypatch, {"only.txt": b"x"})
    monkeypatch.setattr(undo.Store, "_add", lambda self, paths, exclude_file, left: list(paths))
    undo.before_command(_payload(root), _data())
    store = undo.Store(os.path.realpath(root), _data())
    assert store.snapshots() == [] and "no file could be saved" in store.rows()[-1]["unprotected"]


def test_going_back_says_how_many_files_came_back_and_fails_when_none(project, tmp_path, monkeypatch, capsys):
    root = _small(tmp_path, monkeypatch, {"a.txt": b"a1", "b.txt": b"b1", "c.txt": b"c1"})
    undo.before_command(_payload(root), _data())
    _write(root, "a.txt", b"a2-changed")
    os.remove(os.path.join(root, "b.txt"))
    os.makedirs(os.path.join(root, "b.txt"))  # a saved file that is a folder now is left as it is
    capsys.readouterr()
    assert undo._cli(["undo", "restore", "1", root]) == 0
    out = capsys.readouterr().out
    assert "2 of the 3 files in snapshot 1" in out and "b.txt" in out and _read(root, "a.txt") == b"a1"
    for name in ("a.txt", "c.txt"):
        os.remove(os.path.join(root, name))
        os.makedirs(os.path.join(root, name))
    _write(root, "d.txt", b"made later")  # the present still has a file to save
    assert undo._cli(["undo", "restore", "1", root]) == 1
    captured = capsys.readouterr()
    assert "Nothing was put back" in captured.err and "are as they were" not in captured.out


def test_going_back_where_it_is_not_supported_or_to_a_number_not_there(project, monkeypatch, capsys):
    undo.before_command(_payload(project), _data())
    shutil.rmtree(project, onerror=lambda f, p, e: (os.chmod(p, 0o700), f(p)))
    assert undo._cli(["undo", "restore", "7", project]) == 1
    assert "no snapshot 7" in capsys.readouterr().err and not os.path.exists(project)
    monkeypatch.setattr(undo, "SUPPORTED", ())
    assert undo._cli(["undo", "restore", "1", project]) == 1
    assert "not supported" in capsys.readouterr().err and not os.path.exists(project)


def test_the_list_on_a_console_that_cannot_show_the_text(project, tmp_path):
    undo.before_command(_payload(project, "echo ☃ 한글 caf\xe9"), _data())
    _write(project, "node_modules/x/y.js", b"1")
    env = dict(os.environ, PYTHONIOENCODING="ascii", PYTHONPATH=os.path.dirname(os.path.dirname(undo.__file__)),
               PYTHONDONTWRITEBYTECODE="1")
    out = subprocess.run([sys.executable, "-m", "boxdawn_guard.undo", "undo", "list", project], env=env,
                         capture_output=True)
    assert out.returncode == 0 and b"before: echo" in out.stdout and out.stderr == b""


def test_a_path_folder_on_another_machine_is_not_where_git_comes_from(project, monkeypatch):
    real = undo._on_path(None)
    monkeypatch.setenv("PATH", os.pathsep.join(["\\\\localhost\\c$\\x", "//server/share", os.path.dirname(real)]))
    assert undo._on_path(project) == real


def test_a_path_folder_on_another_machine_is_not_looked_at(project, monkeypatch):
    real = undo._on_path(None)
    looked = []
    isfile = os.path.isfile
    monkeypatch.setattr(os.path, "isfile", lambda p: looked.append(p) or isfile(p))
    monkeypatch.setenv("PATH", os.pathsep.join(["\\\\localhost\\c$\\x", "//server/share", os.path.dirname(real)]))
    assert undo._on_path(project) == real
    assert not [p for p in looked if p.replace("\\", "/").startswith("//")]
