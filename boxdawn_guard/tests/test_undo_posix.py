"""Off Windows there is no job to end a git with its holder. The git is handed the open lock
file instead: while it, or anything it started, runs, the lock stays taken, so no second
writer of the store starts next to it. On Linux the system also ends it with its holder."""
from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
import time

import pytest

from boxdawn_guard import undo

pytestmark = [pytest.mark.skipif(os.name == "nt", reason="Windows ends the git with its holder (a job)"),
              pytest.mark.skipif(shutil.which("git") is None, reason="needs git")]

SRC = os.path.dirname(os.path.dirname(os.path.abspath(undo.__file__)))  # the folder that holds boxdawn_guard
HOLDER = (
    "import os, sys\n"
    "from boxdawn_guard import undo\n"
    "s = undo.Store(sys.argv[1], sys.argv[2])\n"
    "assert s.acquire()\n"
    "open(sys.argv[4], 'w').close()\n"   # the lock is taken
    "undo._run(['/bin/sh', '-c', sys.argv[3]], cwd=sys.argv[1], env=dict(os.environ), stdin=None, timeout=None,\n"
    "          lock=s._held)\n"
)


@pytest.fixture
def places(tmp_path):
    project, data = tmp_path / "proj", tmp_path / "data"
    project.mkdir()
    data.mkdir()
    return str(project), str(data), tmp_path


def _wait(condition, seconds: float) -> bool:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if condition():
            return True
        time.sleep(0.05)
    return condition()


def _free(project: str, data: str) -> bool:
    store = undo.Store(project, data)
    if store.acquire():
        store.release()
        return True
    return False


def _holder(places, shell_line: str):
    project, data, tmp = places
    ready = str(tmp / "ready")
    env = dict(os.environ, PYTHONPATH=SRC, PYTHONDONTWRITEBYTECODE="1")
    proc = subprocess.Popen([sys.executable, "-c", HOLDER, project, data, shell_line, ready], env=env, cwd=str(tmp))
    assert _wait(lambda: os.path.exists(ready), 20), "the holder never took the lock"
    return proc


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    try:
        with open(f"/proc/{pid}/stat") as f:
            return f.read().rsplit(") ", 1)[-1][:1] != "Z"  # a zombie holds nothing
    except OSError:
        return True  # no /proc here (macOS)


def test_what_the_git_started_keeps_the_lock_after_its_holder_is_killed(places):
    """A grandchild is not ended with the holder on any system: it must keep the lock taken."""
    project, data, tmp = places
    pid_file = str(tmp / "pid")
    holder = _holder(places, f"sleep 60 & echo $! > {pid_file}; wait")
    assert _wait(lambda: os.path.exists(pid_file) and open(pid_file).read().strip(), 10)
    sleeper = int(open(pid_file).read())
    assert not _free(project, data)
    holder.kill()
    holder.wait()
    try:
        time.sleep(1.0)
        assert _alive(sleeper), "the test's own process is gone: nothing was tested"
        assert not _free(project, data), "the lock was free while a process of the store's git still ran"
    finally:
        os.kill(sleeper, signal.SIGKILL)
    assert _wait(lambda: _free(project, data), 5), "the lock stayed taken after the last process ended"


def test_the_lock_is_free_again_when_the_git_ends_by_itself(places):
    project, data, _ = places
    holder = _holder(places, "sleep 0.3")
    assert holder.wait(timeout=20) == 0
    assert _free(project, data)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="only Linux ends a process with its parent")
def test_on_linux_the_git_ends_with_its_holder(places):
    project, data, tmp = places
    pid_file = str(tmp / "pid")
    holder = _holder(places, f"echo $$ > {pid_file}; exec sleep 60")
    assert _wait(lambda: os.path.exists(pid_file) and open(pid_file).read().strip(), 10)
    git_stand_in = int(open(pid_file).read())
    holder.kill()
    holder.wait()
    assert _wait(lambda: not _alive(git_stand_in), 5), "the process outlived its holder"
    assert _wait(lambda: _free(project, data), 5)


def test_a_process_over_its_time_is_stopped_with_what_it_started(places):
    project, _, tmp = places
    pid_file = str(tmp / "pid")
    with pytest.raises(subprocess.TimeoutExpired):
        undo._run(["/bin/sh", "-c", f"sleep 60 & echo $! > {pid_file}; wait"], cwd=project, env=dict(os.environ),
                  stdin=None, timeout=1.0)
    sleeper = int(open(pid_file).read())
    assert _wait(lambda: not _alive(sleeper), 5)


# ── what the first review on Linux found ────────────────────────────────────
def _on(monkeypatch, data):
    monkeypatch.setenv("CLAUDE_PLUGIN_OPTION_UNDO", "true")
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", data)
    monkeypatch.delenv("CLAUDE_PROJECT_DIR", raising=False)


def _before(project, data, command="echo x"):
    undo.before_command({"cwd": project, "tool_input": {"command": command}, "session_id": "s"}, data)


@pytest.mark.parametrize("name", [".gitattributes", "sub/.gitattributes", ".gitignore", ".gitmodules"])
def test_a_pipe_under_a_name_git_opens_stops_the_snapshot_at_once(places, monkeypatch, name):
    """git opens such a file wherever it finds one and waits for a writer for ever: the hook's
    git ran on in the background with the lock, and a restore gave no answer."""
    project, data, tmp = places
    _on(monkeypatch, data)
    with open(os.path.join(project, "a.txt"), "w") as f:
        f.write("one\n")
    _before(project, data)                                    # snapshot 1, before the pipe is there
    os.makedirs(os.path.dirname(os.path.join(project, name)) or project, exist_ok=True)
    os.mkfifo(os.path.join(project, name))
    started = time.monotonic()
    _before(project, data, "echo two")
    assert time.monotonic() - started < 2.5
    rows = undo.Store(os.path.realpath(project), data).rows()
    assert "pipe or a device" in rows[-1]["unprotected"] and name in rows[-1]["unprotected"]
    assert _free(project, data), "something still holds the lock"
    env = dict(os.environ, PYTHONPATH=SRC, PYTHONDONTWRITEBYTECODE="1")
    back = subprocess.run([sys.executable, "-m", "boxdawn_guard.undo", "undo", "restore", "1", project], env=env,
                          cwd=str(tmp), capture_output=True, text=True, timeout=20)  # it used to give no answer
    assert back.returncode != 0 and "pipe or a device" in back.stdout + back.stderr
    os.remove(os.path.join(project, name))
    _before(project, data, "echo three")
    assert undo.Store(os.path.realpath(project), data).rows()[-1].get("n") == 2


def test_a_link_to_a_pipe_under_such_a_name_stops_it_too(places, monkeypatch):
    project, data, tmp = places
    _on(monkeypatch, data)
    os.mkfifo(str(tmp / "pipe"))
    os.symlink(str(tmp / "pipe"), os.path.join(project, ".gitattributes"))
    _before(project, data)
    assert "pipe or a device" in undo.Store(os.path.realpath(project), data).rows()[-1]["unprotected"]


def test_a_plain_file_or_a_dangling_link_under_such_a_name_is_nothing_special(places, monkeypatch):
    project, data, _ = places
    _on(monkeypatch, data)
    with open(os.path.join(project, ".gitattributes"), "w") as f:
        f.write("* text=auto\n")
    os.symlink("/nowhere/at/all", os.path.join(project, ".gitignore"))
    _before(project, data)
    assert undo.Store(os.path.realpath(project), data).rows()[-1].get("n") == 1


def test_pipes_and_sockets_are_named_as_left_out(places, monkeypatch, capsys):
    import socket
    project, data, _ = places
    _on(monkeypatch, data)
    with open(os.path.join(project, "a.txt"), "w") as f:
        f.write("one\n")
    os.mkfifo(os.path.join(project, "queue"))
    sock = socket.socket(socket.AF_UNIX)
    monkeypatch.chdir(project)  # by a short name: a socket's path may be 104 characters at most on macOS
    sock.bind("s.sock")
    try:
        _before(project, data)
    finally:
        sock.close()
    row = undo.Store(os.path.realpath(project), data).rows()[-1]
    assert row.get("n") == 1 and row["special"] == ["queue", "s.sock"]
    capsys.readouterr()
    undo._cli(["undo", "list", project])
    assert "not files (pipes, sockets, devices): queue, s.sock" in capsys.readouterr().out


def test_ctrl_c_in_the_holder_leaves_the_lock_with_what_still_runs(places):
    """`release` used to unlock the file the git's children share: after Ctrl+C the lock was
    free while `git repack` still ran."""
    project, data, tmp = places
    pid_file, ready = str(tmp / "pid"), str(tmp / "ready")
    holder_code = (
        "import os, sys\nfrom boxdawn_guard import undo\ns = undo.Store(sys.argv[1], sys.argv[2])\nassert s.acquire()\n"
        "open(sys.argv[4], 'w').close()\n"
        "try:\n"
        "    undo._run(['/bin/sh', '-c', sys.argv[3]], cwd=sys.argv[1], env=dict(os.environ), stdin=None, timeout=None,\n"
        "              lock=s._held)\n"
        "finally:\n"
        "    s.release()\n")
    env = dict(os.environ, PYTHONPATH=SRC, PYTHONDONTWRITEBYTECODE="1")
    holder = subprocess.Popen([sys.executable, "-c", holder_code, project, data,
                               f"sleep 60 & echo $! > {pid_file}; wait", ready], env=env, cwd=str(tmp),
                              stderr=subprocess.DEVNULL)
    assert _wait(lambda: os.path.exists(ready) and os.path.exists(pid_file) and open(pid_file).read().strip(), 20)
    sleeper = int(open(pid_file).read())
    holder.send_signal(signal.SIGINT)
    holder.wait(timeout=20)
    try:
        assert _alive(sleeper), "nothing was tested"
        assert not _free(project, data), "the lock was free while a process of the store's git still ran"
    finally:
        os.kill(sleeper, signal.SIGKILL)
    assert _wait(lambda: _free(project, data), 5)


def test_the_accounts_own_home_is_refused_when_HOME_points_elsewhere(places, monkeypatch):
    import pwd
    _, data, tmp = places
    home = os.path.realpath(pwd.getpwuid(os.getuid()).pw_dir)
    monkeypatch.setenv("HOME", str(tmp))
    assert undo._refused(home, data) == "the home folder or above it"
    assert undo._refused(os.path.dirname(home), data) == "the home folder or above it"


# ── what the second review on Linux found ───────────────────────────────────
HOOK = ("import sys\nfrom boxdawn_guard import undo\n"
        "undo.before_command({'cwd': sys.argv[1], 'tool_input': {'command': sys.argv[3]}, 'session_id': 's'}, sys.argv[2])\n")


def _hook_in_time(project, data, tmp, env, command="echo x", seconds=20):
    """The hook as its own process: one that waits for ever fails the test instead of stopping the suite."""
    subprocess.run([sys.executable, "-c", HOOK, project, data, command], env=env, cwd=str(tmp), timeout=seconds, check=True)


def _saved_then(project, data, tmp, env):
    for rel, text in (("a.txt", "one\n"), ("sub/x", "sub-x\n"), ("d/x", "d-x\n")):
        os.makedirs(os.path.dirname(os.path.join(project, rel)), exist_ok=True)
        with open(os.path.join(project, rel), "w") as f:
            f.write(text)
    _hook_in_time(project, data, tmp, env)  # snapshot 1 holds sub/x and d/x


def _nested_repository(project, outside):
    os.mkdir(os.path.join(project, "sub", ".git"))
    os.mkfifo(os.path.join(project, "sub", ".gitattributes"))


def _cannot_be_listed(project, outside):
    os.mkfifo(os.path.join(project, "sub", ".gitattributes"))
    os.chmod(os.path.join(project, "sub"), 0o300)


def _moved_out_and_linked_back(project, outside):
    os.rename(os.path.join(project, "d"), os.path.join(outside, "moved"))
    os.symlink(os.path.join(outside, "moved"), os.path.join(project, "d"))
    os.mkfifo(os.path.join(outside, "moved", ".gitattributes"))


def _replaced_by_a_link(project, outside):
    shutil.rmtree(os.path.join(project, "d"))
    os.makedirs(os.path.join(outside, "other"))
    with open(os.path.join(outside, "other", "x"), "w") as f:
        f.write("another x\n")
    os.mkfifo(os.path.join(outside, "other", ".gitattributes"))
    os.symlink(os.path.join(outside, "other"), os.path.join(project, "d"))


@pytest.fixture(params=["this git", "a git that does not know GIT_ATTR_SOURCE"])
def git_env(request, tmp_path):
    """The second: what a git before 2.40 does with the variable, which is nothing."""
    env = dict(os.environ, PYTHONPATH=SRC, PYTHONDONTWRITEBYTECODE="1", CLAUDE_PLUGIN_OPTION_UNDO="true")
    env.pop("CLAUDE_PROJECT_DIR", None)
    if request.param != "this git":
        older = tmp_path / "older-git"
        older.mkdir()
        script = older / "git"
        script.write_text(f'#!/bin/sh\nunset GIT_ATTR_SOURCE\nexec "{shutil.which("git")}" "$@"\n')
        script.chmod(0o755)
        env["PATH"] = f"{older}{os.pathsep}{env['PATH']}"
    return env


@pytest.mark.parametrize("fault", [_nested_repository, _cannot_be_listed, _moved_out_and_linked_back,
                                   _replaced_by_a_link])
def test_a_pipe_named_gitattributes_where_the_walk_does_not_go_stops_nothing(places, git_env, fault):
    """Files saved earlier lay in a folder that was then left out, or under a link: git still
    opened `.gitattributes` there, waited for ever on a pipe, and kept the lock."""
    project, data, tmp = places
    outside = str(tmp / "outside")
    os.makedirs(outside)
    env = dict(git_env, CLAUDE_PLUGIN_DATA=data)
    _saved_then(project, data, tmp, env)
    fault(project, outside)
    try:
        with open(os.path.join(project, "a.txt"), "w") as f:
            f.write("two\n")
        _hook_in_time(project, data, tmp, env, "echo two")
        rows = undo.Store(os.path.realpath(project), data).rows()
        assert rows[-1].get("n") == 2, rows[-1]
        assert _free(project, data), "something still holds the lock"
        back = subprocess.run([sys.executable, "-m", "boxdawn_guard.undo", "undo", "restore", "1", project], env=env,
                              cwd=str(tmp), capture_output=True, text=True, timeout=30)
        assert back.returncode == 0, back.stdout + back.stderr
        assert open(os.path.join(project, "a.txt")).read() == "one\n"
    finally:
        if os.path.isdir(os.path.join(project, "sub")):
            os.chmod(os.path.join(project, "sub"), 0o700)  # so the test's folder can be removed


def test_a_snapshot_in_the_background_has_an_end(monkeypatch, places):
    project, data, _ = places
    seen = {}
    monkeypatch.setattr(undo.Store, "snapshot",
                        lambda self, why, budget=None, empty_ok=False: seen.update(budget=budget) or {"n": 1, "seconds": 0})
    monkeypatch.setattr(undo.Store, "prune", lambda self: 0)
    undo.start(project, data)
    assert seen["budget"] == undo.BACKGROUND_BUDGET and 0 < undo.BACKGROUND_BUDGET < 3600 * 2


def test_a_snapshot_and_the_way_back_on_this_system(places, monkeypatch):
    """The whole path the hook takes, with the setting on, on the system the tests run on."""
    project, data, _ = places
    monkeypatch.setenv("CLAUDE_PLUGIN_OPTION_UNDO", "true")
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", data)
    monkeypatch.delenv("CLAUDE_PROJECT_DIR", raising=False)
    assert sys.platform in undo.SUPPORTED
    with open(os.path.join(project, "a.txt"), "w") as f:
        f.write("one\n")
    os.makedirs(os.path.join(project, "sub"))
    with open(os.path.join(project, "sub", ".env"), "w") as f:
        f.write("KEY=1\n")
    undo.before_command({"cwd": project, "tool_input": {"command": "rm -rf sub; echo two > a.txt"}, "session_id": "s"}, data)
    shutil.rmtree(os.path.join(project, "sub"))
    with open(os.path.join(project, "a.txt"), "w") as f:
        f.write("two\n")
    rows = undo.Store(os.path.realpath(project), data).rows()
    assert [r.get("n") for r in rows] == [1] and "unprotected" not in rows[0], rows
    assert undo._cli(["undo", "restore", "1", project]) == 0
    assert open(os.path.join(project, "a.txt")).read() == "one\n"
    assert open(os.path.join(project, "sub", ".env")).read() == "KEY=1\n"


# ── what the third review on Linux found ────────────────────────────────────
def _deleted_in_a_nested_repository(project):
    os.mkdir(os.path.join(project, "sub", ".git"))
    os.mkfifo(os.path.join(project, "sub", ".gitattributes"))
    os.remove(os.path.join(project, "sub", "x"))


def _deleted_in_a_folder_that_cannot_be_listed(project):
    os.mkfifo(os.path.join(project, "sub", ".gitattributes"))
    os.remove(os.path.join(project, "sub", "x"))
    os.chmod(os.path.join(project, "sub"), 0o300)


@pytest.mark.parametrize("fault", [_deleted_in_a_nested_repository, _deleted_in_a_folder_that_cannot_be_listed])
def test_a_restore_does_not_write_next_to_a_pipe_named_gitattributes(places, git_env, fault):
    """A saved file was gone from a left-out folder that held such a pipe: the restore's git
    wrote it back, and one that does not know GIT_ATTR_SOURCE opened the pipe and never ended."""
    project, data, tmp = places
    env = dict(git_env, CLAUDE_PLUGIN_DATA=data)
    _saved_then(project, data, tmp, env)
    fault(project)
    try:
        with open(os.path.join(project, "a.txt"), "w") as f:
            f.write("two\n")
        back = subprocess.run([sys.executable, "-m", "boxdawn_guard.undo", "undo", "restore", "1", project], env=env,
                              cwd=str(tmp), capture_output=True, text=True, timeout=30)
        assert back.returncode == 0, back.stdout + back.stderr
        assert open(os.path.join(project, "a.txt")).read() == "one\n"
        assert "left as it is: sub/x (a pipe, a socket or a device named .gitattributes" in back.stdout, back.stdout
        assert not os.path.lexists(os.path.join(project, "sub", "x"))
        assert _free(project, data), "something still holds the lock"
    finally:
        os.chmod(os.path.join(project, "sub"), 0o700)  # so the test's folder can be removed


def test_a_pipe_as_the_accounts_own_attributes_file_stops_nothing(places, git_env):
    """`~/.config/git/attributes` is read by every git unless it is told another file."""
    project, data, tmp = places
    home = tmp / "home"
    (home / ".config" / "git").mkdir(parents=True)
    os.mkfifo(home / ".config" / "git" / "attributes")
    env = dict(git_env, CLAUDE_PLUGIN_DATA=data, HOME=str(home))
    env.pop("XDG_CONFIG_HOME", None)
    _saved_then(project, data, tmp, env)
    with open(os.path.join(project, "a.txt"), "w") as f:
        f.write("two\n")
    _hook_in_time(project, data, tmp, env, "echo two")
    rows = undo.Store(os.path.realpath(project), data).rows()
    assert [r.get("n") for r in rows] == [1, 2], rows
    back = subprocess.run([sys.executable, "-m", "boxdawn_guard.undo", "undo", "restore", "1", project], env=env,
                          cwd=str(tmp), capture_output=True, text=True, timeout=30)
    assert back.returncode == 0, back.stdout + back.stderr
    assert _free(project, data), "something still holds the lock"


def test_a_git_that_never_answers_init_is_stopped(places, monkeypatch, tmp_path):
    project, data, _ = places
    slow = tmp_path / "slow-git"
    slow.mkdir()
    script = slow / "git"
    script.write_text('#!/bin/sh\nexec sleep 600\n')
    script.chmod(0o755)
    monkeypatch.setenv("PATH", f"{slow}{os.pathsep}{os.environ['PATH']}")
    store = undo.Store(os.path.realpath(project), data)
    started = time.monotonic()
    with pytest.raises(subprocess.TimeoutExpired):
        store._init(0.5)
    assert time.monotonic() - started < 10


def test_a_background_snapshot_stopped_over_its_time_says_so_in_words(places, monkeypatch):
    """The exception's own text is git's whole command line, cut off before "timed out"."""
    project, data, _ = places

    def too_slow(self, why, budget=None, empty_ok=False):
        raise subprocess.TimeoutExpired(["/usr/bin/git"] + ["-c", "core.autocrlf=false"] * 40, 5.0)
    monkeypatch.setattr(undo.Store, "snapshot", too_slow)
    said = undo.start(project, data)
    row = undo.Store(os.path.realpath(project), data).rows()[-1]
    for text in (said, row["unprotected"]):
        assert f"took over {undo.BACKGROUND_BUDGET:g} s and was stopped" in text and "core.autocrlf" not in text, text


def test_a_pipe_as_the_accounts_own_ignore_file_stops_no_restore(places, git_env):
    """`git diff` reads `~/.config/git/ignore` unless it is told another file."""
    project, data, tmp = places
    home = tmp / "home"
    (home / ".config" / "git").mkdir(parents=True)
    os.mkfifo(home / ".config" / "git" / "ignore")
    env = dict(git_env, CLAUDE_PLUGIN_DATA=data, HOME=str(home))
    env.pop("XDG_CONFIG_HOME", None)
    _saved_then(project, data, tmp, env)
    with open(os.path.join(project, "a.txt"), "w") as f:
        f.write("two\n")
    back = subprocess.run([sys.executable, "-m", "boxdawn_guard.undo", "undo", "restore", "1", project], env=env,
                          cwd=str(tmp), capture_output=True, text=True, timeout=30)
    assert back.returncode == 0, back.stdout + back.stderr
    assert open(os.path.join(project, "a.txt")).read() == "one\n"
    assert _free(project, data), "something still holds the lock"


def _git_word(args):
    """The git command among `args` (after `-c name=value` pairs and other options)."""
    words = iter(args)
    for a in words:
        if a == "-c":
            next(words)
        elif not a.startswith("-"):
            return a


def test_every_git_of_a_restore_and_of_the_clean_up_has_a_time_limit(places, monkeypatch):
    project, data, _ = places
    monkeypatch.setenv("CLAUDE_PLUGIN_OPTION_UNDO", "true")
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", data)
    monkeypatch.delenv("CLAUDE_PROJECT_DIR", raising=False)
    with open(os.path.join(project, "a.txt"), "w") as f:
        f.write("one\n")
    undo.before_command({"cwd": project, "tool_input": {"command": "echo x"}, "session_id": "s"}, data)
    os.remove(os.path.join(project, "a.txt"))
    store = undo.Store(os.path.realpath(project), data)
    seen = []
    real = undo.Store.git

    def spy(self, *args, timeout=None, **more):
        seen.append((_git_word(args), timeout))
        return real(self, *args, timeout=timeout, **more)
    monkeypatch.setattr(undo.Store, "git", spy)
    assert store.acquire()
    try:
        store.restore(1)
        monkeypatch.setattr(undo, "KEEP_SECONDS", -1)  # every snapshot but the newest is old: the clean-up drops and sweeps
        store.prune()
    finally:
        store.release()
    names = {name for name, _ in seen}
    assert {"checkout", "diff", "ls-tree", "commit-tree", "for-each-ref", "update-ref", "gc"} <= names, names
    assert [name for name, t in seen if t is None] == [], seen


def test_a_restore_whose_git_does_not_end_is_stopped_and_says_what_it_wrote(places, monkeypatch, tmp_path):
    project, data, _ = places
    monkeypatch.setenv("CLAUDE_PLUGIN_OPTION_UNDO", "true")
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", data)
    monkeypatch.delenv("CLAUDE_PROJECT_DIR", raising=False)
    with open(os.path.join(project, "a.txt"), "w") as f:
        f.write("one\n")
    undo.before_command({"cwd": project, "tool_input": {"command": "echo x"}, "session_id": "s"}, data)
    os.remove(os.path.join(project, "a.txt"))
    slow = tmp_path / "slow-git"
    slow.mkdir()
    script = slow / "git"
    script.write_text('#!/bin/sh\nfor a in "$@"; do [ "$a" = checkout ] && exec sleep 600; done\n'
                      f'exec "{shutil.which("git")}" "$@"\n')
    script.chmod(0o755)
    monkeypatch.setenv("PATH", f"{slow}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setattr(undo, "BACKGROUND_BUDGET", 2.0)
    store = undo.Store(os.path.realpath(project), data)
    assert store.acquire()
    started = time.monotonic()
    try:
        with pytest.raises(undo.PartialRestore) as stopped:
            store.restore(1)
    finally:
        store.release()
    assert time.monotonic() - started < 20
    assert "did not finish in 2 s" in str(stopped.value) and "checkout" not in str(stopped.value)
    assert stopped.value.done == [] and stopped.value.rest == ["a.txt"]
    assert not os.path.exists(os.path.join(project, "a.txt"))
    assert not os.path.exists(os.path.join(store.shadow, "index.lock"))
    assert _free(project, data)
