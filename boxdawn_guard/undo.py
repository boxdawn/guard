"""Snapshots of the project before each Bash or PowerShell command, and the way back.

Off unless the plugin setting `undo` is on. A snapshot is a commit in a
"shadow" git repository kept in the plugin's data folder, outside the project
(`--git-dir=<shadow> --work-tree=<project>`). Taking one only reads the
project: its own `.git`, index and files are not written.

In a snapshot: every file under the project folder, ignored ones too.
Not in it, and named in the record: folders in `HEAVY`, nested repositories,
a folder that cannot be listed, on Windows a folder that is a link or
junction, a file over `MAX_FILE_BYTES`, a file that could not be read.
Never in it: any `.git`.

A restore writes a file only where what is on disk now is in the snapshot it
takes first, so going back can itself be undone; anything else is skipped
and named.

Nothing here may change the guard's decision or stop a command: the hook calls
`before_command` after the decision is made and ignores whatever it raises.

Known limits:
- A file rewritten with the same size and the same modified time is not seen
  as changed.
- A project with tens of thousands of folders: finding the folders to leave
  out takes longer than a command may wait, so commands there are covered by
  the snapshots taken in the background only, and the list says so.
- The store is not protected from the agent. A command that writes into it can
  stop snapshots, or make them wrong, without a trace in the record, and the
  copies of ignored files such as `.env` in it can be read with git.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import time

HEAVY = frozenset({"node_modules", ".venv", "venv", "__pycache__", ".next", ".tox", ".mypy_cache",
                   ".pytest_cache", ".ruff_cache", ".cache", ".gradle", ".turbo"})
MAX_FILE_BYTES = 50 * 1024 * 1024
KEEP_SECONDS = 7 * 24 * 3600
MAX_STORE_BYTES = 2 * 1024 ** 3
HOOK_BUDGET = 3.0        # seconds a command may wait for its snapshot
LOCK_STALE = 15 * 60     # a lock older than this was left by a process that died
NAMED = 50               # how many left-out paths one row of the record names
_ATTRIBUTES = "* -text -filter -ident -working-tree-encoding\n"  # files go in and come out byte for byte
_REPARSE = 0x400         # FILE_ATTRIBUTE_REPARSE_POINT: a Windows symlink or junction


def enabled() -> bool:
    return (os.environ.get("CLAUDE_PLUGIN_OPTION_UNDO") or "").lower() in ("true", "1", "yes")


def project_of(payload: dict) -> str | None:
    project = os.environ.get("CLAUDE_PROJECT_DIR") or payload.get("cwd")
    return os.path.realpath(project) if project else None


def _git_exe() -> str | None:
    """Git for Windows puts a launcher on PATH (`cmd\\git.exe`); stopping it leaves
    the real git running. The real one sits next to it."""
    found = shutil.which("git")
    if found and os.name == "nt":
        folder = os.path.dirname(os.path.abspath(found))
        if os.path.basename(folder).lower() == "cmd":
            for build in ("mingw64", "clangarm64", "mingw32"):
                real = os.path.join(os.path.dirname(folder), build, "bin", "git.exe")
                if os.path.isfile(real):
                    return real
    return found


def _run(cmd: list[str], *, cwd: str, env: dict, stdin: bytes | None, timeout: float | None):
    """Like `subprocess.run`, but a process over its time is stopped with its children."""
    proc = subprocess.Popen(cmd, cwd=cwd, env=env, stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0,
                            start_new_session=os.name != "nt")
    try:
        out, err = proc.communicate(stdin, timeout=timeout)
    except subprocess.TimeoutExpired:
        if os.name == "nt":
            subprocess.run(["taskkill", "/T", "/F", "/PID", str(proc.pid)], capture_output=True)
        else:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except OSError:
                pass
        proc.kill()
        try:
            proc.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            pass
        raise
    return proc.returncode, out, err


def _long(path: str) -> str:
    """Windows calls stop at 260 characters unless the path is written this way; git does not stop."""
    if os.name == "nt" and not path.startswith("\\\\"):
        return "\\\\?\\" + os.path.abspath(path)
    return path


def _lstat(path: str):
    try:
        return os.lstat(_long(path))
    except FileNotFoundError:
        return None
    except NotADirectoryError:
        return None


def _is_link(path: str) -> bool:
    try:
        st = _lstat(path)
    except OSError:
        return True  # cannot be looked at: never walk or write through it
    return st is not None and (stat.S_ISLNK(st.st_mode) or bool(getattr(st, "st_file_attributes", 0) & _REPARSE))


def _is_folder(path: str) -> bool:
    try:
        st = _lstat(path)
    except OSError:
        return False
    return st is not None and stat.S_ISDIR(st.st_mode)


def _shown(text) -> str:
    """Command text goes to a terminal: a newline, a carriage return or an escape in it
    must not draw a line of its own."""
    return "".join(c if c.isprintable() else c.encode("unicode_escape").decode() for c in str(text))


def _inside(path: str, folder: str) -> bool:
    path, folder = os.path.normcase(path), os.path.normcase(folder)
    return path == folder or path.startswith(folder.rstrip("\\/") + os.sep)


def _refused(project: str, data_dir: str) -> str | None:
    """A project that is the home folder, above it, a drive, on the network, or
    around the store would put far more than a project in the snapshot."""
    if not os.path.isdir(project):
        return "not a folder"
    if project.replace("\\", "/").startswith("//"):
        return "a network path"
    if os.path.dirname(project) == project:
        return "a whole drive"
    if _inside(os.path.realpath(os.path.expanduser("~")), project):
        return "the home folder or above it"
    if _inside(os.path.realpath(data_dir), project):
        return "holds the snapshot store"
    return None


class Store:
    def __init__(self, project: str, data_dir: str):
        self.project = project
        key = hashlib.sha256(os.path.normcase(project).encode("utf-8", "surrogatepass")).hexdigest()[:16]
        self.root = os.path.join(os.path.realpath(data_dir), "undo")
        self.shadow = os.path.join(self.root, key + ".git")
        self.log = os.path.join(self.root, key + ".jsonl")
        self.lock = os.path.join(self.root, key + ".lock")

    # -- git ---------------------------------------------------------------
    def git(self, *args: str, timeout: float | None = None, stdin: bytes | None = None, check: bool = True):
        env = {k: v for k, v in os.environ.items() if not k.upper().startswith("GIT_")}
        env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull, GIT_CONFIG_NOSYSTEM="1",
                   GIT_ATTR_NOSYSTEM="1", GIT_TERMINAL_PROMPT="0")
        # Set on every call: the shadow's own config file must not be able to change how files are compared,
        # converted or hooked.
        fixed = ["core.autocrlf=false", "core.safecrlf=false", "core.longpaths=true", "core.fsmonitor=false",
                 "core.ignoreStat=false", "core.trustctime=true", "core.checkStat=default",
                 f"core.fileMode={'false' if os.name == 'nt' else 'true'}", f"core.hooksPath={os.devnull}", "gc.auto=0", "advice.addIgnoredFile=false",
                 "advice.addEmbeddedRepo=false"]
        code, out, err = _run(
            [_git_exe() or "git", *[part for item in fixed for part in ("-c", item)],
             f"--git-dir={self.shadow}", f"--work-tree={self.project}", *args],
            cwd=self.project, env=env, stdin=stdin, timeout=timeout)
        if check and code != 0:
            name = next((a for a in args if not a.startswith("-")), args[0])
            raise RuntimeError(f"git {name}: {err.decode('utf-8', 'replace')[-300:]}")
        return out if check else (code, out, err)

    def _init(self) -> None:
        info = os.path.join(self.shadow, "info")
        if os.path.isfile(os.path.join(self.shadow, "HEAD")) and os.path.isfile(os.path.join(info, "attributes")):
            return
        # Also for a store that was only half deleted: `git init` on what is left is safe.
        os.makedirs(self.root, mode=0o700, exist_ok=True)
        subprocess.run([_git_exe() or "git", "init", "-q", "--bare", self.shadow], check=True, capture_output=True)
        os.makedirs(info, exist_ok=True)
        with open(os.path.join(info, "attributes"), "w", encoding="utf-8") as f:
            f.write(_ATTRIBUTES)

    def _names(self, commit: str) -> set[str]:
        out = self.git("ls-tree", "-r", "-z", "--name-only", commit)
        return {os.fsdecode(p) for p in out.split(b"\0") if p}

    # -- one writer at a time ---------------------------------------------
    def acquire(self) -> bool:
        os.makedirs(self.root, mode=0o700, exist_ok=True)
        try:
            st = os.lstat(self.lock)
            # Not a plain file: nothing of ours. Old: its owner died.
            if not stat.S_ISREG(st.st_mode) or time.time() - st.st_mtime > LOCK_STALE:
                os.rmdir(self.lock) if stat.S_ISDIR(st.st_mode) and not _is_link(self.lock) else os.remove(self.lock)
        except OSError:
            pass
        try:
            os.close(os.open(self.lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY))
        except FileExistsError:
            return False
        # Ours alone now: a git that was stopped mid-way may have left its own lock.
        try:
            os.remove(os.path.join(self.shadow, "index.lock"))
        except OSError:
            pass
        return True

    def release(self) -> None:
        try:
            os.remove(self.lock)
        except OSError:
            pass

    # -- the record --------------------------------------------------------
    def rows(self) -> list[dict]:
        found = []
        try:
            with open(self.log, encoding="utf-8") as f:
                for line in f:
                    try:
                        row = json.loads(line)
                    except ValueError:
                        continue  # a line cut short by a crash must not end the record
                    at = row.get("at") if isinstance(row, dict) else None
                    # A time the clock can show; anything else was not written by this code.
                    if isinstance(at, (int, float)) and not isinstance(at, bool) and math.isfinite(at) \
                            and 0 < at < 4_000_000_000:
                        found.append(row)
        except OSError:
            pass
        return found

    def _write_new(self, path: str, lines: list[str], append: bool) -> None:
        """Mode 0600, and never through a link someone put at that path."""
        if os.path.islink(path) or (not append and os.path.lexists(path)):
            os.remove(path)
        flags = os.O_CREAT | os.O_WRONLY | (os.O_APPEND if append else os.O_EXCL)
        with os.fdopen(os.open(path, flags, 0o600), "a" if append else "w", encoding="utf-8") as f:
            f.writelines(lines)

    def note(self, row: dict) -> None:
        os.makedirs(self.root, mode=0o700, exist_ok=True)
        self._write_new(self.log, [json.dumps({"at": round(time.time(), 1), **row}) + "\n"], append=True)

    def note_once(self, reason: str, why: dict) -> None:
        """For a cause that every command would repeat (no git, a refused project)."""
        last = self.rows()[-1:]
        if not last or last[0].get("unprotected") != reason:
            self.note({"unprotected": reason, **why})

    def snapshots(self) -> list[dict]:
        # A commit is used as a git argument: nothing but an object id may pass.
        return [r for r in self.rows() if isinstance(r.get("n"), int) and not isinstance(r["n"], bool)
                and 0 < r["n"] < 10 ** 9
                and isinstance(r.get("commit"), str) and re.fullmatch(r"[0-9a-f]{40}([0-9a-f]{24})?", r["commit"])]

    # -- what stays out ----------------------------------------------------
    def _folders_left_out(self, left) -> dict[str, str]:
        """Folders the snapshot does not go into, found without following a link."""
        out: dict[str, str] = {}
        stack = [""]
        while stack:
            left()
            rel = stack.pop()
            try:
                entries = list(os.scandir(_long(os.path.join(self.project, rel))))
            except OSError:
                if rel:
                    out[rel] = "cannot be listed"
                continue
            for entry in entries:
                child = f"{rel}/{entry.name}" if rel else entry.name
                try:
                    link = entry.is_symlink() or bool(
                        getattr(entry.stat(follow_symlinks=False), "st_file_attributes", 0) & _REPARSE)
                    if link:
                        # Elsewhere git keeps a link as a link. Git for Windows walks into it.
                        if os.name == "nt" and entry.is_dir():
                            out[child] = "link"
                        continue
                    if not entry.is_dir(follow_symlinks=False) or entry.name == ".git":
                        continue
                except OSError:
                    out[child] = "cannot be listed"
                    continue
                if entry.name.casefold() in HEAVY:
                    out[child] = "heavy"
                elif os.path.lexists(os.path.join(entry.path, ".git")):
                    out[child] = "repository"
                else:
                    stack.append(child)
        return out

    def _link_above(self, rel: str, seen: dict[str, bool]) -> bool:
        parts = rel.split("/")[:-1]
        for i in range(1, len(parts) + 1):
            key = "/".join(parts[:i])
            if key not in seen:
                seen[key] = _is_link(os.path.join(self.project, *parts[:i]))
            if seen[key]:
                return True
        return False

    # -- taking one --------------------------------------------------------
    def _changed(self, exclude_file: str, timeout: float | None) -> list[str]:
        listed = self.git("ls-files", "-z", "-m", "-o", "-d", "-X", exclude_file, "--", ".", timeout=timeout)
        return sorted({os.fsdecode(p) for p in listed.split(b"\0") if p})

    def _add(self, paths: list[str], exclude_file: str, left) -> list[str]:
        """Stages `paths`; returns the ones git could not take. One path git cannot even
        look at ends the whole `add`, so on that the list is halved until it is found."""
        code, _, err = self.git("--literal-pathspecs", "add", "-A", "-f", "--ignore-errors",
                                "--pathspec-from-file=-", "--pathspec-file-nul", check=False,
                                stdin=b"\0".join(map(os.fsencode, paths)), timeout=left())
        if code == 0:
            return []
        if len(paths) == 1:
            return paths
        if b"fatal:" in err:
            half = len(paths) // 2
            return self._add(paths[:half], exclude_file, left) + self._add(paths[half:], exclude_file, left)
        still = set(self._changed(exclude_file, left()))  # these were skipped one by one
        return [rel for rel in paths if rel in still]

    def snapshot(self, why: dict, budget: float | None = None) -> dict:
        """The caller holds the lock. Raises `subprocess.TimeoutExpired` over budget."""
        started = time.perf_counter()

        def left() -> float | None:
            if budget is None:
                return None
            remaining = budget - (time.perf_counter() - started)
            if remaining <= 0:
                raise subprocess.TimeoutExpired("snapshot", budget)
            return remaining

        self._init()
        folders = self._folders_left_out(left)
        exclude_file = os.path.join(self.shadow, "info", "exclude")
        with open(exclude_file, "w", encoding="utf-8", errors="surrogateescape", newline="\n") as f:
            for rel in folders:
                if "\n" not in rel:
                    f.write("/" + "".join("\\" + c if c in "\\*?[]" else c for c in rel) + "/\n")
        changed = self._changed(exclude_file, left())
        links: dict[str, bool] = {}
        add, drop, too_big, unreadable = [], [], [], []
        for rel in changed:
            full = os.path.join(self.project, rel)
            parts = rel.split("/")
            if self._link_above(rel, links) or any("/".join(parts[:i]) in folders for i in range(1, len(parts))):
                drop.append(rel)  # was saved as a file; a link or a left-out folder stands above it now
                continue
            try:
                st = _lstat(full)
            except OSError:
                unreadable.append(rel)  # there, but not to be looked at
                continue
            if st is None:
                add.append(rel)  # deleted: `add -A` records that
            elif stat.S_ISDIR(st.st_mode) or (os.name == "nt" and getattr(st, "st_file_attributes", 0) & _REPARSE
                                              and os.path.isdir(full)):
                drop.append(rel)  # a saved file that is a folder now; its files are listed on their own
            elif st.st_size > MAX_FILE_BYTES:
                too_big.append(rel)
            else:
                add.append(rel)
        if add:
            unreadable += self._add(add, exclude_file, left)
        gone = drop + too_big + unreadable
        if gone:  # an older version in the index must not stand in for what is there now
            self.git("update-index", "--force-remove", "-z", "--stdin",
                     stdin=b"\0".join(map(os.fsencode, gone)), timeout=left())
        # The index, not the list of changes, says whether this is the same state as the last
        # snapshot: a restore changes the index without taking one.
        tree = self.git("write-tree", timeout=left()).decode().strip()
        previous = self.snapshots()
        if previous and previous[-1].get("tree") == tree:
            commit = previous[-1]["commit"]
        else:
            commit = self.git("-c", "user.name=boxdawn", "-c", "user.email=guard@localhost", "commit-tree", tree,
                              "-m", "snapshot", timeout=left()).decode().strip()
        n = max((r["n"] for r in previous), default=0) + 1
        self.git("update-ref", f"refs/snap/{n}", commit, timeout=left())
        row = {"n": n, "commit": commit, "tree": tree, "seconds": round(time.perf_counter() - started, 3), **why}
        for name, paths in (("too_large", too_big), ("unreadable", unreadable),
                            ("folders", [f"{rel} ({kind})" for rel, kind in sorted(folders.items())])):
            if paths:
                row[name] = paths[:NAMED]
                if len(paths) > NAMED:
                    row[name + "_more"] = len(paths) - NAMED
        self.note(row)
        return row

    # -- coming back -------------------------------------------------------
    def restore(self, n: int) -> tuple[dict, dict, dict[str, str]]:
        """Files as they were in snapshot `n`. The present goes into a snapshot
        first, and a file is written only where that snapshot holds what is on
        disk now. Files made after `n` stay. Returns (target, present, skipped)."""
        target = next((r for r in self.snapshots() if r["n"] == n), None)
        if target is None:
            raise LookupError(f"no snapshot {n}")
        present = self.snapshot({"note": f"before going back to {n}"})
        saved_now = self._names(present["commit"])
        differs = self.git("diff", "--name-only", "-z", present["commit"])
        differs = {os.fsdecode(p) for p in differs.split(b"\0") if p}
        links: dict[str, bool] = {}
        write, skipped = [], {}
        for rel in sorted(self._names(target["commit"])):
            full = os.path.join(self.project, rel)
            parts = rel.split("/")
            above = ["/".join(parts[:i]) for i in range(1, len(parts))]
            if self._link_above(rel, links):
                skipped[rel] = "a link stands above it"
            elif _is_folder(full) and not _is_link(full):
                skipped[rel] = "it is a folder now"
            elif rel in differs or (os.path.lexists(_long(full)) and rel not in saved_now):
                skipped[rel] = "what is there now could not be saved first"
            elif any(a not in saved_now and os.path.lexists(_long(os.path.join(self.project, a)))
                     and not _is_folder(os.path.join(self.project, a)) for a in above):
                skipped[rel] = "a file that could not be saved first is in its place"
            else:
                write.append(rel)
        if write:
            self.git("--literal-pathspecs", "checkout", target["commit"], "--pathspec-from-file=-",
                     "--pathspec-file-nul", stdin=b"\0".join(map(os.fsencode, write)))
        return target, present, skipped

    # -- keeping it small --------------------------------------------------
    def size(self) -> int:
        total = 0
        for folder, _, files in os.walk(self.shadow):
            for name in files:
                try:
                    total += os.path.getsize(os.path.join(folder, name))
                except OSError:
                    pass
        return total

    def prune(self, now: float | None = None) -> int:
        """Drops snapshots older than `KEEP_SECONDS`, then the oldest until the store
        fits `MAX_STORE_BYTES`. The newest one always stays. The caller holds the lock."""
        now = time.time() if now is None else now
        kept = self.snapshots()
        dropped = 0

        def drop(rows: list[dict]) -> None:
            nonlocal dropped
            for r in rows:
                self.git("update-ref", "-d", f"refs/snap/{r['n']}")
            dropped += len(rows)

        old = [r for r in kept[:-1] if now - r["at"] > KEEP_SECONDS]
        if old:
            drop(old)
            kept = [r for r in kept if r not in old]
            self.git("gc", "--prune=now", "-q")
        while len(kept) > 1 and self.size() > MAX_STORE_BYTES:
            oldest = kept[:max(1, len(kept) // 4)]
            drop(oldest)
            kept = kept[len(oldest):]
            self.git("gc", "--prune=now", "-q")
        if dropped:
            numbers = {r["n"] for r in kept}
            # Snapshot rows that are left, and the "unprotected" notes that are not old yet.
            rows = [r for r in self.rows()
                    if (r.get("n") in numbers if isinstance(r.get("commit"), str) else now - r["at"] <= KEEP_SECONDS)]
            self._write_new(self.log + ".tmp", [json.dumps(r) + "\n" for r in rows], append=False)
            os.replace(self.log + ".tmp", self.log)
        return dropped


def _own_command(*args: str) -> list[str]:
    if getattr(sys, "frozen", False):
        return [sys.executable, *args]
    return [sys.executable, "-m", "boxdawn_guard.undo", *args]


def start_in_background(project: str) -> None:
    """A first snapshot can take a minute on a large folder; no command waits for it."""
    flags = 0
    if os.name == "nt":
        flags = subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS
    subprocess.Popen(_own_command("undo-start", project), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL, creationflags=flags, start_new_session=os.name != "nt",
                     close_fds=True)


def before_command(payload: dict, data_dir: str | None) -> None:
    """Called by the hook for a Bash or PowerShell call it did not deny. A command
    that goes on without a snapshot gets an "unprotected" row in the record."""
    project = project_of(payload)
    if not (enabled() and data_dir and project):
        return
    store = Store(project, data_dir)
    command = payload.get("tool_input", {}).get("command")
    why = {"before": command[:200] if isinstance(command, str) else "", "session": payload.get("session_id")}
    refused = _refused(project, data_dir)
    if refused or not _git_exe():
        store.note_once(f"no snapshots here: the project is {refused}" if refused else
                        "no snapshots: git is not installed", why)
        return
    finish_later = False
    try:
        if not store.acquire():
            store.note({"unprotected": "another snapshot was still being taken", **why})
            return
        try:
            store.snapshot(why, budget=HOOK_BUDGET)
        finally:
            store.release()
    except subprocess.TimeoutExpired:
        finish_later = True
        store.note({"unprotected": f"the snapshot took over {HOOK_BUDGET:g}s; finishing in the background", **why})
    except Exception as exc:  # noqa: BLE001 - whatever it was, the record must say this command had no snapshot
        store.note({"unprotected": f"the snapshot failed ({type(exc).__name__}: {str(exc)[:200]})", **why})
    if finish_later:
        start_in_background(project)


def start(project: str, data_dir: str) -> str:
    """Session start, in the background: a snapshot with no time limit, then the clean-up."""
    project = os.path.realpath(project)
    refused = _refused(project, data_dir)
    if refused:
        return f"not taken: the project is {refused}"
    if not _git_exe():
        return "not taken: git is not installed"
    store = Store(project, data_dir)
    try:
        if not store.acquire():
            return "another snapshot is being taken"
        try:
            row = store.snapshot({"note": "session start"})
            return f"snapshot {row['n']} in {row['seconds']}s, {store.prune()} old dropped"
        finally:
            store.release()
    except Exception as exc:  # noqa: BLE001 - runs unattended; say what happened and leave
        store.note({"unprotected": f"the snapshot at session start failed ({type(exc).__name__}: {str(exc)[:200]})"})
        return f"failed: {type(exc).__name__}: {exc}"


def _left_out(row: dict) -> str:
    parts = []
    for key, label in (("too_large", "too large"), ("unreadable", "could not be read"), ("folders", "folders")):
        names = row.get(key)
        if isinstance(names, list) and names and all(isinstance(x, str) for x in names):
            more = row.get(key + "_more")
            more = f" and {more} more" if isinstance(more, int) and more > 0 else ""
            parts.append(f"{label}: {', '.join(map(_shown, names))}{more}")
    return f"\n        not in it — {'; '.join(parts)}" if parts else ""


def _cli(argv: list[str]) -> int:
    """`undo-start <project>` · `undo list [project]` · `undo restore <n> [project]`
    The project is the folder Claude Code was started in; without it, the current folder."""
    data_dir = os.environ.get("CLAUDE_PLUGIN_DATA")
    if not data_dir and getattr(sys, "frozen", False):  # <data>/current/bdxguard.exe
        data_dir = os.path.dirname(os.path.dirname(os.path.abspath(sys.executable)))
    if not data_dir:
        print("boxdawn guard undo: CLAUDE_PLUGIN_DATA is not set", file=sys.stderr)
        return 1
    if argv[:1] == ["undo-start"] and len(argv) == 2:
        result = start(argv[1], data_dir)
        print(f"boxdawn guard undo: {result}", file=sys.stderr)
        return 1 if result.startswith("failed") else 0
    if argv[:2] == ["undo", "list"]:
        store = Store(os.path.realpath(argv[2] if len(argv) > 2 else os.getcwd()), data_dir)
        rows, numbered = store.rows(), store.snapshots()
        if not rows:
            print(f"No snapshots of {_shown(store.project)} in {_shown(store.root)}. "
                  "Give the folder Claude Code was started in.")
            return 0
        for r in rows:
            when = time.strftime("%m-%d %H:%M:%S", time.localtime(r["at"]))
            what = _shown(r.get("before") or r.get("note", ""))
            if r in numbered:
                print(f"{r['n']:4d}  {when}  before: {what}{_left_out(r)}")
            elif "unprotected" in r:
                print(f"   -  {when}  NO SNAPSHOT ({_shown(r['unprotected'])}) before: {what}")
        return 0
    if argv[:2] == ["undo", "restore"] and len(argv) in (3, 4) and argv[2].isdigit():
        store = Store(os.path.realpath(argv[3] if len(argv) > 3 else os.getcwd()), data_dir)
        if not store.snapshots():
            print(f"boxdawn guard undo: no snapshots of {_shown(store.project)}", file=sys.stderr)
            return 1
        if not store.acquire():
            print("boxdawn guard undo: a snapshot is being taken; try again in a moment", file=sys.stderr)
            return 1
        highest = max(r["n"] for r in store.snapshots())
        try:
            target, present, skipped = store.restore(int(argv[2]))
        except LookupError as exc:
            print(f"boxdawn guard undo: {exc}", file=sys.stderr)
            return 1
        except Exception as exc:  # noqa: BLE001 - say where things stand instead of a traceback
            taken = [r for r in store.snapshots() if r["n"] > highest]  # the present, if this call got that far
            where = (f" The state before this attempt is snapshot {taken[-1]['n']}; some files may have been written."
                     if taken else " Nothing was written.")
            print(f"boxdawn guard undo: stopped ({type(exc).__name__}: {_shown(exc)}).{where}", file=sys.stderr)
            return 1
        finally:
            store.release()
        print(f"Files are back as they were in snapshot {target['n']}. "
              f"The state just before this is snapshot {present['n']}. Files made since stay in place.")
        for rel, reason in skipped.items():
            print(f"  left as it is: {_shown(rel)} ({reason})")
        return 0
    print(_cli.__doc__, file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(_cli(sys.argv[1:]))
