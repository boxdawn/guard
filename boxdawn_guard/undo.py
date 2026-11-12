"""Snapshots of the project before each Bash or PowerShell command, and the way back.

Off unless the plugin setting `undo` is on. A snapshot is a commit in a
"shadow" git repository kept in the plugin's data folder, outside the project
(`--git-dir=<shadow> --work-tree=<project>`). Taking one only reads the
project: its own `.git`, index and files are not written.

In a snapshot: every file under the project folder, ignored ones too.
Not in it: the folders in `HEAVY`, any `.git`, a file over `MAX_FILE_BYTES`,
and what is inside a nested repository (git records only a pointer to it).

Nothing here may change the guard's decision or stop a command: the hook calls
`before_command` after the decision is made and ignores whatever it raises.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import time

HEAVY = ("node_modules", ".venv", "venv", "__pycache__", ".next", "dist", "build", "target", ".tox",
         ".mypy_cache", ".pytest_cache", ".ruff_cache", ".cache", ".gradle", ".turbo")
MAX_FILE_BYTES = 50 * 1024 * 1024
KEEP_SECONDS = 7 * 24 * 3600
MAX_STORE_BYTES = 2 * 1024 ** 3
HOOK_BUDGET = 3.0        # seconds a command may wait for its snapshot
LOCK_STALE = 15 * 60     # a lock older than this was left by a process that died
_ATTRIBUTES = "* -text -filter -ident -working-tree-encoding\n"  # files go in and come out byte for byte


def enabled() -> bool:
    return (os.environ.get("CLAUDE_PLUGIN_OPTION_UNDO") or "").lower() in ("true", "1", "yes")


def project_of(payload: dict) -> str | None:
    project = os.environ.get("CLAUDE_PROJECT_DIR") or payload.get("cwd")
    return os.path.realpath(project) if project else None


def _inside(path: str, folder: str) -> bool:
    path, folder = os.path.normcase(path), os.path.normcase(folder)
    return path == folder or path.startswith(folder.rstrip("\\/") + os.sep)


def _refused(project: str, data_dir: str) -> str | None:
    """A project that is the home folder, above it, a drive, or around the store
    would put far more than a project in the snapshot."""
    if not os.path.isdir(project):
        return "not a folder"
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
        key = hashlib.sha256(os.path.normcase(project).encode("utf-8")).hexdigest()[:16]
        self.root = os.path.join(os.path.realpath(data_dir), "undo")
        self.shadow = os.path.join(self.root, key + ".git")
        self.log = os.path.join(self.root, key + ".jsonl")
        self.lock = os.path.join(self.root, key + ".lock")

    # -- git ---------------------------------------------------------------
    def git(self, *args: str, timeout: float | None = None, stdin: bytes | None = None) -> bytes:
        env = {k: v for k, v in os.environ.items() if not k.upper().startswith("GIT_")}
        env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull, GIT_CONFIG_NOSYSTEM="1",
                   GIT_ATTR_NOSYSTEM="1", GIT_TERMINAL_PROMPT="0")
        run = subprocess.run(
            ["git", "-c", "core.autocrlf=false", "-c", "core.safecrlf=false", "-c", "core.longpaths=true",
             "-c", "core.fsmonitor=false", "-c", "gc.auto=0", "-c", "advice.addIgnoredFile=false",
             "-c", "advice.addEmbeddedRepo=false", f"--git-dir={self.shadow}", f"--work-tree={self.project}", *args],
            cwd=self.project, env=env, input=stdin, capture_output=True, timeout=timeout)
        if run.returncode != 0:
            raise RuntimeError(f"git {args[0]}: {run.stderr.decode('utf-8', 'replace')[-300:]}")
        return run.stdout

    def _init(self) -> None:
        if os.path.isdir(self.shadow):
            return
        os.makedirs(self.root, mode=0o700, exist_ok=True)
        subprocess.run(["git", "init", "-q", "--bare", self.shadow], check=True, capture_output=True)
        with open(os.path.join(self.shadow, "info", "attributes"), "w", encoding="utf-8") as f:
            f.write(_ATTRIBUTES)

    # -- one writer at a time ---------------------------------------------
    def acquire(self) -> bool:
        os.makedirs(self.root, mode=0o700, exist_ok=True)
        try:
            if time.time() - os.path.getmtime(self.lock) > LOCK_STALE:
                os.remove(self.lock)
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
        try:
            with open(self.log, encoding="utf-8") as f:
                return [json.loads(line) for line in f if line.strip()]
        except OSError:
            return []

    def note(self, row: dict) -> None:
        os.makedirs(self.root, mode=0o700, exist_ok=True)
        with open(self.log, "a", encoding="utf-8") as f:
            f.write(json.dumps({"at": round(time.time(), 1), **row}, ensure_ascii=False) + "\n")

    def snapshots(self) -> list[dict]:
        return [r for r in self.rows() if "commit" in r]

    # -- taking one --------------------------------------------------------
    def snapshot(self, why: dict, budget: float | None = None) -> dict:
        """The caller holds the lock. Raises `subprocess.TimeoutExpired` over budget."""
        started = time.perf_counter()
        left = (lambda: max(0.1, budget - (time.perf_counter() - started))) if budget else (lambda: None)
        self._init()
        exclude = [f":(exclude,glob)**/{h}/**" for h in HEAVY] + [f":(exclude){h}" for h in HEAVY]
        listed = self.git("ls-files", "-z", "-m", "-o", "-d", "--", ".", *exclude, timeout=left())
        changed = sorted({p for p in listed.split(b"\0") if p})
        too_big = []
        for path in changed:
            try:
                if os.lstat(os.path.join(os.fsencode(self.project), path)).st_size > MAX_FILE_BYTES:
                    too_big.append(path)
            except OSError:
                pass  # deleted: `add -A` records that
        previous = self.snapshots()
        if changed or not previous:
            add = [p for p in changed if p not in too_big]
            if add:
                self.git("--literal-pathspecs", "add", "-A", "-f", "--pathspec-from-file=-", "--pathspec-file-nul",
                         stdin=b"\0".join(add), timeout=left())
            if too_big:  # an older, smaller version must not come back in place of this one
                self.git("update-index", "--force-remove", "-z", "--stdin", stdin=b"\0".join(too_big), timeout=left())
            tree = self.git("write-tree", timeout=left()).decode().strip()
            commit = self.git("-c", "user.name=boxdawn", "-c", "user.email=guard@localhost", "commit-tree", tree,
                              "-m", "snapshot", timeout=left()).decode().strip()
        else:
            commit = previous[-1]["commit"]
        n = max((r["n"] for r in previous), default=0) + 1
        self.git("update-ref", f"refs/snap/{n}", commit, timeout=left())
        row = {"n": n, "commit": commit, "seconds": round(time.perf_counter() - started, 3),
               "left_out": [p.decode("utf-8", "replace") for p in too_big], **why}
        self.note(row)
        return row

    # -- coming back -------------------------------------------------------
    def restore(self, n: int) -> tuple[dict, dict]:
        """Files as they were in snapshot `n`. The present goes into a snapshot
        first; files made after `n` stay where they are."""
        target = next((r for r in self.snapshots() if r["n"] == n), None)
        if target is None:
            raise LookupError(f"no snapshot {n}")
        present = self.snapshot({"note": f"before going back to {n}"})
        self.git("checkout", target["commit"], "--", ".")
        return target, present

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
            with open(self.log + ".tmp", "w", encoding="utf-8") as f:
                f.writelines(json.dumps(r, ensure_ascii=False) + "\n" for r in kept)
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
    """Called by the hook for a Bash or PowerShell call it did not deny."""
    project = project_of(payload)
    if not (enabled() and data_dir and project and shutil.which("git")):
        return
    if _refused(project, data_dir):
        return
    store = Store(project, data_dir)
    command = payload.get("tool_input", {}).get("command")
    why = {"before": command[:200] if isinstance(command, str) else "", "session": payload.get("session_id")}
    if not store.acquire():
        store.note({"unprotected": "another snapshot was still being taken", **why})
        return
    try:
        store.snapshot(why, budget=HOOK_BUDGET)
    except subprocess.TimeoutExpired:
        store.release()
        store.note({"unprotected": f"the snapshot took over {HOOK_BUDGET:g}s; finishing in the background", **why})
        start_in_background(project)
    finally:
        store.release()


def start(project: str, data_dir: str) -> str:
    """Session start, in the background: a snapshot with no time limit, then the clean-up."""
    project = os.path.realpath(project)
    refused = _refused(project, data_dir)
    if refused:
        return f"not taken: the project is {refused}"
    if not shutil.which("git"):
        return "not taken: git is not installed"
    store = Store(project, data_dir)
    if not store.acquire():
        return "another snapshot is being taken"
    try:
        row = store.snapshot({"note": "session start"})
        return f"snapshot {row['n']} in {row['seconds']}s, {store.prune()} old dropped"
    finally:
        store.release()


def _cli(argv: list[str]) -> int:
    """`undo-start <project>` · `undo list [project]` · `undo restore <n> [project]`"""
    data_dir = os.environ.get("CLAUDE_PLUGIN_DATA")
    if not data_dir and getattr(sys, "frozen", False):  # <data>/current/bdxguard.exe
        data_dir = os.path.dirname(os.path.dirname(os.path.abspath(sys.executable)))
    if not data_dir:
        print("boxdawn guard undo: CLAUDE_PLUGIN_DATA is not set", file=sys.stderr)
        return 1
    if argv[:1] == ["undo-start"] and len(argv) == 2:
        print(f"boxdawn guard undo: {start(argv[1], data_dir)}", file=sys.stderr)
        return 0
    if argv[:2] == ["undo", "list"]:
        store = Store(os.path.realpath(argv[2] if len(argv) > 2 else os.getcwd()), data_dir)
        for r in store.snapshots():
            when = time.strftime("%m-%d %H:%M:%S", time.localtime(r["at"]))
            left_out = f"  (left out, too large: {', '.join(r['left_out'])})" if r.get("left_out") else ""
            print(f"{r['n']:4d}  {when}  before: {r.get('before') or r.get('note', '')}{left_out}")
        return 0
    if argv[:2] == ["undo", "restore"] and len(argv) in (3, 4) and argv[2].isdigit():
        store = Store(os.path.realpath(argv[3] if len(argv) > 3 else os.getcwd()), data_dir)
        if not store.acquire():
            print("boxdawn guard undo: a snapshot is being taken; try again in a moment", file=sys.stderr)
            return 1
        try:
            target, present = store.restore(int(argv[2]))
        except LookupError as exc:
            print(f"boxdawn guard undo: {exc}", file=sys.stderr)
            return 1
        finally:
            store.release()
        print(f"Files are back as they were in snapshot {target['n']}. "
              f"The state just before this is snapshot {present['n']}. Files made since stay in place.")
        return 0
    print(_cli.__doc__, file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(_cli(sys.argv[1:]))
