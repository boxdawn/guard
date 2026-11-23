"""Snapshots of the project before each Bash or PowerShell command, and the way back.

Off unless the plugin setting `undo` is on, and only on the systems in
`SUPPORTED`. A snapshot is a commit in a "shadow" git repository kept in the
plugin's data folder, outside the project (`--git-dir=<shadow>
--work-tree=<project>`). Taking one only reads the project: its own `.git`,
index and files are not written. Needs git 2.25 or later.

In a snapshot: every file under the project folder, ignored ones too.
Not in it, and named in the record: folders in `HEAVY`, nested repositories,
a folder that cannot be listed, on Windows a folder that is a link or
junction, a file over `MAX_FILE_BYTES`, a file that could not be saved (one
another program holds open, or a name git does not take, such as `nul` or
`aux.txt`), a pipe, a socket or a device (they are not files). While a pipe, a
socket or a device stands under the name `.gitattributes`, `.gitignore` or
`.gitmodules` where the walk goes, no snapshot is taken at all, and the record
says so for each command. (Measured with git 2.43 made to ignore
`GIT_ATTR_SOURCE`, standing in for an older git: it opens a pipe named
`.gitattributes` and waits for ever; the other names and git 2.43 as it is did
not wait. The check is wider than that: any of the three names, in any case of
letters, a socket and a link to one too, whatever the git.)
Never in it, and not named: any `.git` (the project's commits, stashes and
branches do not come back), empty folders.

A restore writes a file only where what was on disk when it looked is in the
snapshot it takes first, so going back can itself be undone; anything else is
skipped and named. A file made by the first restore stays when that restore is
undone.

Nothing here may change the guard's decision or stop a command: the hook calls
`before_command` after the decision is made and ignores whatever it raises.

Known limits:
- Another program that changes a file, or turns a folder into a link, in the
  moment between the restore's look and its write is not seen: that change is
  overwritten, or the write follows the link and lands outside the project
  (on every system; measured on Linux: 16 of 250 restores raced on purpose).
  A link that stands there before the restore looks is never written through.
- git 2.41 and later is told to read no `.gitattributes` from the project
  (`GIT_ATTR_SOURCE`). An older git opens that file in each folder holding a
  file it saves or writes: files under a folder that is left out, or under a
  link, leave the index before git looks; a pipe under that name where the walk
  goes stops the snapshot at once. What is left for an older git is a pipe put
  there while a snapshot or a restore runs: that git is ended after
  `BACKGROUND_BUDGET`, and until then it holds the lock.
- With any git, a restore does not write a file while a pipe, a socket or a
  device (or a link to one) named `.gitattributes` stands in its folder or one
  above it, also in a folder that is left out: the file is named as left as it
  is. (A git that knows `GIT_ATTR_SOURCE` would have put it back.)
- Every git this starts has a time limit (`BACKGROUND_BUDGET` at most), the
  ones of a restore and of the clean-up too.
- A project so large that its first snapshot takes longer than
  `BACKGROUND_BUDGET` gets no snapshot at all: every attempt starts from
  nothing, and the list says each time that it was stopped. Measured on Linux
  with small files: 160,000 files took 316 s, and the time grew about fourfold
  with each doubling.
- A file rewritten with the same size and the same modified time may not be
  seen as changed.
- A file changed by an edit tool is in the snapshot taken before the next Bash
  or PowerShell command, not before.
- Two snapshots at once: the second command waits for the first up to
  `HOOK_BUDGET`, then goes on without one, and the list says so.
- What comes back is the bytes of each file: not its read-only or hidden
  attribute, its modified time, its alternate data streams, or a hard link
  (it comes back as a file of its own). Off Windows, of its permissions only
  whether it can be run comes back: a file that was 0600, and one that was
  only changed, comes back with the permissions a new file gets (0644 with the
  usual umask), a folder that had to be made again likewise; extended
  attributes and the owner are not kept. "As they were then" in what a restore
  prints is about the bytes.
- A file renamed only in case (`Readme.md` to `README.md`) keeps its old name
  in the snapshots, and comes back under it.
- On Windows the store's git processes end with the process that runs them (a
  job). Elsewhere a git is handed the open lock file and so keeps the lock
  taken until it, and anything it started, has ended: a hook that is killed
  mid-snapshot leaves its git running to its end on macOS (on Linux the system
  ends it, though not what it started), and until then later commands go on
  without a snapshot and the list says another one was still being taken. The
  next holder of the lock clears every lock file git left behind
  in the store. A git that someone else runs on the store at the same time is
  not seen, and its locks are cleared under it. On Windows, a process killed while it is
  starting a git (a few milliseconds each time; measured: about 1 in 10 hooks
  killed mid-run) leaves that git behind, stopped before its first instruction:
  it does nothing and holds only its own program file (git cannot be updated
  or removed while one stands), and stays until it is ended or the machine
  restarts.
- A hook that Claude Code itself stops (over the hook's time limit) leaves no
  row for its command. The plugin's own hook has no time limit and blocks the
  command when it fails.
- While another program holds the record so that it cannot be read or written
  (a backup or scanning tool, for moments), a snapshot waits briefly, then
  fails; if the record cannot be written at all, the command has no row, and
  a snapshot that was taken just then is in the store without being listed
  (the next clean-up drops it).
- A symbolic link: on Linux it is saved as the link it is, whatever it points
  to, and comes back as that link (checked on Linux; on macOS only by the
  suite). On Windows: not checked (most likely it comes back as a plain file
  holding the target).
- A command can wait for the record up to `LOG_WAIT` seconds more than
  `HOOK_BUDGET`, when another process is writing or holding it at that moment.
- Snapshots older than `KEEP_SECONDS` are dropped at session start only (a
  long session keeps what it takes, past the limits too), per project, and the
  oldest ones while the store takes more than `MAX_STORE_BYTES` (measured as
  it lies on disk, before git packs it); the newest always stays.
- A project with tens of thousands of folders: finding the folders to leave
  out takes longer than a command may wait, so commands there are covered by
  the snapshots taken in the background only, and the list says so.
- A large project at the start of a session: until the first snapshot is
  done, commands go on without one, and the list says so.
- This is for an agent's mistakes, not for an agent that works against it.
  The store is not kept from the agent: a command that writes into it can stop
  snapshots, make them wrong or make git run a program of its choice (a filter
  in the store's config), without a trace in the record, and a command can
  read the copies of ignored files such as `.env` in it with git. The only
  thing the hook does about it is ask before a line that plainly runs the
  guard's own `undo restore`.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import math
import os
import re
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
HOOK_BUDGET = 3.0        # seconds the snapshot itself may take; the hook around it adds up to a second
BACKGROUND_BUDGET = 1800.0  # seconds a snapshot in the background, or one git of a restore or the clean-up, may take
LOG_WAIT = 2.0           # seconds a row waits for another writer of the record
SUPPORTED = ("win32", "darwin", "linux")  # where this was measured; elsewhere it stays off and says so
NAMED = 50               # how many left-out paths one row of the record names
_ATTRIBUTES = "* -text -filter -ident -working-tree-encoding\n"  # files go in and come out byte for byte
_EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"  # git's id for a tree with nothing in it
_REPARSE = 0x400         # FILE_ATTRIBUTE_REPARSE_POINT: a Windows symlink or junction
_GIT_READS = frozenset({".gitattributes", ".gitignore", ".gitmodules"})  # opened by git wherever it finds them


def enabled() -> bool:
    """On unless the user turned it off. Claude Code gives a hook no variable for an
    option the user never set (2.1.318, measured 11-23), so a missing one is the default."""
    return (os.environ.get("CLAUDE_PLUGIN_OPTION_UNDO") or "").lower() not in ("false", "0", "no")


def project_of(payload: dict) -> str | None:
    project = os.environ.get("CLAUDE_PROJECT_DIR") or payload.get("cwd")
    return os.path.realpath(project) if project else None


def _on_path(project: str | None) -> str | None:
    """`git` from the folders on PATH that are written in full and are not in the
    project. Never the current folder: a `git.bat` in a project must not run."""
    names = ("git.exe",) if os.name == "nt" else ("git",)
    for folder in os.environ.get("PATH", "").split(os.pathsep):
        folder = folder.strip('"')
        if not os.path.isabs(folder) or folder.replace("\\", "/").startswith("//") \
                or (project and _inside(os.path.realpath(folder), project)):
            continue
        for name in names:
            full = os.path.join(folder, name)
            if os.path.isfile(full) and os.access(full, os.X_OK):
                return full
    return None


def _git_exe(project: str | None = None) -> str | None:
    """Git for Windows puts a launcher on PATH (`cmd\\git.exe`); stopping it leaves
    the real git running. The real one sits next to it."""
    found = _on_path(project)
    if found and os.name == "nt":
        folder = os.path.dirname(os.path.abspath(found))
        if os.path.basename(folder).lower() == "cmd":
            for build in ("mingw64", "clangarm64", "mingw32"):
                real = os.path.join(os.path.dirname(folder), build, "bin", "git.exe")
                if os.path.isfile(real):
                    return real
    return found


_JOB: int | None = None  # this process's Windows job for its git processes; 0 when none could be made


def _job() -> int:
    """A Windows job that ends every process in it when this process ends, however it ends:
    a git must not go on writing the store after the one that holds the lock is gone."""
    global _JOB
    if _JOB is None:
        _JOB = 0
        import ctypes
        from ctypes import wintypes

        class Basic(ctypes.Structure):
            _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
                        ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                        ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                        ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD),
                        ("SchedulingClass", wintypes.DWORD)]

        class Extended(ctypes.Structure):
            _fields_ = [("BasicLimitInformation", Basic), ("IoInfo", ctypes.c_uint64 * 6),
                        ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                        ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateJobObjectW.restype = wintypes.HANDLE
        kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        kernel.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        job = kernel.CreateJobObjectW(None, None)  # not inheritable: only this process holds it
        if job:
            info = Extended()
            info.BasicLimitInformation.LimitFlags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            if kernel.SetInformationJobObject(job, 9, ctypes.byref(info), ctypes.sizeof(info)):  # extended limits
                _JOB = job
            else:
                kernel.CloseHandle(wintypes.HANDLE(job))
    return _JOB


def _start_in_job(proc: subprocess.Popen) -> None:
    """The process was made suspended: into the job before it runs a single instruction (so
    whatever it starts is in the job too), then on its way."""
    import ctypes
    from ctypes import wintypes
    try:
        job = _job()
        if job:
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
            kernel.AssignProcessToJobObject(job, int(proc._handle))
    finally:  # whatever happened above, the process must not stay suspended
        ntdll = ctypes.WinDLL("ntdll")
        ntdll.NtResumeProcess.argtypes = [wintypes.HANDLE]
        ntdll.NtResumeProcess(int(proc._handle))


def _ends_with_parent(parent: int):
    """For the new process, before it becomes git (Linux): the system ends it when the process
    that started it ends, however that ends. macOS has no such call; see `_run`."""
    def setup() -> None:
        try:
            import ctypes
            ctypes.CDLL(None, use_errno=True).prctl(1, int(signal.SIGKILL), 0, 0, 0)  # PR_SET_PDEATHSIG
        except Exception:  # noqa: BLE001 - the lock it holds (see `_run`) is what keeps the store whole
            return
        if os.getppid() != parent:  # it ended before the call above was made
            os._exit(1)
    return setup


def _run(cmd: list[str], *, cwd: str, env: dict, stdin: bytes | None, timeout: float | None,
         lock: int | None = None):
    """Like `subprocess.run`, but a process over its time is stopped with its children, and a
    git must not go on writing the store next to another holder of the lock after the one that
    started it is gone (a hook that Claude Code stops, say):
    - Windows: it ends when this process ends (see `_job`).
    - Elsewhere: it is handed the open lock file (`lock`), so the lock stays taken for as long as
      it or anything it started runs, and the next snapshot waits for it or goes on without one.
      On Linux the system also ends it when this process ends. On macOS it runs to its end."""
    flags = subprocess.CREATE_NEW_PROCESS_GROUP | 0x4 if os.name == "nt" else 0  # 0x4: CREATE_SUSPENDED
    more: dict = {}
    if os.name == "nt":
        _job()  # made before the process is: the time it stands suspended and outside the job stays short
    else:
        if lock is not None:
            more["pass_fds"] = (lock,)
        if sys.platform.startswith("linux"):
            more["preexec_fn"] = _ends_with_parent(os.getpid())
    proc = subprocess.Popen(cmd, cwd=cwd, env=env, stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=flags,
                            start_new_session=os.name != "nt", **more)
    if os.name == "nt":
        _start_in_job(proc)
    try:
        out, err = proc.communicate(stdin, timeout=timeout)
    except subprocess.TimeoutExpired:
        if os.name == "nt":
            # By its full path: a `taskkill.exe` in the project (the working folder) must not run.
            root = os.environ.get("SystemRoot") or ""
            taskkill = os.path.join(root if os.path.isabs(root) else r"C:\Windows", "System32", "taskkill.exe")
            subprocess.run([taskkill, "/T", "/F", "/PID", str(proc.pid)], capture_output=True)
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
    except BaseException:  # Ctrl+C, say: the caller lets the lock go next, and no git may outlive that
        proc.kill()
        raise
    return proc.returncode, out, err


def _take(fd: int) -> bool:
    """A lock the system holds on byte 0 of an open file, not waiting. Each open file is its
    own holder, in one process or several; it goes when the file is closed or its process ends."""
    try:
        os.lseek(fd, 0, os.SEEK_SET)  # Windows locks from where the file stands
        if os.name == "nt":
            import msvcrt
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except OSError:
        return False


def _give(fd: int) -> None:
    """Every caller closes the file next, and that lets the lock go. Off Windows nothing else
    is done here: unlocking would also take the lock from a git that was handed this open file
    and is still running (after Ctrl+C in its holder, say), while closing leaves it with that git."""
    if os.name != "nt":
        return
    try:
        os.lseek(fd, 0, os.SEEK_SET)
        import msvcrt
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
    except OSError:
        pass  # closing the file lets it go in any case


def _append(path: str, data: bytes) -> None:
    """One write at the end of the file that the system keeps whole next to another process's.
    `O_APPEND` is that everywhere but on Windows, where the C library seeks to the end and then
    writes: two processes that did so at once wrote over each other, and a row was lost (a writer
    that had waited `LOG_WAIT` for its turn writes without it). A handle opened for appending
    only is the system's own append there. The file is made with mode 0600 if it is not there."""
    if os.name != "nt":
        fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o600)
        try:
            os.write(fd, data)
        finally:
            os.close(fd)
        return
    import ctypes
    from ctypes import wintypes
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                   wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel.WriteFile.argtypes = [wintypes.HANDLE, ctypes.c_char_p, wintypes.DWORD,
                                 ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    # FILE_APPEND_DATA | SYNCHRONIZE; shared for reading, writing and deleting; OPEN_ALWAYS.
    handle = kernel.CreateFileW(_long(path), 0x0004 | 0x00100000, 0x1 | 0x2 | 0x4, None, 4, 0x80, None)
    if handle is None or handle == wintypes.HANDLE(-1).value:
        code = ctypes.get_last_error()
        # A sharing violation or no access is what `open` raises PermissionError for: the callers wait on that.
        raise PermissionError(code, ctypes.FormatError(code), path) if code in (5, 32, 33) else ctypes.WinError(code)
    try:
        written = wintypes.DWORD(0)
        if not kernel.WriteFile(handle, data, len(data), ctypes.byref(written), None) or written.value != len(data):
            code = ctypes.get_last_error()
            raise PermissionError(code, ctypes.FormatError(code), path) if code in (5, 32, 33) else ctypes.WinError(code)
    finally:
        kernel.CloseHandle(handle)


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


def _git_would_wait(path: str) -> bool:
    """A pipe, a socket or a device at `path`, or a link to one (an older git follows the link)."""
    try:
        mode = os.stat(path).st_mode
    except OSError:
        return False  # not there, or not to be reached: git cannot open it either
    return not (stat.S_ISREG(mode) or stat.S_ISDIR(mode))


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
    homes = [os.path.expanduser("~")]
    try:  # the account's own home too: `HOME` may have been pointed somewhere else
        import pwd
        homes.append(pwd.getpwuid(os.getuid()).pw_dir)
    except (ImportError, KeyError, OSError):
        pass
    if any(home and _inside(os.path.realpath(home), project) for home in homes):
        return "the home folder or above it"
    if _inside(os.path.realpath(data_dir), project):
        return "around the snapshot store"
    return None


class PartialRestore(RuntimeError):
    """The write stopped part way. `done` is None when which files were written is not known."""

    def __init__(self, message: str, present: dict, done: list[str] | None, rest: list[str],
                 skipped: dict[str, str]):
        super().__init__(message)
        self.present, self.done, self.rest, self.skipped = present, done, rest, skipped


class Store:
    def __init__(self, project: str, data_dir: str):
        self.project = project
        key = hashlib.sha256(os.path.normcase(project).encode("utf-8", "surrogatepass")).hexdigest()[:16]
        self.root = os.path.join(os.path.realpath(data_dir), "undo")
        self.shadow = os.path.join(self.root, key + ".git")
        self.log = os.path.join(self.root, key + ".jsonl")
        self.lock = os.path.join(self.root, key + ".lock")
        self._held: int | None = None  # the open lock file while this holds the lock
        self._special: list[str] = []  # pipes, sockets and devices the last walk of the project met
        self.record_by: float | None = None  # `time.monotonic()` after which no row waits for the record

    # -- git ---------------------------------------------------------------
    @staticmethod
    def _env() -> dict:
        env = {k: v for k, v in os.environ.items() if not k.upper().startswith("GIT_")}
        # GIT_ATTR_SOURCE (git 2.41 and later; an older git does not know it): attributes are read
        # from an empty tree, so no `.gitattributes` in the project is opened at all. The files go in
        # and come out byte for byte whatever such a file says (`_ATTRIBUTES`); opening one is only
        # a way to be stopped by a pipe under that name.
        env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull, GIT_CONFIG_NOSYSTEM="1",
                   GIT_ATTR_NOSYSTEM="1", GIT_TERMINAL_PROMPT="0", GIT_ATTR_SOURCE=_EMPTY_TREE)
        return env

    def _exe(self) -> str:
        exe = _git_exe(self.project)
        if not exe:
            raise RuntimeError("git is not installed")
        return exe

    def git(self, *args: str, timeout: float | None = None, stdin: bytes | None = None, check: bool = True):
        env = self._env()
        # Set on every call: the shadow's own config file must not be able to change how files are compared,
        # converted or hooked.
        fixed = ["core.autocrlf=false", "core.safecrlf=false", "core.longpaths=true", "core.fsmonitor=false",
                 "core.ignoreStat=false", "core.trustctime=true", "core.checkStat=default",
                 f"core.fileMode={'false' if os.name == 'nt' else 'true'}", f"core.hooksPath={os.devnull}",
                 # Else the account's own attributes and ignore files are read (a pipe there: no end).
                 f"core.attributesFile={os.devnull}", f"core.excludesFile={os.devnull}",
                 "gc.auto=0", "advice.addIgnoredFile=false",
                 "advice.addEmbeddedRepo=false"]
        code, out, err = _run(
            [self._exe(), *[part for item in fixed for part in ("-c", item)],
             f"--git-dir={self.shadow}", f"--work-tree={self.project}", *args],
            cwd=self.project, env=env, stdin=stdin, timeout=timeout, lock=self._held)
        if check and code != 0:
            name = next((a for a in args if not a.startswith("-")), args[0])
            raise RuntimeError(f"git {name}: {err.decode('utf-8', 'replace')[-300:]}")
        return out if check else (code, out, err)

    def _init(self, timeout: float | None = None) -> None:
        info = os.path.join(self.shadow, "info")
        if os.path.isfile(os.path.join(self.shadow, "HEAD")) and os.path.isfile(os.path.join(info, "attributes")):
            return
        os.makedirs(self.root, mode=0o700, exist_ok=True)
        code, _, err = _run([self._exe(), "init", "-q", "--bare", self.shadow], cwd=self.root, env=self._env(),
                            stdin=None, timeout=timeout, lock=self._held)
        if code != 0:
            raise RuntimeError(f"git init: {err.decode('utf-8', 'replace')[-300:]}")
        os.makedirs(info, exist_ok=True)
        with open(os.path.join(info, "attributes"), "w", encoding="utf-8") as f:
            f.write(_ATTRIBUTES)

    def _names(self, commit: str) -> set[str]:
        out = self.git("ls-tree", "-r", "-z", "--name-only", commit, timeout=BACKGROUND_BUDGET)
        return {os.fsdecode(p) for p in out.split(b"\0") if p}

    # -- one writer at a time ---------------------------------------------
    def acquire(self) -> bool:
        """A lock the system holds on the lock file's first byte: one holder at a time, and it
        goes when its process does, so one that died leaves nothing to clear. The file stays."""
        if self._held is not None:
            return False
        os.makedirs(self.root, mode=0o700, exist_ok=True)
        try:
            fd = os.open(self.lock, os.O_CREAT | os.O_RDWR, 0o600)
        except OSError:
            try:  # not a plain file (a folder, say): nothing of ours
                st = os.lstat(self.lock)
                os.rmdir(self.lock) if stat.S_ISDIR(st.st_mode) and not _is_link(self.lock) else os.remove(self.lock)
                fd = os.open(self.lock, os.O_CREAT | os.O_RDWR, 0o600)
            except OSError as exc:  # not "being taken": say what is in the way
                raise OSError(f"the store's lock file cannot be opened: {_shown(self.lock)} "
                              f"({type(exc).__name__})") from exc
        if not _take(fd):
            os.close(fd)
            return False
        self._held = fd
        self._clear_git_locks()
        return True

    def _clear_git_locks(self) -> None:
        """Every git of the store ends with its holder (Windows, `_job`) or holds the lock itself
        until it ends (elsewhere, `_run`): with the lock
        ours, no git of the store is running, and a lock file git left behind (its holder was
        stopped mid-way, by Claude Code ending a hook, say) is only in the way. Not the index's
        alone: one left under `refs/` stopped every later snapshot and restore, one on
        `packed-refs` the clean-up. Loose objects are not looked at: git puts no lock there."""
        folders = [self.shadow, os.path.join(self.shadow, "objects", "info"),
                   os.path.join(self.shadow, "objects", "pack")]
        try:
            folders += [folder for folder, _, _ in os.walk(os.path.join(self.shadow, "refs"))]
        except OSError:
            pass
        for folder in folders:
            try:
                names = [e.name for e in os.scandir(folder) if e.name.endswith(".lock") or e.name == "gc.pid"]
            except OSError:
                continue
            for name in names:
                try:
                    os.remove(os.path.join(folder, name))
                except OSError:
                    pass  # a folder under that name, say: git will give its own reason

    def release(self) -> None:
        fd, self._held = self._held, None
        if fd is not None:
            _give(fd)
            os.close(fd)

    # -- the record --------------------------------------------------------
    def rows(self, wait: float = 0.25) -> list[dict]:
        """The record. No record yet is no rows; a record that is there and cannot be read
        (another program holds it) is tried again for `wait` seconds and then raises: taking it
        for empty had the clean-up write an empty record and the numbers start again at 1."""
        deadline = time.monotonic() + wait
        while True:
            try:
                return self._read_rows()
            except FileNotFoundError:
                return []
            except OSError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.02)

    def _read_rows(self) -> list[dict]:
        found = []
        with open(self.log, encoding="utf-8", errors="replace") as f:
            for line in f:
                try:
                    row = json.loads(line)
                except (ValueError, RecursionError):
                    continue  # a line cut short by a crash, or one nested too deep, must not end the record
                at = row.get("at") if isinstance(row, dict) else None
                # A time the clock can show; anything else was not written by this code.
                if isinstance(at, (int, float)) and not isinstance(at, bool) \
                        and (isinstance(at, int) or math.isfinite(at)) and 0 < at < 4_000_000_000:
                    found.append(row)
        return found

    def _write_new(self, path: str, lines: list[str], append: bool) -> None:
        """Mode 0600, and never through a link someone put at that path."""
        if os.path.islink(path) or (not append and os.path.lexists(path)):
            os.remove(path)
        if append:
            _append(path, "".join(lines).encode("utf-8"))
            return
        with os.fdopen(os.open(path, os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o600), "w", encoding="utf-8") as f:
            f.writelines(lines)

    @contextlib.contextmanager
    def _log_turn(self, deadline: float | None = None):
        """One writer of the record at a time. Appends from several processes are not whole on
        Windows: rows were lost. Held only for a write; after `LOG_WAIT` the write goes ahead."""
        os.makedirs(self.root, mode=0o700, exist_ok=True)
        try:
            fd = os.open(self.log + ".turn", os.O_CREAT | os.O_RDWR, 0o600)
        except OSError:
            yield  # no way to take turns: write anyway
            return
        # Like the store's lock (`acquire`): a writer that died leaves nothing to clear.
        deadline, mine = time.monotonic() + LOG_WAIT if deadline is None else deadline, False
        try:
            while not mine:
                mine = _take(fd)
                if not mine:
                    if time.monotonic() > deadline:
                        break
                    time.sleep(0.005)
            yield
        finally:
            if mine:
                _give(fd)
            os.close(fd)

    def note(self, row: dict) -> None:
        deadline = time.monotonic() + LOG_WAIT  # the wait for the turn and the tries share it
        if self.record_by is not None:  # a command's rows, one after a failed other, share one wait
            deadline = min(deadline, self.record_by)
        with self._log_turn(deadline):
            while True:
                try:
                    # A row cut short by a crash has no line end: this one must not be joined to it.
                    lead = ""
                    try:
                        with open(self.log, "rb") as f:
                            f.seek(-1, os.SEEK_END)
                            lead = "" if f.read(1) == b"\n" else "\n"
                    except OSError:
                        pass  # no record yet, or an empty one
                    self._write_new(self.log, [lead + json.dumps({"at": round(time.time(), 1), **row}) + "\n"],
                                    append=True)
                    return
                except PermissionError:  # Windows: another program holds the record for a moment
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(0.02)

    def note_once(self, reason: str, why: dict) -> None:
        """For a cause that every command would repeat (no git, a refused project)."""
        try:
            last = self.rows()[-1:]
        except OSError:
            last = []  # not known: say it again rather than not at all
        if not last or last[0].get("unprotected") != reason:
            self.note({"unprotected": reason, **why})

    def snapshots(self, wait: float = 0.25) -> list[dict]:
        return self._numbered(self.rows(wait))

    @staticmethod
    def _numbered(rows: list[dict]) -> list[dict]:
        # A commit is used as a git argument: nothing but an object id may pass.
        return [r for r in rows if isinstance(r.get("n"), int) and not isinstance(r["n"], bool)
                and 0 < r["n"] < 10 ** 9
                and isinstance(r.get("commit"), str) and re.fullmatch(r"[0-9a-f]{40}([0-9a-f]{24})?", r["commit"])]

    # -- what stays out ----------------------------------------------------
    def _folders_left_out(self, left) -> dict[str, str]:
        """Folders the snapshot does not go into, found without following a link."""
        out: dict[str, str] = {}
        self._special = []
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
            for i, entry in enumerate(entries):
                if i % 256 == 255:
                    left()  # one folder can hold hundreds of thousands
                child = f"{rel}/{entry.name}" if rel else entry.name
                try:
                    link = entry.is_symlink() or bool(
                        getattr(entry.stat(follow_symlinks=False), "st_file_attributes", 0) & _REPARSE)
                    if os.name != "nt" and entry.name.lower() in _GIT_READS:
                        # git opens these in every folder it goes through, and waits for ever on a pipe.
                        plain = entry.is_file(follow_symlinks=False) or entry.is_dir(follow_symlinks=False)
                        if link:  # an older git follows the link
                            try:
                                plain = not os.path.lexists(os.path.realpath(entry.path)) \
                                    or stat.S_ISREG(os.stat(entry.path).st_mode) or os.path.isdir(entry.path)
                            except OSError:
                                plain = True  # cannot be reached: git cannot open it either
                        if not plain:
                            raise RuntimeError(f"`{child}` is a pipe or a device, and git would wait on it")
                    if link:
                        # Elsewhere git keeps a link as a link. Git for Windows walks into it.
                        if os.name == "nt" and entry.is_dir():
                            out[child] = "link"
                        continue
                    if os.name != "nt" and not entry.is_dir(follow_symlinks=False) \
                            and not entry.is_file(follow_symlinks=False):
                        self._special.append(child)  # a pipe, a socket, a device: git saves no such thing
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

    def _pipe_above(self, rel: str, seen: dict[str, bool]) -> bool:
        """A pipe or a device named `.gitattributes` in the project folder or a folder on the
        way to `rel`: a git that does not know `GIT_ATTR_SOURCE` opens it to write `rel`."""
        parts = rel.split("/")[:-1]
        for i in range(len(parts) + 1):
            key = "/".join(parts[:i])
            if key not in seen:
                seen[key] = _git_would_wait(os.path.join(self.project, *parts[:i], ".gitattributes"))
            if seen[key]:
                return True
        return False

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
        if b"pathspec-from-file" in err or b"pathspec-file-nul" in err:
            raise RuntimeError("this git is too old: 2.25 or later is needed")
        if len(paths) == 1:
            return paths
        if b"fatal:" in err:
            half = len(paths) // 2
            return self._add(paths[:half], exclude_file, left) + self._add(paths[half:], exclude_file, left)
        still = set(self._changed(exclude_file, left()))  # these were skipped one by one
        return [rel for rel in paths if rel in still]

    def snapshot(self, why: dict, budget: float | None = None, empty_ok: bool = False) -> dict:
        """The caller holds the lock. Raises `subprocess.TimeoutExpired` over budget.
        `empty_ok`: numbered even when no file could be saved (a restore must record the present
        to go back, and after a wipe that may hold nothing; what it could not save is named)."""
        try:
            return self._take_snapshot(why, budget, empty_ok)
        except subprocess.TimeoutExpired:
            # The git stopped over budget may have left its own lock. The store's lock is still
            # held, so no other git runs here, and the next snapshot must not find it.
            try:
                os.remove(os.path.join(self.shadow, "index.lock"))
            except OSError:
                pass
            raise

    def _take_snapshot(self, why: dict, budget: float | None, empty_ok: bool) -> dict:
        started = time.perf_counter()

        def left() -> float | None:
            if budget is None:
                return None
            remaining = budget - (time.perf_counter() - started)
            if remaining <= 0:
                raise subprocess.TimeoutExpired("snapshot", budget)
            return remaining

        self._init(left())
        folders = self._folders_left_out(left)
        exclude_file = os.path.join(self.shadow, "info", "exclude")
        with open(exclude_file, "w", encoding="utf-8", errors="surrogateescape", newline="\n") as f:
            for rel in folders:
                if "\n" not in rel:
                    f.write("/" + "".join("\\" + c if c in "\\*?[]" else c for c in rel) + "/\n")
        links: dict[str, bool] = {}
        add, drop, too_big, unreadable = [], [], [], []
        # Files saved before their folder was left out (it became a repository, cannot be listed
        # any more, ...) or before a link came to stand above them: the record names the folder
        # as not in the snapshot, so its files go too. They leave the index BEFORE git looks at
        # the project: git opens `.gitattributes` in every folder that holds a file it knows,
        # and a pipe under that name in a folder the walk above did not enter made it wait for ever.
        fold = str.casefold if os.name == "nt" else (lambda p: p)
        under = tuple(fold(rel) + "/" for rel in folders)
        cached = self.git("ls-files", "-z", timeout=left())
        for i, rel in enumerate(sorted({os.fsdecode(x) for x in cached.split(b"\0") if x})):
            if i % 256 == 255:
                left()
            if (under and fold(rel).startswith(under)) or self._link_above(rel, links):
                drop.append(rel)
        if drop:
            self.git("update-index", "--force-remove", "-z", "--stdin",
                     stdin=b"\0".join(map(os.fsencode, drop)), timeout=left())
        changed = self._changed(exclude_file, left())
        for i, rel in enumerate(changed):
            if i % 256 == 255:
                left()
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
            # Files git could not take are named; the rest of the project is still in the snapshot.
            # (Files another program holds open, as in `.vs/`, are refused on every snapshot.)
            unreadable += self._add(add, exclude_file, left)
        gone = drop + too_big + unreadable
        if gone:  # an older version in the index must not stand in for what is there now
            self.git("update-index", "--force-remove", "-z", "--stdin",
                     stdin=b"\0".join(map(os.fsencode, gone)), timeout=left())
        # The index, not the list of changes, says whether this is the same state as the last
        # snapshot: a restore changes the index without taking one.
        tree = self.git("write-tree", timeout=left()).decode().strip()
        if tree == _EMPTY_TREE and gone and not empty_ok:
            # Not a snapshot: do not number it. What stood in the way is named here, as a row would.
            more = f" and {len(gone) - 3} more" if len(gone) > 3 else ""
            raise RuntimeError(f"no file could be saved: {', '.join(gone[:3])}{more} left out")
        previous = self.snapshots()
        if previous and previous[-1].get("tree") == tree:
            commit = previous[-1]["commit"]
        else:
            commit = self.git("-c", "user.name=boxdawn", "-c", "user.email=guard@localhost", "commit-tree", tree,
                              "-m", "snapshot", timeout=left()).decode().strip()
        n = max((r["n"] for r in previous), default=0) + 1
        if n >= 10 ** 9:
            raise RuntimeError("the record of snapshots is damaged")  # a row past this would not be listed
        self.git("update-ref", f"refs/snap/{n}", commit, timeout=left())
        row = {"n": n, "commit": commit, "tree": tree, "seconds": round(time.perf_counter() - started, 3), **why}
        for name, paths in (("too_large", too_big), ("unreadable", unreadable), ("special", sorted(self._special)),
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
        disk now. Files that are not in `n` stay; one deleted and made anew since is
        in `n`, and goes back to what it was. Returns (target, present, skipped)."""
        target = next((r for r in self.snapshots() if r["n"] == n), None)
        if target is None:
            raise LookupError(f"no snapshot {n}")
        # Every git here has a time limit: one that waits on something holds the lock.
        present = self.snapshot({"note": f"before going back to {n}"}, budget=BACKGROUND_BUDGET, empty_ok=True)
        saved_now = self._names(present["commit"])
        differs = self.git("diff", "--name-only", "-z", present["commit"], timeout=BACKGROUND_BUDGET)
        differs = {os.fsdecode(p) for p in differs.split(b"\0") if p}
        links: dict[str, bool] = {}
        pipes: dict[str, bool] = {}
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
            elif any(os.path.lexists(_long(os.path.join(self.project, a)))
                     and not _is_folder(os.path.join(self.project, a)) for a in above):
                # Writing it would delete that file, which "files made since stay" says does not happen.
                skipped[rel] = "a file now stands where its folder was"
            elif os.name != "nt" and self._pipe_above(rel, pipes):
                skipped[rel] = "a pipe, a socket or a device named .gitattributes stands in its folder or one above"
            else:
                write.append(rel)
        if write:
            try:
                self.git("--literal-pathspecs", "checkout", target["commit"], "--pathspec-from-file=-",
                         "--pathspec-file-nul", stdin=b"\0".join(map(os.fsencode, write)),
                         timeout=BACKGROUND_BUDGET)
            except (RuntimeError, subprocess.TimeoutExpired) as exc:  # some files may be written: say which
                if isinstance(exc, subprocess.TimeoutExpired):
                    exc = RuntimeError(f"git did not finish in {BACKGROUND_BUDGET:g} s and was stopped")
                    try:  # the git that was stopped left its lock; the store's lock is still held
                        os.remove(os.path.join(self.shadow, "index.lock"))
                    except OSError:
                        pass
                try:
                    still = self.git("diff", "--name-only", "-z", target["commit"], timeout=60)
                    still = {os.fsdecode(p) for p in still.split(b"\0") if p}
                    done = [rel for rel in write if rel not in still and not _is_folder(os.path.join(self.project, rel))]
                except Exception:  # noqa: BLE001 - the first error is the one to report
                    done = None
                raise PartialRestore(str(exc), present, done, [rel for rel in write if done is None or rel not in done],
                                     skipped)
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
        fits `MAX_STORE_BYTES`. The newest one always stays. The caller holds the lock.
        The record says what is a snapshot: whatever the store holds that the record does not
        list goes too (left by a clean-up that was stopped after it rewrote the record)."""
        now = time.time() if now is None else now
        kept = self.snapshots(wait=0.5)
        dropped = 0

        def sweep() -> None:
            listed = {r["n"] for r in self.snapshots(wait=0.5)}
            refs = self.git("for-each-ref", "--format=%(refname)", "refs/snap/",
                            timeout=BACKGROUND_BUDGET).decode().split()
            gone = [ref for ref in refs
                    if not (re.fullmatch(r"refs/snap/[0-9]{1,9}", ref) and int(ref[10:]) in listed)]
            if gone:
                self.git("update-ref", "--stdin", stdin="".join(f"delete {ref}\n" for ref in gone).encode(),
                         timeout=BACKGROUND_BUDGET)
                self.git("gc", "--prune=now", "-q", timeout=BACKGROUND_BUDGET)

        def drop(rows: list[dict]) -> None:
            """The record first, then the snapshots: a record that could not be rewritten
            (someone is reading it) leaves everything as it was, to be tried next time."""
            nonlocal dropped
            gone = {r["n"] for r in rows}
            with self._log_turn():  # a row noted while this rewrites would be lost
                # Snapshot rows that are left, and the "unprotected" notes that are not old yet.
                left = [r for r in self.rows(wait=0.5)
                        if (r.get("n") not in gone if isinstance(r.get("commit"), str) else now - r["at"] <= KEEP_SECONDS)]
                self._write_new(self.log + ".tmp", [json.dumps(r) + "\n" for r in left], append=False)
                # Well under `LOG_WAIT`: a writer waiting for its turn must not give up and append
                # to the file that is about to be replaced.
                for attempt in range(15):
                    try:
                        os.replace(self.log + ".tmp", self.log)
                        break
                    except PermissionError:  # Windows: a reader has it open for a moment
                        if attempt == 14:
                            os.remove(self.log + ".tmp")
                            raise
                        time.sleep(0.05)
            sweep()
            dropped += len(rows)

        old = [r for r in kept[:-1] if now - r["at"] > KEEP_SECONDS]
        if old:
            drop(old)
            kept = [r for r in kept if r not in old]
        else:
            sweep()
        while len(kept) > 1 and self.size() > MAX_STORE_BYTES:
            oldest = kept[:max(1, len(kept) // 4)]
            drop(oldest)
            kept = kept[len(oldest):]
        return dropped


def _own_command(*args: str) -> list[str]:
    if getattr(sys, "frozen", False):
        return [sys.executable, *args]
    return [sys.executable, "-m", "boxdawn_guard.undo", *args]


def start_in_background(project: str, command: str = "") -> None:
    """A snapshot that did not fit the budget is finished here; the command has gone on.
    Its row names that command: rows written in between may stand between them in the list."""
    flags = 0
    if os.name == "nt":
        flags = subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS
    subprocess.Popen(_own_command("undo-start", project, "late", command[:200].replace("\0", "")),
                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL, creationflags=flags, start_new_session=os.name != "nt",
                     close_fds=True)


def before_command(payload: dict, data_dir: str | None) -> dict | None:
    """Called by the hook for a Bash or PowerShell call it did not deny. A command
    that goes on without a snapshot gets an "unprotected" row in the record; a cause
    that every command would repeat (system not supported, project refused, no git)
    gets one row, written again only after another row.
    While another snapshot is being taken (the one at session start, say), this waits
    for it within `HOOK_BUDGET`, then takes its own in what is left of it.
    Returns the snapshot's row when one was taken in time, else None."""
    project = project_of(payload)
    if not (enabled() and data_dir and project):
        return None
    store = Store(project, data_dir)
    command = payload.get("tool_input", {}).get("command")
    why = {"before": command[:200] if isinstance(command, str) else "", "session": payload.get("session_id")}
    refused = _refused(project, data_dir)
    if sys.platform not in SUPPORTED or refused or not _git_exe(project):
        store.note_once("no snapshots: this system is not supported yet" if sys.platform not in SUPPORTED else
                        f"no snapshots here: the project is {refused}" if refused else
                        "no snapshots: git is not installed", why)
        return None
    finish_later = False
    row = None
    started = time.perf_counter()
    store.record_by = time.monotonic() + HOOK_BUDGET + LOG_WAIT
    try:
        while not store.acquire():
            if time.perf_counter() - started + 0.05 >= HOOK_BUDGET:
                store.note({"unprotected": "another snapshot was still being taken", **why})
                return None
            time.sleep(0.05)
        try:
            row = store.snapshot(why, budget=HOOK_BUDGET - (time.perf_counter() - started))
        finally:
            store.release()
    except subprocess.TimeoutExpired:
        finish_later = True
    except Exception as exc:  # noqa: BLE001 - whatever it was, the record must say this command had no snapshot
        store.note({"unprotected": f"the snapshot failed ({type(exc).__name__}: {str(exc)[:200]})", **why})
        row = None
    if finish_later:
        # Started before the row is written: a record that cannot be written must not cost the snapshot too.
        start_in_background(project, why["before"])
        store.note({"unprotected": f"the snapshot took over {HOOK_BUDGET:g}s (waiting included); "
                                   "finishing in the background", **why})
        return None
    return row


def start(project: str, data_dir: str, note: str = "session start", late_for: str | None = None) -> str:
    """In the background: a snapshot that may take `BACKGROUND_BUDGET`, then the clean-up. `late_for`: the
    command whose snapshot did not fit its budget; if this one cannot be taken either, the
    record says so."""
    project = os.path.realpath(project)
    if sys.platform not in SUPPORTED:
        return "not taken: snapshots are not supported on this system yet"
    refused = _refused(project, data_dir)
    if refused:
        return f"not taken: the project is {refused}"
    if not _git_exe(project):
        return "not taken: git is not installed"
    store = Store(project, data_dir)
    try:
        if not store.acquire():
            if late_for is not None:
                store.note({"unprotected": "the snapshot left for later was not taken: another snapshot was "
                                           "being taken", "before": late_for})
            return "another snapshot is being taken"
        try:
            row = store.snapshot({"note": note}, budget=BACKGROUND_BUDGET)
            try:
                cleaned = f"{store.prune()} old dropped"
            except Exception as exc:  # noqa: BLE001 - the snapshot is taken; the clean-up is tried next time
                cleaned = f"clean-up left for next time ({type(exc).__name__})"
            return f"snapshot {row['n']} in {row['seconds']}s, {cleaned}"
        finally:
            store.release()
    except Exception as exc:  # noqa: BLE001 - runs unattended; say what happened and leave
        what = "the snapshot left for later" if late_for is not None else "the snapshot at session start"
        said = f"{type(exc).__name__}: {str(exc)[:200]}"
        if isinstance(exc, subprocess.TimeoutExpired):  # its own text is git's whole command line
            said = f"it took over {BACKGROUND_BUDGET:g} s and was stopped"
        try:
            store.note({"unprotected": f"{what} failed ({said})",
                        **({"before": late_for} if late_for is not None else {})})
        except Exception:  # noqa: BLE001 - the record cannot be written either: the answer below still says it
            return f"failed: {said} (and the record could not be written)"
        return f"failed: {said}"


def _left_out(row: dict) -> str:
    parts = []
    for key, label in (("too_large", "too large"), ("unreadable", "could not be saved"),
                       ("special", "not files (pipes, sockets, devices)"), ("folders", "folders")):
        names = row.get(key)
        if isinstance(names, list) and names and all(isinstance(x, str) for x in names):
            more = row.get(key + "_more")
            more = f" and {more} more" if isinstance(more, int) and more > 0 else ""
            parts.append(f"{label}: {', '.join(map(_shown, names))}{more}")
    return f"\n        not in it - {'; '.join(parts)}" if parts else ""


def _cli(argv: list[str]) -> int:
    """`undo-start <project>` · `undo list [project]` · `undo restore <n> [project]`
    The project is the folder Claude Code was started in; without it, the current folder."""
    for stream in (sys.stdout, sys.stderr):  # a console that cannot show a character must not end the list
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="backslashreplace")
    data_dir = os.environ.get("CLAUDE_PLUGIN_DATA")
    if not data_dir and getattr(sys, "frozen", False):  # <data>/current/bdxguard.exe
        data_dir = os.path.dirname(os.path.dirname(os.path.abspath(sys.executable)))
    if not data_dir:
        print("boxdawn guard undo: CLAUDE_PLUGIN_DATA is not set", file=sys.stderr)
        return 1
    if argv[:1] == ["undo-start"] and (len(argv) == 2 or (argv[2:3] == ["late"] and len(argv) in (3, 4))):
        late_for = argv[3] if len(argv) == 4 else "" if len(argv) == 3 else None
        note = ("session start" if late_for is None else
                f"finished late, after this command had started: {late_for}" if late_for else
                "finished late, after the command above had started")
        result = start(argv[1], data_dir, note, late_for)
        print(f"boxdawn guard undo: {result}", file=sys.stderr)
        return 1 if result.startswith("failed") else 0
    if argv[:2] == ["undo", "list"]:
        store = Store(os.path.realpath(argv[2] if len(argv) > 2 else os.getcwd()), data_dir)
        try:
            rows = store.rows(wait=1.0)
        except OSError as exc:
            print(f"boxdawn guard undo: the record cannot be read right now ({type(exc).__name__}): "
                  f"{_shown(store.log)}", file=sys.stderr)
            return 1
        numbered = {id(r) for r in store._numbered(rows)}  # one pass: the list is read whole every time
        if not rows:
            print(f"No snapshots of {_shown(store.project)} in {_shown(store.root)}. "
                  "Give the folder Claude Code was started in.")
            return 0
        for r in rows:
            when = time.strftime("%m-%d %H:%M:%S", time.localtime(r["at"]))
            # "before:" a command; a snapshot taken for another reason shows its note as it is.
            what = f"before: {_shown(r['before'])}" if r.get("before") else _shown(r.get("note", ""))
            if id(r) in numbered:
                print(f"{r['n']:4d}  {when}  {what}{_left_out(r)}")
            elif "unprotected" in r:
                print(f"   -  {when}  NO SNAPSHOT ({_shown(r['unprotected'])}) {what}")
        return 0
    if argv[:2] == ["undo", "restore"] and len(argv) in (3, 4) and re.fullmatch(r"[0-9]+", argv[2]):
        store = Store(os.path.realpath(argv[3] if len(argv) > 3 else os.getcwd()), data_dir)
        if sys.platform not in SUPPORTED:
            print("boxdawn guard undo: not supported on this system yet", file=sys.stderr)
            return 1
        try:
            known = store.snapshots(wait=1.0)
        except OSError as exc:
            print(f"boxdawn guard undo: the record cannot be read right now ({type(exc).__name__}): "
                  f"{_shown(store.log)}. Nothing was written.", file=sys.stderr)
            return 1
        if not known:
            print(f"boxdawn guard undo: no snapshots of {_shown(store.project)}", file=sys.stderr)
            return 1
        if not any(r["n"] == int(argv[2]) for r in known):
            print(f"boxdawn guard undo: no snapshot {int(argv[2])}", file=sys.stderr)
            return 1
        if not os.path.lexists(store.project):
            os.makedirs(store.project)  # the whole folder was removed: its files go back into a new one
        try:
            free = store.acquire()
        except OSError as exc:
            print(f"boxdawn guard undo: {_shown(exc)}. Nothing was written.", file=sys.stderr)
            return 1
        if not free:
            print("boxdawn guard undo: a snapshot is being taken; try again in a moment", file=sys.stderr)
            return 1
        try:  # read again with the lock held: a snapshot may have been taken since the look above
            highest = max((r["n"] for r in store.snapshots()), default=0)
        except OSError:
            highest = max(r["n"] for r in known)

        def where_now() -> str:
            try:
                taken = [r for r in store.snapshots() if r["n"] > highest]  # the present, if this call got that far
            except OSError:
                return " Whether the state before this attempt was saved is not known: see `undo list`."
            return f" The state before this attempt is snapshot {taken[-1]['n']}" if taken else ""
        try:
            target, present, skipped = store.restore(int(argv[2]))
        except LookupError as exc:
            print(f"boxdawn guard undo: {exc}", file=sys.stderr)
            return 1
        except PartialRestore as exc:
            print(f"boxdawn guard undo: stopped part way ({_shown(exc)}). The state before this attempt is "
                  f"snapshot {exc.present['n']}.", file=sys.stderr)
            if exc.done is None:
                print("  which files were written is not known; these were to be:", file=sys.stderr)
            for label, names in (("put back", exc.done or []), ("not put back", exc.rest),
                                 ("left as it is", [f"{rel} ({why})" for rel, why in exc.skipped.items()])):
                for rel in names[:NAMED]:
                    print(f"  {label}: {_shown(rel)}", file=sys.stderr)
                if len(names) > NAMED:
                    print(f"  {label}: and {len(names) - NAMED} more", file=sys.stderr)
            return 1
        except KeyboardInterrupt:
            where = where_now()
            print("boxdawn guard undo: interrupted. Some files may have been put back and others not."
                  f"{where + '.' if where.startswith(' The') else where}", file=sys.stderr)
            return 1
        except Exception as exc:  # noqa: BLE001 - say where things stand instead of a traceback
            # Files are written in one place only, and a stop there is the case above.
            if isinstance(exc, subprocess.TimeoutExpired):  # its own text is git's whole command line
                exc = RuntimeError(f"git did not finish in {BACKGROUND_BUDGET:g} s and was stopped")
            where = where_now()
            where = f"{where}; nothing was written." if where.startswith(" The") else where or " Nothing was written."
            print(f"boxdawn guard undo: stopped ({type(exc).__name__}: {_shown(exc)}).{where}", file=sys.stderr)
            return 1
        finally:
            store.release()
        total = len(store._names(target["commit"]))
        back = total - len(skipped)
        if back:
            print(f"{back} of the {total} files in snapshot {target['n']} are as they were then. "
                  f"The state just before this is snapshot {present['n']}. "
                  f"Files that are not in snapshot {target['n']} stay in place.")
        else:
            print(f"Nothing was put back: snapshot {target['n']} holds {total} files"
                  + (" and each was left as it is." if total else "."), file=sys.stderr)
        for rel, reason in skipped.items():
            print(f"  left as it is: {_shown(rel)} ({reason})")
        return 0 if back else 1
    print(_cli.__doc__, file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(_cli(sys.argv[1:]))
