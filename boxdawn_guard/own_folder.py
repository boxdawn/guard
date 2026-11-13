"""Whether a tool call reaches into the plugin's data folder.

While `undo` is on, that folder holds copies of the project, ignored files
such as `.env` too. A command that names a path in it, written in any of the
ways a shell on this machine would read as that path, is not let through.

How a command is read: every word of it (quotes taken off, and also split on
the spaces inside quotes, so a `cmd /c "..."` or `bash -c '...'` is read too),
with `$HOME`, `%USERPROFILE%`, `$env:...`, `$CLAUDE_PLUGIN_DATA` and the
variables the line itself assigns put in, is turned into a full path from the
folder the command runs in, or from any folder the line names above the data
folder, and compared with the data folder.

Not seen: a path put together from pieces only when the command runs (command
substitution, a glob, a value read from a file), a link that already leads
there, and what a script or program does once it runs. A line that only
mentions the folder, in a message for instance, is treated the same as one
that uses it, and so is a line that names a folder beside it whose name is
the data folder's name, a space and more, written in quotes.
"""
from __future__ import annotations

import os
import re
import socket

_SEPARATORS = set(";|&<>()\r\n\t ")
_ASSIGN = re.compile(r"(?:^|[\s;&|(])\$?([A-Za-z_]\w*)\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s;&|)]*)")
_VARIABLE = re.compile(r"\$\{env:(\w+)\}|\$env:(\w+)|\$\{(\w+)(?::?[-=?+][^}]*)?\}|\$(\w+)|%(\w+)(?::[^%]*)?%", re.I)
_ANSI_C = re.compile(r"\$'((?:[^'\\]|\\.)*)'")


def within(path: str, folder: str) -> bool:
    """Both full, normalised and case-folded the way this system compares names."""
    return path == folder or path.startswith(folder.rstrip("\\/") + os.sep)


def _norm(path: str) -> str:
    return os.path.normcase(os.path.normpath(path))


def folder_to_keep(data_dir: str | None, project: str | None) -> str | None:
    """The data folder, unless the setting points somewhere no rule could keep:
    a whole drive, the home folder or above it, or around the project."""
    if not data_dir:
        return None
    folder = _norm(os.path.realpath(data_dir))
    home = _norm(os.path.realpath(os.path.expanduser("~")))
    if os.path.dirname(folder) == folder or within(home, folder):
        return None
    if project and within(_norm(os.path.realpath(project)), folder):
        return None
    return folder


def _this_machine() -> set[str]:
    names = {"localhost", "127.0.0.1", "::1", "[::1]", "."}
    for name in (os.environ.get("COMPUTERNAME"), socket.gethostname()):
        if name:
            names.add(name.lower())
    return names


def _local(word: str) -> str:
    """The forms Windows, Git Bash, WSL and Cygwin write a path of this machine in, as `C:/...`."""
    w = word.replace("\\", "/")
    if os.name != "nt":
        return w
    w = re.sub(r"^//[?.]/globalroot/(?:dosdevices|global\?\?)/", "", w, flags=re.I)
    unc = re.match(r"^//[?.]/unc/", w, re.I)
    w = "//" + w[unc.end():] if unc else re.sub(r"^//[?.]/", "", w)
    share = re.match(r"^//([^/]+)/([a-z])\$(?=/|$)", w, re.I)
    if share and share.group(1).lower() in _this_machine():
        w = share.group(2) + ":" + w[share.end():]
    for start in ("/proc/cygdrive/", "/cygdrive/", "/mnt/", "/"):
        drive = re.match("^" + start + r"([a-z])(?=/|$)", w, re.I)
        if drive:
            return drive.group(1) + ":" + w[drive.end():]
    return w


def absolute(word: str, base: str) -> str | None:
    """`word` as a full path from `base`, normalised; None for a path on another machine."""
    w = _local(word)
    if w.startswith("~"):
        w = os.path.expanduser(w)
    if w.replace("\\", "/").startswith("//"):
        return None  # a share on another machine; looking it up would contact it
    if os.name == "nt":
        parts = re.split(r"[\\/]", w)
        kept = []
        for i, part in enumerate(parts):
            if i == 0 and re.fullmatch(r"[A-Za-z]:", part):
                kept.append(part)
                continue
            if ":" in part:
                part = part.split(":", 1)[0]  # an alternate data stream names the file before it
            if part not in (".", ".."):
                part = part.rstrip(". ")
            kept.append(part)
        w = "/".join(kept)
    path = _norm(os.path.join(base, w))
    if os.name == "nt" and re.search(r"~\d", path):
        try:
            path = _norm(os.path.realpath(path))  # a short 8.3 name
        except OSError:
            pass
    return path


def looks_absolute(word: str) -> bool:
    return word.startswith(("/", "\\", "~")) or bool(re.match(r"[A-Za-z]:", word))


def _values(text: str) -> dict[str, str]:
    home = os.path.expanduser("~")
    drive, rest = os.path.splitdrive(home)
    values = {"HOME": home, "USERPROFILE": os.environ.get("USERPROFILE") or home,
              "HOMEDRIVE": os.environ.get("HOMEDRIVE") or drive, "HOMEPATH": os.environ.get("HOMEPATH") or rest}
    if os.environ.get("CLAUDE_PLUGIN_DATA"):
        values["CLAUDE_PLUGIN_DATA"] = os.environ["CLAUDE_PLUGIN_DATA"]
    for m in _ASSIGN.finditer(text):  # what the line sets, as written
        values[m.group(1).upper()] = m.group(2).strip("\"'")
    return values


def _ansi_c(body: str) -> str:
    try:
        return body.encode("utf-8").decode("unicode_escape")
    except UnicodeDecodeError:
        return body


def expanded(text: str) -> str:
    text = _ANSI_C.sub(lambda m: _ansi_c(m.group(1)), text)
    values = _values(text)

    def put(m: re.Match) -> str:
        name = next(g for g in m.groups() if g)
        return values.get(name.upper(), m.group(0))
    for _ in range(3):  # a value that names another variable
        text = _VARIABLE.sub(put, text)
    return text


def _words(text: str, quoted: bool, skip: str = "") -> list[str]:
    """Shell words. `quoted`: a quoted part stays one word with the word around it."""
    words, current, quote = [], [], None
    for ch in text:
        if ch in skip:
            continue
        if quote:
            if ch == quote:
                quote = None
            elif quoted:
                current.append(ch)
            elif ch.isspace():
                words.append("".join(current))
                current = []
            else:
                current.append(ch)
        elif ch in "\"'":
            quote = ch
        elif ch in _SEPARATORS or ch.isspace() or ch == "`":
            words.append("".join(current))
            current = []
        else:
            current.append(ch)
    words.append("".join(current))
    return [w for w in words if w]


def _variants(word: str) -> set[str]:
    found = {word}
    if "\\" in word:
        found.add(re.sub(r"\\(.)", r"\1", word))  # a backslash that only escapes the next letter
    for w in list(found):
        braces = re.search(r"\{([^{}]*)\}", w)
        if braces:
            found.update(w[:braces.start()] + alt + w[braces.end():] for alt in braces.group(1).split(","))
    for w in list(found):
        if "=" in w:
            found.update(w.split("=")[1:])
        if w.startswith("-") and len(w) > 2:
            found.add(w.lstrip("-"))
            found.add(w[2:])
            option = re.match(r"-+\w+:", w)
            if option:
                found.add(w[option.end():])
        if w.lower().startswith("file:"):
            found.add(re.sub(r"^file:/*", "/", w, flags=re.I))
    return {w for w in found if w}


def command_words(command: str) -> set[str]:
    text = expanded(command)
    found = set()
    for skip in ("", "`^"):
        found.update(_words(text, True, skip))
    found.update(w for w in re.split(r"""[\s;|&<>()`'",]+""", text) if w)  # a path inside code: open('...', 'a')
    return found


def command_reaches(command: str, folder: str, cwd: str) -> bool:
    """Whether a word of `command` is a path in `folder`."""
    cwd = _norm(cwd)
    name = os.path.normcase(os.path.basename(folder))
    bases, relative = [cwd], []
    for word in command_words(command):
        for v in _variants(word):
            path = absolute(v, cwd)
            if path is None:
                continue
            if within(path, folder):
                return True
            if within(folder, path):
                bases.append(path)  # a folder above the data folder: a later relative word may start there
            if not looks_absolute(v) and name in os.path.normcase(v):
                relative.append(v)
    return any(p is not None and within(p, folder) for v in relative for b in bases[1:] for p in [absolute(v, b)])


def path_reaches(path: str, cwd: str | None, folder: str) -> bool:
    """A file tool's path: as written, then on disk (a link or junction, a short name)."""
    for v in _variants(path.strip()):
        full = absolute(v, cwd or os.getcwd())
        if full is None:
            continue
        if within(full, folder):
            return True
        try:
            if within(_norm(os.path.realpath(full)), folder):
                return True
        except OSError:
            pass
    return False


def own_command(command: str, folder: str, cwd: str) -> str | None:
    """`list` or `restore` when the whole line is the guard's own undo command and nothing else."""
    if not all(ch.isprintable() for ch in command):  # PowerShell ends a statement at a carriage return too
        return None
    text = command.strip()
    if text.startswith("&"):
        text = text[1:].lstrip()  # PowerShell's call operator
    if re.search(r"[;&|<>$()%{}`^!*?\[\]=]", text):
        return None
    words = _words(text, quoted=True)
    exe = os.path.normcase(os.path.join(folder, "current", "bdxguard.exe"))
    if len(words) < 3 or absolute(words[0], cwd) != exe or words[1].lower() != "undo":
        return None
    action, rest = words[2].lower(), words[3:]
    if action == "restore" and rest and rest[0].isdigit():
        rest = rest[1:]
    if action not in ("list", "restore") or len(rest) > 1:
        return None
    if rest and (rest[0].startswith("-") or command_reaches(rest[0], folder, cwd)):
        return None
    return action
