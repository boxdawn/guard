"""Which paths are secret files, which arguments read one, which ones send one.

Fixed here and not in `CommandRules`: a signed bundle must carry exactly the
fields a guard expects, so a new field there would make every guard already
installed refuse the bundle and lose the org's own rules.

By name only. This is not a sandbox: a path built at run time, a recursive
shell search, or a secret in a file with an ordinary name is not seen.
"""
from __future__ import annotations

import fnmatch
import os
import posixpath
import re
from typing import Optional

_NAMES = frozenset({".netrc", "_netrc", ".pypirc", ".npmrc", ".git-credentials"})
_DIRS = frozenset({".ssh", ".aws"})
_ENDINGS = (".aws/credentials", ".docker/config.json", ".kube/config", "gh/hosts.yml",
            ".claude/.credentials.json")
_ENV_EXAMPLES = (".example", ".sample", ".template", ".dist")
_SSH_NOT_SECRET = frozenset({"config", "authorized_keys"})
_PRIVATE_KEY = re.compile(r"id_(rsa|ed25519|ecdsa|dsa)(\..+)?")
_KEY_STORES = (".p12", ".pfx")


def _any_case(glob: str) -> str:
    """`is_secret` ignores case and a ripgrep glob does not: `.PFX` is common on Windows."""
    return re.sub(r"[a-z]", lambda m: f"[{m[0]}{m[0].upper()}]", glob)


# What a search leaves out when it was not told to read one of these. Wider than
# `is_secret`: ripgrep has no way to take `.env.example` back out of `.env.*`.
SEARCH_EXCLUDES = tuple("!" + _any_case(g) for g in (
    ".env", ".env.*", *sorted(_NAMES), *(k + e for k in ("id_rsa", "id_ed25519", "id_ecdsa", "id_dsa") for e in ("", ".*")),
    *("*" + e for e in _KEY_STORES), ".ssh", *(f"**/{e}" for e in _ENDINGS),
))


# `grep` matches a name, never a path, so what sits at a fixed path goes with its folder.
# Short on purpose: the person asked reads this line. Any case only where upper case
# is common. macOS `grep` has no `--exclude-from`, and there it finds nothing at all.
GREPS = frozenset({"grep", "egrep", "fgrep", "rgrep"})
GREP_FOLDERS = (".ssh", ".aws", ".kube", ".docker")
_GREP_VALUE_LETTERS = "efABCmDd"
_GREP_LONG_VALUES = ("--regexp", "--file", "--max-count", "--context", "--after-context", "--before-context",
                     "--devices", "--include", "--exclude", "--exclude-dir", "--exclude-from", "--label",
                     "--binary-files", "--group-separator")
GREP_EXCLUDES = (
    *(f"--exclude={n}" for n in (".env", *sorted(_NAMES), "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa",
                                 ".credentials.json", "hosts.yml")),
    "--exclude='.env.*'", "--exclude='*.[pP]12'", "--exclude='*.[pP][fF][xX]'",
    *(f"--exclude-dir={d}" for d in (".ssh", ".aws", ".docker", ".kube")),
)
_GREP_FLAGS_AS_READ = frozenset(g.replace("'", "") for g in GREP_EXCLUDES)


# GNU grep's long options: it takes any start of one that fits no other.
_GREP_LONG = (
    "--extended-regexp", "--fixed-strings", "--basic-regexp", "--perl-regexp", "--regexp", "--file",
    "--ignore-case", "--no-ignore-case", "--word-regexp", "--line-regexp", "--null-data", "--no-messages",
    "--invert-match", "--version", "--help", "--max-count", "--byte-offset", "--line-number", "--no-line-number",
    "--line-buffered", "--with-filename", "--no-filename", "--label", "--only-matching", "--quiet", "--silent",
    "--binary-files", "--text", "--directories", "--devices", "--recursive", "--dereference-recursive",
    "--include", "--exclude", "--exclude-from", "--exclude-dir", "--files-without-match", "--files-with-matches",
    "--count", "--initial-tab", "--null", "--before-context", "--after-context", "--context",
    "--group-separator", "--no-group-separator", "--color", "--colour", "--binary",
)


def _long_is(flag: str, name: str, shortest: int = 0) -> bool:
    """`flag` is `name` as `grep` reads it: the whole name, or a start that fits no other."""
    fits = [n for n in _GREP_LONG if n.startswith(flag)]
    return flag == name or (len(flag) > 2 and fits == [name])


def grep_reads(args: list) -> tuple[bool, list, bool]:
    """(searches folders, the paths it is given, has `--include`), read like `grep` reads
    them: bundles (`-rA2`, `-nd recurse`), shortened long options, a flag's value is not
    a flag, and the first word is the pattern unless `-e` or `-f` gave one."""
    recursive = includes = patterned = False
    words: list = []
    i = 0
    while i < len(args):
        a = args[i]
        i += 1
        if a is None or not a.startswith("-") or a == "-":
            words.append(a)
        elif a == "--":
            words += args[i:]
            break
        elif a.startswith("--"):
            flag, equals, value = a.partition("=")
            takes = not equals and any(_long_is(flag, n, 5) for n in _GREP_LONG_VALUES)
            if _long_is(flag, "--directories", 4):
                value = value or (args[i] if i < len(args) and args[i] else "")
                takes = not equals
                recursive = recursive or bool(value and "recurse".startswith(value))
            recursive = recursive or _long_is(flag, "--recursive", 5) or _long_is(flag, "--dereference-recursive", 5)
            includes = includes or _long_is(flag, "--include", 5)
            patterned = patterned or _long_is(flag, "--regexp", 5) or _long_is(flag, "--file", 5)
            i += 1 if takes else 0
        else:
            for at, letter in enumerate(a[1:], 1):
                recursive = recursive or letter in "rR"
                if letter in _GREP_VALUE_LETTERS:
                    patterned = patterned or letter in "ef"
                    value = a[at + 1:]
                    if not value:
                        value = args[i] if i < len(args) and args[i] else ""
                        i += 1
                    recursive = recursive or (letter == "d" and bool(value) and "recurse".startswith(value))
                    break
    return recursive, words if patterned else words[1:], includes


def grep_must_stay(args: list, paths: list, includes: bool) -> bool:
    """`--include` changes how `grep` reads every `--exclude` before it: its filter falls
    away. `--exclude` also drops a file named on the line, so a search of named files only
    stays: one named on the line would be left out. A line that already has every flag needs none."""
    if includes or _GREP_FLAGS_AS_READ <= set(args):
        return True
    names = tuple(g.split("=", 1)[1].strip("'") for g in GREP_EXCLUDES)
    return any(
        a is not None and any(fnmatch.fnmatchcase(posixpath.basename(a.rstrip("/")), n) for n in names)
        for a in paths)


def grep_folder(paths: list, workdirs: list) -> Optional[str]:
    """A credentials folder the search starts in or under, as named, as a glob, or as a
    directory the line is in. `--exclude-dir` misses the folder a search starts in."""
    for a in [*workdirs, *paths]:
        if a is None:
            continue
        for part in a.replace("\\", "/").split("/"):
            part = part.lower()
            if part in GREP_FOLDERS or (part.startswith(".") and any(c in part for c in "*?[")
                                        and any(fnmatch.fnmatchcase(f, part) for f in GREP_FOLDERS)):
                return a
    return None


def search_excludes(*roots: str) -> tuple[str, ...]:
    """A ripgrep glob is matched from the folder it starts in, so `**/.kube/config`
    misses `config` when the search starts in `.kube`."""
    roots = tuple(r.replace("\\", "/").lower().rstrip("/") for r in roots)
    here = tuple("!" + _any_case(e.rsplit("/", 1)[1]) for e in _ENDINGS
                 if any(r.endswith("/" + e.rsplit("/", 1)[0]) for r in roots))
    return SEARCH_EXCLUDES + here


def secret_folder(root: str) -> Optional[str]:
    """The `.ssh` or `.aws` this folder is, or is under."""
    parts = root.replace("\\", "/").rstrip("/").split("/")
    return next(("/".join(parts[:i + 1]) for i, p in enumerate(parts) if p.lower() in _DIRS), None)


# What a pattern is tried against.
_GLOB_TRIES = (".env", ".env.local", ".netrc", ".pypirc", ".npmrc", ".git-credentials", "_netrc",
               "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", "credentials", "config", "config.json",
               "hosts.yml", "x.p12", "x.pfx")

# These take a path and do not show what is in the file.
METADATA_ONLY = frozenset({
    "ls", "dir", "stat", "file", "test", "du", "wc", "md5sum", "sha1sum", "sha256sum", "sha512sum",
    "shasum", "b2sum", "cksum", "getfacl", "echo", "printf", "touch", "mkdir", "rm", "rmdir", "unlink",
    "chmod", "chown", "chgrp", "realpath", "readlink", "basename", "dirname", "which", "cd", "pushd",
    "find", "export", "true", "tee",
    # PowerShell
    "test-path", "get-item", "get-childitem", "gci", "gi", "resolve-path", "split-path", "join-path",
    "write-output", "write-host", "set-location", "remove-item", "clear-content", "set-content",
    "add-content", "out-file", "tee-object", "new-item", "get-filehash", "get-acl",
})
# These use the key without showing it.
USES_WITHOUT_SHOWING = frozenset({"ssh-add", "ssh-keygen"})
# The last operand is where it goes, not what is read.
COPIERS = frozenset({"cp", "mv", "copy-item", "move-item"})
# The first operand is a pattern or a script, unless a flag gave it.
PATTERN_FIRST = frozenset({"grep", "egrep", "fgrep", "rg", "ag", "sed", "awk", "gawk", "select-string"})
_PATTERN_VALUE_FLAGS = frozenset({"-e", "--regexp", "--expression", "-pattern"})
_ATTACHED_PATTERN = re.compile(r"-[a-z]*[ef].*|--(regexp|expression|file)=.*", re.S)
GIT_SHOWS = frozenset({"show", "diff", "cat-file", "blame", "archive", "grep"})
_GIT_VALUE_FLAGS = frozenset({"-C", "-c", "--git-dir", "--work-tree", "--namespace"})
# A flag naming these does not read the file: it leaves it out, or hands it to a program's environment.
_NOT_READ_FLAG = re.compile(r"--?[\w-]*(exclude|ignore|include|env-file|grep|message)[\w-]*", re.I)

SENDERS = frozenset({
    "curl", "wget", "scp", "sftp", "rsync", "nc", "ncat", "netcat", "socat", "ftp", "telnet", "ssh",
    "http", "https", "invoke-webrequest", "invoke-restmethod", "iwr", "irm",
})
_COPY_VALUE_FLAGS = frozenset({"-i", "-e", "-P", "-o", "-F", "-l", "-S", "--rsh", "--exclude", "--include",
                               "--filter", "--exclude-from", "--include-from"})
_CURL_LONG = frozenset({"--data", "--data-ascii", "--data-binary", "--data-urlencode", "--json",
                        "--form", "--upload-file"})
_CURL_SHORT = re.compile(r"-[sSkLvfiIgGNqO#]*([dFT])(.*)", re.S)
_FILE_IN_VALUE = re.compile(r"[@<]([^;]+)")


def is_secret(path: str, *, glob_matches_dots: bool = False) -> bool:
    """`glob_matches_dots`: a shell `*` skips a leading dot, a ripgrep glob does not."""
    p = path.replace("\\", "/").lower().rstrip("/")
    p = p.split("::", 1)[0]  # NTFS: `.env::$DATA` is the same file
    parent, name = posixpath.split(p)
    if re.search(r"[*?\[]", name):
        return _glob_is_secret(parent, name, glob_matches_dots)
    if name in _NAMES or name in _DIRS:
        return True
    if name == ".env" or (name.startswith(".env.") and not name.endswith(_ENV_EXAMPLES)):
        return True
    if name.endswith(_KEY_STORES):
        return True
    if _PRIVATE_KEY.fullmatch(name) and not name.endswith(".pub"):
        return True
    if posixpath.basename(parent) == ".ssh":
        return not (name.endswith(".pub") or name.startswith("known_hosts") or name in _SSH_NOT_SECRET)
    return any(p == e or p.endswith("/" + e) for e in _ENDINGS)


def _glob_is_secret(parent: str, name: str, matches_dots: bool) -> bool:
    if not name.strip("*?"):
        if posixpath.basename(parent) in _DIRS:
            return True
        return name.startswith(".")
    dots = matches_dots or name.startswith(".")
    tries = _GLOB_TRIES if dots else [t for t in _GLOB_TRIES if not t.startswith(".")]
    return any(fnmatch.fnmatchcase(t, name) and is_secret(posixpath.join(parent, t)) for t in tries)


def path_in_argument(arg: str) -> Optional[str]:
    """The path an argument names, if it names one: `.env`, `@.env`, `if=.env`,
    `--file=.env`. Not a URL, `A=1` or a flag that leaves the file out."""
    if "://" in arg:
        return None
    if arg.startswith("-"):
        flag, equals, value = arg.partition("=")
        if not equals or _NOT_READ_FLAG.fullmatch(flag):
            return None
        arg = value
    elif arg.startswith("if="):
        arg = arg[3:]
    elif re.match(r"\w+=", arg):
        return None
    return arg.lstrip("@") or None


def pattern_is_first(name: str, args: list) -> bool:
    """No flag gave the pattern, so the first operand is it."""
    if name not in PATTERN_FIRST:
        return False
    return not any(a is not None and (a.lower() in _PATTERN_VALUE_FLAGS or a in ("-f", "--file")
                                      or (not a.startswith("-pattern") and _ATTACHED_PATTERN.fullmatch(a)))
                   for a in args)


def flag_values_to_skip(name: str, args: list) -> set:
    """Positions holding a value that is not a file to read."""
    skip = set()
    for i, a in enumerate(args):
        if a is None or not a.startswith("-") or "=" in a:
            continue
        if _NOT_READ_FLAG.fullmatch(a) or (name in PATTERN_FIRST and a.lower() in _PATTERN_VALUE_FLAGS):
            skip.add(i + 1)
    return skip


def git_subcommand(args: list) -> Optional[str]:
    i = 0
    while i < len(args):
        a = args[i]
        if a in _GIT_VALUE_FLAGS:
            i += 2
        elif a is not None and a.startswith("-"):
            i += 1
        else:
            return a
    return None


def sent_paths(name: str, args: list) -> list[str]:
    """The files this program is told to upload. A sender given a path any other
    way (`curl -o .env`, `ssh host 'ls ~/.ssh'`, `rsync --exclude=.env`) sends nothing."""
    if name == "curl":
        return _curl_sent(args)
    if name == "wget":
        return [a.split("=", 1)[1] for a in args if a and a.startswith(("--post-file=", "--body-file="))]
    if name in ("scp", "rsync", "sftp"):
        return _copied_out(args)
    if name in ("invoke-webrequest", "invoke-restmethod", "iwr", "irm"):
        return [args[i + 1] for i, a in enumerate(args[:-1]) if a and a.lower() == "-infile" and args[i + 1]]
    if name in ("http", "https"):
        return [m.group(1) for a in args if a and (m := re.fullmatch(r"[\w-]+@(.+)", a))]
    if name == "socat":
        return [m.group(1) for a in args if a and (m := re.match(r"(?i)(?:file|open|gopen):([^,]+)", a))]
    return []


def _curl_sent(args: list) -> list[str]:
    out = []
    for i, a in enumerate(args):
        if a is None:
            continue
        following = args[i + 1] if i + 1 < len(args) else None
        if a.startswith("file://"):
            out.append(a[len("file://"):])
            continue
        if a.startswith("--"):
            flag, equals, value = a.partition("=")
            if flag not in _CURL_LONG:
                continue
            value = value if equals else following
            kind = "T" if flag == "--upload-file" else "d"
        elif m := _CURL_SHORT.fullmatch(a):
            kind, value = m.group(1), m.group(2) or following
        else:
            continue
        if value is None:
            continue
        if kind == "T":
            out.append(value)
        elif found := _FILE_IN_VALUE.search(value):
            out.append(found.group(1))
    return out


def _copied_out(args: list) -> list[str]:
    operands, skip = [], False
    for a in args:
        if skip:
            skip = False
        elif a is None:
            operands.append(None)
        elif a.startswith("-"):
            skip = a in _COPY_VALUE_FLAGS
        else:
            operands.append(a)
    if len(operands) < 2 or not _is_remote(operands[-1]):
        return []
    return [a for a in operands[:-1] if a is not None and not _is_remote(a)]


# `h:/tmp` is drive H on Windows. Elsewhere there are no drive letters, so it
# is the host `h`.
_WINDOWS = os.name == "nt"


def _is_remote(path: Optional[str]) -> bool:
    if path is None or ":" not in path:
        return False
    return not (_WINDOWS and re.match(r"[A-Za-z]:[\\/]", path))


def literals_in_code(code: str) -> list[str]:
    """Quoted strings in inline code. Text, not meaning: a path put together
    while the code runs is not seen."""
    return re.findall(r"""["']([^"'\n]{1,300})["']""", code)
