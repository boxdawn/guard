"""Judge a shell command before it runs: deny, ask, or no decision.

What it is built against:

- GuardFall (CSA research note, 2026-07-11): filters that read the command as
  text lose to the shell rewriting it — quote removal, $IFS, command
  substitution, base64 piped to sh, other tools with the same effect. So the
  command is parsed (tree-sitter-bash) and every word is reduced to the value
  the shell would see, or to "unknown" when that value only exists at run time.
- Continue CVE-2026-76072: its evaluator survived GuardFall and still fell to
  `rm -rf $HOME` (a variable read as an empty token), to directories missing
  from its list, and to "needs permission" passing unattended. So an unknown
  value is never a safe one, anything risky outside a list asks rather than
  passing, and `unattended=True` turns every ask into a deny.

The output is deny, ask or None — never allow. None leaves the call to the
user's own permission settings; this guard only ever adds friction.

The parser is not bash (it splits `rm$IFS-rf$IFS/` differently), so any parse
error or unreadable name is "ask", not a guess.
"""
from __future__ import annotations

import os
import posixpath
import re
import shlex
from dataclasses import dataclass, field
from glob import escape as glob_escape, iglob
from itertools import islice
from typing import Optional

import tree_sitter_bash
from tree_sitter import Language, Node, Parser

from boxdawn_guard import secret_files

Value = Optional[str]  # None: only known at run time

_LEVEL = {None: 0, "ask": 1, "deny": 2}
_MAX_DEPTH = 4  # sh -c inside eval inside sh -c ...

_PARSER = Parser(Language(tree_sitter_bash.language()))


@dataclass(frozen=True)
class CustomRule:
    """A rule a paying org added (server 0032), matched on what this guard
    reads, never on the command text. It can only ask or deny: there is no
    rule that lets anything through."""
    id: str                    # "r12"; reported as "custom.r12"
    level: str                 # "ask" or "deny"
    command: str               # the name, lower case, no ".exe"
    args: tuple[str, ...] = ()   # positional words, in this order (others may sit between)
    flags: tuple[str, ...] = ()  # any one of these, as `--x` or `--x=value`
    note: str = ""             # the org's reason, shown to the person asked


@dataclass(frozen=True)
class CommandRules:
    """The rule values. Data, so they can come from a signed bundle later."""

    interpreters: frozenset[str]          # read code from stdin when piped into
    shells: frozenset[str]                # their -c text is judged as shell
    code_flags: dict[str, frozenset[str]]  # interpreter -> flags taking code
    wrappers: frozenset[str]              # run the rest of the line as a command
    privilege: frozenset[str]             # run the rest with more rights
    source: frozenset[str]                # run a script file in this shell
    always_deny: frozenset[str]
    always_deny_prefixes: tuple[str, ...]
    devices: tuple[str, ...]              # block-device paths
    harmless_devices: frozenset[str]
    db_clients: frozenset[str]
    db_code_flags: frozenset[str]
    db_file_flags: frozenset[str]
    db_destructive: tuple[str, ...]       # regexes, case-insensitive
    inline_code_risky: dict[str, tuple[str, ...]]  # interpreter -> regexes over its code
    scratch_dirs: tuple[str, ...]         # temp roots: work inside is fine, wiping them is not
    unattended_modes: frozenset[str]
    custom: tuple[CustomRule, ...] = ()   # the org's own rules, from a signed bundle


@dataclass(frozen=True)
class Finding:
    """One flag in a form that may leave the machine: every field comes from
    a closed set, so no path, command text or value can ride along. `reasons`
    on the Verdict keep the readable sentence (with paths) for the person
    at the keyboard; they stay local."""
    rule: str                  # one of RULE_IDS; stable, never reused
    level: str                 # "deny" or "ask"
    target: Optional[str] = None  # one of TARGETS, or None when no path is involved


@dataclass(frozen=True)
class Verdict:
    decision: Optional[str]
    reasons: tuple[str, ...]
    findings: tuple[Finding, ...] = ()
    escalated: bool = False    # an "ask" became "deny" because nobody is present
    grep_ends: tuple[int, ...] = ()  # where a recursive `grep` name ends, in bytes of the line


# Stable ids (SARIF: rule ids SHALL be stable). Retire an id, never reuse it.
RULE_IDS = frozenset({
    "guard.crashed", "parse.too_deep", "parse.unreadable", "name.runtime",
    "code.inline_unknown_language", "code.inline_risky", "code.runtime", "code.stdin_runtime",
    "privilege.elevated", "privilege.su_runtime", "eval.runtime", "source.script",
    "destroy.by_design", "pipe.into_interpreter",
    "redirect.runtime", "redirect.disk_device", "redirect.outside",
    "rm.runtime", "rm.outside", "rm.project_root", "find.delete_outside", "find.delete",
    "dd.runtime", "dd.disk_device", "dd.outside", "dd.overwrite",
    "truncate.outside", "truncate.file", "chmod.recursive_outside", "sed.outside",
    "cp.outside", "mv.outside", "new_item.force_outside",
    "git.runtime", "git.push_force", "git.push_force_with_lease", "git.push_delete",
    "git.reset_hard", "git.clean", "git.branch_delete", "git.rewrite_history",
    "db.destructive", "db.runtime", "db.file",
    "iac.destroy", "k8s.delete", "helm.uninstall", "s3.rm", "s3.rb", "cloud.delete",
    "docker.prune", "secret.read", "secret.send", "link.same_command", "rm.filtered_recurse",
    "tar.outside", "unzip.outside", "rsync.outside", "rsync.delete", "dotnet.outside",
    "device.app_data", "device.wipe", "device.flash", "wsl.unregister",
    "db.reset", "git.discard_changes", "git.stash_drop", "git.stash", "git.alias", "git.config_command", "rm.history", "iac.auto_approve",
    "mirror.delete", "gh.delete", "fetch.then_run", "remote.run",
})
# Where the target sits, never what it is. "project_root" is the project
# directory itself; "unknown" is a path known only at run time.
TARGETS = frozenset({"project", "project_root", "outside", "unknown", "disk_device"})
# An org's own rule: "custom.r<its number on the server>". Not in RULE_IDS,
# which is this guard's own closed set.
CUSTOM_RULE_ID = re.compile(r"custom\.r[0-9]{1,18}")


def rule_id_ok(rule: str) -> bool:
    return rule in RULE_IDS or CUSTOM_RULE_ID.fullmatch(rule) is not None
_TARGET_OF_WHERE = {"inside": "project", "cwd": "project_root",
                    "outside": "outside", "unknown": "unknown"}


def evaluate(command: str, *, cwd: str, home: str, rules: CommandRules,
             unattended: bool = False, known_env: dict[str, str] | None = None) -> Verdict:
    """`known_env`: variables whose value the caller read from the process
    environment (the hook passes TEMP/TMP/TMPDIR). Used only when the line
    itself never assigns them — the same rules as any other variable."""
    judge = _Judge(cwd=cwd, home=home, rules=rules, known_env=dict(known_env or {}))
    try:
        judge.run(command, depth=0)
    except Exception as exc:  # noqa: BLE001 - a guard that crashes must not pass
        judge.flag("ask", "guard.crashed", f"the guard could not read this command ({type(exc).__name__})")
    decision = judge.decision
    escalated = unattended and decision == "ask"
    if escalated:
        decision = "deny"
        judge.reasons.append("nobody is present to approve it")
    return Verdict(decision, tuple(judge.reasons), tuple(judge.findings), escalated, tuple(sorted(set(judge.grep_ends))))


def evaluate_file_tool(tool: str, paths: list[str], *, cwd: str, home: str, rules: CommandRules,
                       unattended: bool = False) -> Verdict:
    """Claude Code's file tools: no shell to read, only the paths they were given."""
    judge = _Judge(cwd=cwd, home=home, rules=rules)
    judge.workdirs = [judge.cwd]
    for path in paths:
        if judge._is_secret(path, glob_matches_dots=True):
            judge.flag("ask", "secret.read", f"`{tool}` reads the secret file `{path}`", judge._where(path))
    decision = judge.decision
    escalated = unattended and decision == "ask"
    if escalated:
        decision = "deny"
        judge.reasons.append("nobody is present to approve it")
    return Verdict(decision, tuple(judge.reasons), tuple(judge.findings), escalated)


# ── words to values ─────────────────────────────────────────────────────────

def _unescape(text: str) -> str:
    """Unquoted word: a backslash keeps the next character literally."""
    return re.sub(r"\\(.)", r"\1", text, flags=re.S)


def _unescape_dq(text: str) -> str:
    """Inside double quotes only these four lose their backslash."""
    return re.sub(r'\\([$`"\\])', r"\1", text)


Env = "dict[str, list[tuple[int, Value]]]"  # name -> [(byte where set, value)]


def _value(node: Node, env: dict | None = None) -> Value:
    text = node.text.decode("utf-8", "replace")
    kind = node.type
    if kind in ("word", "number"):
        return _unescape(text)
    if kind == "raw_string":
        return text[1:-1]
    if kind == "string":
        parts = []
        for child in node.named_children:
            if child.type == "string_content":
                parts.append(_unescape_dq(child.text.decode("utf-8", "replace")))
            else:
                part = _value(child, env)
                if part is None:
                    return None
                parts.append(part)
        return "".join(parts)
    if kind == "concatenation":
        parts = [_value(c, env) for c in node.children]
        return None if any(p is None for p in parts) else "".join(parts)
    if kind in ("simple_expansion", "expansion"):
        return _lookup(node, env)
    return None  # substitutions, $'..', arithmetic, anything new


def _plain_variable(node: Node) -> str | None:
    """`$X` or `${X}` — not `${X:-…}`, `${#X}` or any other operator form."""
    named = node.named_children
    if len(named) != 1 or named[0].type != "variable_name":
        return None
    if node.type == "expansion" and node.child_count != 3:
        return None
    return named[0].text.decode()


def _lookup(node: Node, env: dict | None) -> Value:
    """The value set straight-line before this point, else unknown."""
    name = _plain_variable(node)
    if name is None or not env or name not in env:
        return None
    use = node.start_byte
    earlier = [(v, span) for at, v, span in env[name] if at < use]
    if not earlier:
        return None
    value, span = earlier[-1]
    if span is not None and not (span[0] <= use < span[1]):
        return None  # set inside an && chain that has ended: may not have run
    return value


def _posix(path: str) -> str:
    """Git Bash form for a Windows path: C:\\x or C:/x -> /c/x."""
    if re.match(r"^[A-Za-z]:[\\/]", path) or re.fullmatch(r"[A-Za-z]:", path):
        return "/" + path[0].lower() + path[2:].replace("\\", "/")
    return path


def _custom_match(rule: CustomRule, args: list[Value]) -> Optional[bool]:
    """True: matches. False: cannot match. None: matches only if an unknown
    value turns out to be the missing word or flag."""
    positional = _positional(args)
    sure = _in_order(rule.args, positional, unknown_fits=False)
    if not sure and not _in_order(rule.args, positional, unknown_fits=True):
        return False
    if rule.flags and not any(a is not None and any(a == f or a.startswith(f + "=") for f in rule.flags)
                              for a in args):
        if not any(a is None for a in args):
            return False
        sure = False
    return True if sure else None


def _in_order(words: tuple[str, ...], args: list[Value], *, unknown_fits: bool) -> bool:
    """`words` appear in `args` in this order, other args allowed between
    (`kubectl -n prod delete pod`: `prod` is an option's value)."""
    i = 0
    for a in args:
        if i == len(words):
            break
        if a == words[i] or (a is None and unknown_fits):
            i += 1
    return i == len(words)


def _short_flags(args: list[Value]) -> set[str]:
    out: set[str] = set()
    for a in args:
        if a and a.startswith("-") and not a.startswith("--"):
            out.update(a[1:])
    return out


# ── the judge ───────────────────────────────────────────────────────────────

@dataclass
class _Judge:
    cwd: str
    home: str
    rules: CommandRules
    decision: Optional[str] = None
    reasons: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    workdirs: list[Optional[str]] = field(default_factory=list)
    env: dict = field(default_factory=dict)
    known_env: dict = field(default_factory=dict)
    made_links: list[str] = field(default_factory=list)  # by this same command: not on disk yet
    reals: dict = field(default_factory=dict)
    grep_ends: list[int] = field(default_factory=list)
    fetched: list = field(default_factory=list)  # [(keys of a file this line downloaded, the name shown)]
    fetch_said: set = field(default_factory=set)
    fetch_looks: int = 0
    # What the command being judged reads on stdin, for `_remote`: (how, the text if known),
    # how = "pipe" (another command's output) or "fed" (heredoc / herestring), or None.
    stdin_now: tuple = (None, None)
    stdin_base: tuple = (None, None)  # what a command with no stdin of its own reads (a remote line's)
    stdin_local: bool = False  # inside `bash -c '…'` here: stdin_base is this shell's stdin, read here too
    piped: set = field(default_factory=set)  # ids of the commands on this line that read a pipe

    def __post_init__(self) -> None:
        self._windows = bool(re.match(r"^([A-Za-z]:|\\\\)", self.cwd))
        if self._windows:
            self.cwd = self.cwd.replace("\\", "/")
        self.cwd = posixpath.normpath(_posix(self.cwd))
        self.home = posixpath.normpath(_posix(self.home))

    def flag(self, level: str, rule: str, reason: str, target: Optional[str] = None) -> None:
        if rule not in RULE_IDS:
            raise ValueError(f"unregistered rule id {rule!r}")
        self._record(level, rule, reason, target)

    def flag_custom(self, level: str, rule: CustomRule, reason: str) -> None:
        self._record(level, f"custom.{rule.id}", reason, None)

    def _record(self, level: str, rule: str, reason: str, target: Optional[str]) -> None:
        if not rule_id_ok(rule):
            raise ValueError(f"unregistered rule id {rule!r}")
        if target is not None:
            target = _TARGET_OF_WHERE.get(target, target)
            if target not in TARGETS:
                raise ValueError(f"unregistered target class {target!r}")
        if _LEVEL[level] > _LEVEL[self.decision]:
            self.decision = level
        self.reasons.append(reason)
        self.findings.append(Finding(rule, level, target))

    # entry ──────────────────────────────────────────────────────────────
    def run(self, text: str, depth: int) -> None:
        if depth > _MAX_DEPTH:
            self.flag("ask", "parse.too_deep", "commands nested too deep to read")
            return
        tree = _PARSER.parse(text.encode("utf-8"))
        root = tree.root_node
        if root.has_error:
            self.flag("ask", "parse.unreadable", "the shell syntax could not be read")
        outer = (self.env, self.workdirs, self.piped)
        self.env = self._collect_env(root)
        self._collect_workdirs(root, depth)
        self.piped = _piped_commands(root)
        try:
            for node in _walk(root):
                if node.type == "command":
                    self._command(node, depth)
                elif node.type == "file_redirect":
                    self._redirect(node)
                elif node.type == "pipeline":
                    self._pipeline(node)
        finally:
            self.env, self.workdirs, self.piped = outer

    # variables ──────────────────────────────────────────────────────────
    def _collect_env(self, root: Node) -> dict:
        """Values assigned straight-line at the top level of this line.

        Only an assignment that certainly ran before the use, in this shell,
        counts: a top-level `X=…` or `export X=…`. Anything that might not
        run, runs in a subshell, or could reassign unseen leaves the name
        unknown — the bypass shapes are listed in the tests.
        """
        poisoned: set[str] = set()
        for node in _walk(root):
            kind = node.type
            if kind == "variable_assignment":
                name = node.child_by_field_name("name")
                ops = {c.type for c in node.children if not c.is_named}
                if name is not None and name.type == "subscript":
                    poisoned.update(c.text.decode() for c in name.named_children[:1])  # `X[0]=…` sets X
                elif name is not None and name.text == b"IFS":
                    return {}  # words are split differently from here on
                elif name is not None and (not _straight_line(node)[0] or "+=" in ops):
                    poisoned.add(name.text.decode())
            elif kind == "unset_command":
                return {}  # its own node type, not a `command` (found by the suite)
            elif kind in ("for_statement", "c_style_for_statement"):
                var = node.child_by_field_name("variable")
                if var is not None:
                    poisoned.add(var.text.decode())
            elif kind == "expansion" and _plain_variable(node) is None:
                poisoned.update(c.text.decode() for c in node.named_children
                                if c.type == "variable_name")
            elif kind in ("binary_expression", "unary_expression", "postfix_expression",
                          "arithmetic_expansion"):
                poisoned.update(c.text.decode() for c in _walk(node) if c.type == "variable_name")
            elif kind == "declaration_command" and node.children and node.children[0].type != "export":
                poisoned.update(c.text.decode() for c in _walk(node) if c.type == "variable_name")
            elif kind == "command":
                name_node = node.child_by_field_name("name")
                word = _value(name_node.named_children[0]) if name_node is not None and name_node.named_children else ""
                if word in ("command", "builtin"):  # `command read X` is `read X`
                    rest = [_value(a) for a in node.children_by_field_name("argument")]
                    word = next((a for a in rest if a is None or not a.startswith("-")), "")
                if word is None or word in _REASSIGNS:
                    return {}  # eval, read, source …: any name may change unseen

        env: dict = {"HOME": [(-1, self.home, None)]}
        for name, value in self.known_env.items():
            env[name] = [(-1, value, None)]
        for node in _walk(root):
            if node.type != "variable_assignment":
                continue
            holds, scope = _straight_line(node)
            if not holds:
                continue
            name = node.child_by_field_name("name").text.decode()
            if name in poisoned:
                continue
            value_node = node.child_by_field_name("value")
            value = "" if value_node is None else _value(value_node, env)
            span = None if scope is None else (scope.start_byte, scope.end_byte)
            env.setdefault(name, []).append((node.start_byte, value, span))
        for name in poisoned:
            env.pop(name, None)
        return env

    # stdin ──────────────────────────────────────────────────────────────
    def _stdin(self, node: Node) -> tuple[bool, Value]:
        """(fed by heredoc / herestring, the text if it is known)."""
        redirects = list(node.children_by_field_name("redirect"))
        if node.parent is not None and node.parent.type == "redirected_statement":
            redirects += node.parent.children_by_field_name("redirect")
        for r in redirects:
            if r.type == "herestring_redirect":
                arg = r.named_children[-1] if r.named_children else None
                return True, (None if arg is None else _value(arg, self.env))
            if r.type == "heredoc_redirect":
                body = next((c for c in r.named_children if c.type == "heredoc_body"), None)
                if body is None:
                    return True, ""
                if any(c.type != "heredoc_content" for c in body.named_children):
                    return True, None
                return True, body.text.decode("utf-8", "replace")
        return False, None

    def _stdin_is_output(self, node: Node) -> bool:
        """`bash < <(curl …)`: stdin is another command's output, as through a pipe."""
        redirects = list(node.children_by_field_name("redirect"))
        if node.parent is not None and node.parent.type == "redirected_statement":
            redirects += node.parent.children_by_field_name("redirect")
        for r in redirects:
            op = "".join(c.text.decode() for c in r.children if not c.is_named)
            source = r.child_by_field_name("destination")
            descriptor = r.child_by_field_name("descriptor")
            if (r.type == "file_redirect" and op == "<" and source is not None
                    and source.type == "process_substitution"
                    and (descriptor is None or descriptor.text == b"0")):
                return True
        return False

    def _stdin_from_file(self, node: Node) -> bool:
        """`bash < a.sh`: this command's stdin is a file of its own."""
        redirects = list(node.children_by_field_name("redirect"))
        if node.parent is not None and node.parent.type == "redirected_statement":
            redirects += node.parent.children_by_field_name("redirect")
        for r in redirects:
            op = "".join(c.text.decode() for c in r.children if not c.is_named)
            descriptor = r.child_by_field_name("descriptor")
            if r.type == "file_redirect" and op in ("<", "<>", "<&") and (
                    descriptor is None or descriptor.text == b"0"):
                return True
        return False

    def _scan_code(self, name: str, code: str) -> None:
        for text in secret_files.literals_in_code(code):
            if self._is_secret(text):
                self.flag("ask", "secret.read", f"`{name}` code names the secret file `{text}`", self._where(text))
                break
        patterns = self.rules.inline_code_risky.get(name)
        if patterns is None:
            self.flag("ask", "code.inline_unknown_language", f"`{name}` runs inline code this guard has no rules for")
            return
        for pattern in patterns:
            if re.search(pattern, code):
                self.flag("ask", "code.inline_risky", f"`{name}` code deletes files, runs other programs or rewrites data")
                return

    # paths ──────────────────────────────────────────────────────────────
    def _collect_workdirs(self, root: Node, depth: int = 0) -> None:
        """`cd` moves where relative paths point. Order is not tracked, so a
        relative path is judged against every directory the line may be in.
        Code nested in `bash -c` or `eval` starts where the line around it is."""
        self.workdirs = list(dict.fromkeys(self.workdirs)) if depth and self.workdirs else [self.cwd]
        for node in _walk(root):
            if node.type != "command":
                continue
            name, args = self._name_args(node)
            if name in ("cd", "pushd"):
                if not args:
                    self.workdirs.append(self.home)
                else:
                    target = args[-1]
                    if target is None or re.search(r"[*?\[]", target):
                        self.workdirs.append(None)
                    else:
                        self.workdirs += [self._absolute(target, self.cwd),
                                          self._absolute(target, self.workdirs[-1] or self.cwd)]

    def _joined(self, target: str, base: str) -> str:
        if target == "~" or target.startswith("~/"):
            target = self.home + target[1:]
        target = _posix(target)
        if self._windows:
            target = target.replace("\\", "/")
        if not target.startswith("/"):
            target = posixpath.join(base, target)
        return target

    def _absolute(self, target: str, base: str) -> str:
        return posixpath.normpath(self._joined(target, base))

    def _fold(self, path: str) -> str:
        return path.lower() if self._windows else path

    def _real(self, path: str) -> str:
        if path not in self.reals:
            self.reals[path] = self._on_disk(path)
        return self.reals[path]

    def _on_disk(self, path: str) -> str:
        """Where the path is on disk, in the same form as `self.cwd`. A part
        that does not exist yet stays as written."""
        if path.endswith("/.."):
            path += "/"
        while "/../" in path:  # realpath on Windows drops `x/..` before it looks at x; a shell goes through x
            head, _, tail = path.partition("/../")
            path = posixpath.join(posixpath.dirname(self._real(head)), tail)
        return _posix(os.path.realpath(self._native(path)).replace(os.sep, "/"))

    def _native(self, path: str) -> str:
        if self._windows and re.match(r"^/[a-zA-Z](/|$)", path):
            return path[1].upper() + ":" + (path[2:] or "/")
        return path

    def _lands(self, target: str, base: str, keep_last: bool) -> str:
        """Where the path is once links are followed: a link on the way can
        take a path that reads as inside out of the project, or back to the
        project itself. Not normalized first: `link/..` is the parent of where
        the link points, not the project."""
        path = self._joined(target, base)
        head, tail = posixpath.split(path.rstrip("/"))
        if keep_last and tail not in (".", ".."):
            real = posixpath.join(self._real(head), tail)
        else:
            real = self._real(path)
        return self._relation(real, on_disk=True)

    def _where(self, target: Value, removes_link: bool = False) -> str:
        """'unknown', 'outside', 'cwd' (the project itself) or 'inside'.
        `removes_link`: the command removes a link it is given, not what the
        link points to, unless a slash or a glob goes through it. Measured on
        GNU rm, Git Bash rm and Windows PowerShell Remove-Item."""
        if target is None:
            return "unknown"
        if self._windows:
            target = target.replace("\\", "/")
        keep_last = removes_link and not re.search(r"[*?\[]", target) and not target.endswith("/")
        if target.startswith("~") and not (target == "~" or target.startswith("~/")):
            return "outside"  # ~user
        glob = re.search(r"[*?\[]", target)
        through_glob = None
        if glob:
            if "/" in target[glob.start():]:
                through_glob = target  # `own/*/` goes into what matches, so a matching link counts
            prefix = target[:glob.start()]
            target = prefix[: prefix.rfind("/") + 1] if "/" in prefix else ""
            target = target or "."
        worst = "inside"
        order = {"inside": 0, "cwd": 1, "outside": 2, "unknown": 3}
        for base in self.workdirs:
            if base is None and not (target.startswith("/") or target.startswith("~")
                                     or _posix(target) != target):
                where = "unknown"
            else:
                path = self._absolute(target, base or self.cwd)
                where = self._relation(path)
                if where != "outside":
                    lands = self._lands(target, base or self.cwd, keep_last)
                    if order[lands] > order[where]:
                        where = lands
                if where != "outside" and through_glob:
                    pattern = self._native(self._joined(through_glob, glob_escape(base or self.cwd)))
                    if any(self._lands(m, base or self.cwd, False) == "outside"
                           for m in islice(iglob(pattern), 1000)):
                        where = "outside"
                folded = self._fold(path)
                if any(folded == self._fold(m) and not keep_last or folded.startswith(self._fold(m) + "/")
                       for m in self.made_links):
                    self.flag("ask", "link.same_command", f"`{target}` goes through a link this command makes", "unknown")
            if order[where] > order[worst]:
                worst = where
        return worst

    def _relation(self, path: str, on_disk: bool = False) -> str:
        cwd = self.cwd
        scratch = [self._absolute(d, self.cwd) for d in self.rules.scratch_dirs]
        if on_disk:
            cwd = self._real(cwd)
            scratch = [self._real(d) for d in scratch]
        if self._windows:
            path, cwd = path.lower(), cwd.lower()
            scratch = [d.lower() for d in scratch]
        if path == cwd:
            return "cwd"
        if path.startswith(cwd.rstrip("/") + "/"):
            return "inside"
        # Inside a temp root is as safe as inside the project; the root
        # itself is not (wiping /tmp takes everyone's files with it). A `*`
        # stands for one directory name.
        if any(re.match(re.escape(d.rstrip("/")).replace(r"\*", "[^/]+") + "/.", path) for d in scratch):
            return "inside"
        return "outside"

    # secret files ───────────────────────────────────────────────────────
    def _is_secret(self, target: str, glob_matches_dots: bool = False) -> bool:
        return any(secret_files.is_secret(target if base is None else self._absolute(target, base),
                                          glob_matches_dots=glob_matches_dots)
                   for base in self.workdirs or [self.cwd])

    def _named_secrets(self, name: str, args: list[Value]) -> list[str]:
        """The secret files this command is given to read or send. Any command
        reads what it is given unless it is known not to show the file: a list
        of readers is what `xxd .env` walks past."""
        lowered = name.lower()
        if lowered in secret_files.SENDERS:
            return [p for p in secret_files.sent_paths(lowered, args) if self._is_secret(p)]
        if lowered in secret_files.METADATA_ONLY or lowered in secret_files.USES_WITHOUT_SHOWING:
            return []
        if lowered == "git" and secret_files.git_subcommand(args) not in secret_files.GIT_SHOWS:
            return []
        skip = secret_files.flag_values_to_skip(lowered, args)
        code = self.rules.code_flags.get(name, ())
        skip |= {i + 1 for i, a in enumerate(args) if a in code}
        found = _code_on_line(name, args, self.rules)
        if found is not None and found[1] is not None and found[1] in args[found[0] + 1:]:
            skip.add(args.index(found[1], found[0] + 1))
        rest = [a for i, a in enumerate(args) if i not in skip]
        if secret_files.pattern_is_first(lowered, args):
            operands = _operands(rest)
            if operands and operands[0] in rest:
                rest.remove(operands[0])
        if lowered in secret_files.COPIERS:
            operands = _operands(rest)
            if len(operands) >= 2 and operands[-1] in rest:
                rest.reverse()
                rest.remove(operands[-1])
                rest.reverse()
        if lowered == "git":
            rest = [a.rsplit(":", 1)[-1] if a else a for a in rest]  # `git show HEAD:.env`
        out = []
        for a in rest:
            path = None if a is None else secret_files.path_in_argument(a)
            if path is not None and self._is_secret(path):
                out.append(path)
        return out

    def _final(self, name: Value, args: list[Value]) -> tuple[Value, list[Value]]:
        """The command behind `sudo`, `env`, `timeout` and the like."""
        r = self.rules
        while name is not None and (name in r.wrappers or name in r.privilege):
            rest = _unwrap(name, args)
            if not rest:
                break
            name, args = rest[0], rest[1:]
        return name, args

    def _sends(self, node: Node) -> bool:
        """A sender anywhere inside this part of the line."""
        for n in _walk(node):
            if n.type == "command":
                name = self._final(*self._name_args(n))[0]
                if name and name.lower() in secret_files.SENDERS:
                    return True
        return False

    def _flag_secret(self, name: str, path: str) -> None:
        if name.lower() in secret_files.SENDERS:
            self.flag("deny", "secret.send", f"`{name}` sends the secret file `{path}` out", self._where(path))
        else:
            self.flag("ask", "secret.read", f"`{name}` reads the secret file `{path}`", self._where(path))

    def _secret_args(self, name: str, args: list[Value]) -> None:
        for path in self._named_secrets(name, args):
            self._flag_secret(name, path)

    # commands ───────────────────────────────────────────────────────────
    def _name_args(self, node: Node) -> tuple[Value, list[Value]]:
        name_node = node.child_by_field_name("name")
        if name_node is None:
            return "", []
        inner = name_node.named_children[0] if name_node.named_children else name_node
        name = _value(inner, self.env)
        extra: list[Value] = []
        if name is not None and inner.type not in ("string", "raw_string"):
            name, *extra = _braces(name)
        if name is not None:
            name = posixpath.basename(name.replace("\\", "/"))
            if name.lower().endswith(".exe"):
                name = name[:-4]
        args = extra
        for a in node.children_by_field_name("argument"):
            value = _value(a, self.env)
            unquoted = a.type == "concatenation" and any(c.type == "word" and b"{" in c.text for c in a.children)
            args.extend(_braces(value) if value is not None and unquoted else [value])
        return name, args

    def _command(self, node: Node, depth: int) -> None:
        name, args = self._name_args(node)
        if name == "":
            return  # a bare assignment
        if name is None:
            self.flag("ask", "name.runtime", "the command name is only known at run time")
            return
        fed, text = self._stdin(node)
        try:
            self._fetch_command(node, name, args)
        except Exception:  # noqa: BLE001 - it only adds an ask; the judgement below does not wait on it
            pass
        outer_stdin = self.stdin_now
        substituted = not fed and self._stdin_is_output(node)
        if substituted:
            first, rest = self._final(name, args)
            if first in self.rules.interpreters and not _code_or_file(first, rest, self.rules):
                self.flag("ask", "pipe.into_interpreter", f"output of another command is run as `{first}` code")
        piped = node.id in self.piped or substituted
        if self.stdin_local and not fed and not piped and not self._stdin_from_file(node):
            how, base_text = self.stdin_base
            if how == "fed":
                fed, text = True, base_text
            elif how == "pipe":
                first, rest = self._final(name, args)
                if first in self.rules.interpreters and not _code_or_file(first, rest, self.rules):
                    self.flag("ask", "pipe.into_interpreter", f"output of another command is run as `{first}` code")
        self.stdin_now = ("fed", text) if fed else ("pipe", None) if piped else self.stdin_base
        try:
            self._judge(name, args, depth, stdin_fed=fed, stdin_text=text)
        finally:
            self.stdin_now = outer_stdin
        grep = posixpath.basename(name).lower()
        if depth == 0 and grep in secret_files.GREPS:
            recursive, paths, includes = secret_files.grep_reads(args)
            if grep == "rgrep" or recursive:
                start = secret_files.grep_folder(paths, self.workdirs)
                if start is not None:
                    self.flag("ask", "secret.read", f"`{name}` reads the secret file `{start}`", self._where(start))
                elif not secret_files.grep_must_stay(args, paths, includes):
                    self.grep_ends.append(node.child_by_field_name("name").end_byte)
        final = self._final(name, args)[0]
        if final and final.lower() in secret_files.SENDERS:
            for n in _walk(node):  # `curl -d "$(cat .env)"`
                if n.type == "command" and n.id != node.id and self._named_secrets(*self._name_args(n)):
                    self.flag("deny", "secret.send", f"`{final}` sends what a secret file holds out")
                    break

    def _judge(self, name: Value, args: list[Value], depth: int, *,
               stdin_fed: bool = False, stdin_text: Value = None) -> None:
        r = self.rules
        if name is None:
            self.flag("ask", "name.runtime", "the command name is only known at run time")
            return
        if r.custom:
            self._custom(name, args)

        if name in r.privilege:
            self.flag("ask", "privilege.elevated", f"`{name}` runs a command with more rights")
            if name == "su":
                if "-c" in args:
                    i = args.index("-c")
                    code = args[i + 1] if i + 1 < len(args) else None
                    if code is None:
                        self.flag("ask", "privilege.su_runtime", "`su -c` runs text known only at run time")
                    else:
                        self.run(code, depth + 1)
                return
            rest = _strip_options(args, takes_value={"-u", "-g", "-U", "-C", "-h", "-p"})
            if rest:
                self._judge(rest[0], rest[1:], depth)
            return

        if name in r.wrappers:
            rest = _unwrap(name, args)
            if name == "env":
                self._env(args, rest, depth, stdin_fed, stdin_text)
                return
            if name == "xargs":
                self.stdin_now = (None, None)  # what it runs reads /dev/null
                if rest:
                    self._judge(rest[0], rest[1:] + [None], depth)
                return
            if rest:
                self._judge(rest[0], rest[1:], depth, stdin_fed=stdin_fed, stdin_text=stdin_text)
            return

        if name == "eval":
            if any(a is None for a in args):
                self.flag("ask", "eval.runtime", "`eval` runs text known only at run time")
            elif args:
                self.run(" ".join(args), depth + 1)
            return

        if name in r.source:
            self.flag("ask", "source.script", f"`{name}` runs a script file in this shell")
            return

        self._secret_args(name, args)

        if name in _DB_RESET_NAMES:
            line = " ".join([name] + ["?" if a is None else a for a in args])
            if any(re.search(p, line) for p in _DB_RESETS):
                self.flag("ask", "db.reset", f"`{name}` resets or drops a database")

        if name in r.code_flags:
            found = _code_on_line(name, args, r)
            if found is not None:
                code = found[1]
                if code is None:
                    self.flag("ask", "code.runtime", f"`{name}` runs code known only at run time")
                elif name in r.shells:
                    # `… | bash -c 'bash -s'`: a command in there with no stdin of its own reads this shell's
                    outer = (self.stdin_base, self.stdin_local)
                    if self.stdin_now[0]:
                        self.stdin_base, self.stdin_local = self.stdin_now, True
                    try:
                        self.run(code, depth + 1)
                    finally:
                        self.stdin_base, self.stdin_local = outer
                else:
                    self._scan_code(name, code)
                return
            if stdin_fed and name in r.interpreters and not _code_or_file(name, args, r):
                if stdin_text is None:
                    self.flag("ask", "code.stdin_runtime", f"text known only at run time is fed into `{name}` as code")
                elif name in r.shells:
                    self.run(stdin_text, depth + 1)
                else:
                    self._scan_code(name, stdin_text)
            return

        if name in r.always_deny or name.startswith(r.always_deny_prefixes):
            self.flag("deny", "destroy.by_design", f"`{name}` destroys data by design")
            return

        handler = _HANDLERS.get(name)
        if handler is not None:
            handler(self, name, args, depth)
        elif name in r.db_clients:
            self._db(name, args)

    def _env(self, args: list[Value], rest: list[Value], depth: int, fed: bool, text: Value) -> None:
        """`env -C dir` moves the one command it runs, so the rest of the line stays."""
        options = args[:len(args) - len(rest)]
        outer = self.workdirs
        for d in _env_dirs(options):
            self.workdirs = [None if d is None else self._absolute(d, base or self.cwd) for base in self.workdirs]
        try:
            split = False
            for i, a in enumerate(options):
                m = re.fullmatch(r"-[iv0]*S(.*)|--split-string(?:=(.*))?", a or "")
                if m:
                    split = True
                    code = m.group(1) or m.group(2) or (options[i + 1] if i + 1 < len(options) else None)
                    if code is None or None in rest:
                        self.flag("ask", "code.runtime", "`env` runs code known only at run time")
                    else:
                        self.run(" ".join([code, *rest]), depth + 1)  # the words after it are its arguments
            if rest and not split:
                self._judge(rest[0], rest[1:], depth, stdin_fed=fed, stdin_text=text)
        finally:
            self.workdirs = outer

    def _custom(self, name: str, args: list[Value]) -> None:
        """The org's rules on this one command. Judged here, so a rule meets
        the command inside sudo, env, xargs, `bash -c` and eval as well. The
        rest of the judgement still runs: a stronger rule of ours still wins."""
        lowered = name.lower()
        for rule in self.rules.custom:
            if rule.command != lowered:
                continue
            match = _custom_match(rule, args)
            if match is False:
                continue
            why = f"team rule {rule.id}" + (f": {rule.note}" if rule.note else f" on `{name}`")
            if match is True:
                self.flag_custom(rule.level, rule, why)
            else:  # it may match once a value known only at run time is filled in
                self.flag_custom("ask", rule, why + " (a value is known only at run time)")

    # redirects and pipes ────────────────────────────────────────────────
    def _redirect(self, node: Node) -> None:
        op = "".join(c.text.decode() for c in node.children if not c.is_named)
        if "<" in op:
            self._redirected_in(node)
            try:
                self._fetched_in(node)
            except Exception:  # noqa: BLE001 - it only adds an ask
                pass
            return
        dest_node = node.child_by_field_name("destination")
        if dest_node is None:
            return
        if "&" in op and dest_node.type == "number":
            return  # 2>&1
        dest = _value(dest_node, self.env)
        self._output(dest)
        try:
            descriptor = node.child_by_field_name("descriptor")
            stdout = descriptor is None or descriptor.text == b"1"  # `>`, `>>`, `&>`, `1>`; not `2>`
            if stdout and self._may_look() and any(posixpath.basename(n or "") in _FETCHERS for n in self._names_in(_redirect_body(node))):
                self._note_fetched(dest, dest_node.text.decode("utf-8", "replace"))  # `curl … > x.sh`
        except Exception:  # noqa: BLE001 - it only adds an ask
            pass

    def _may_look(self) -> bool:
        """Looking through a part of the line for a download costs time on each redirect and
        each `tee`: a line with thousands of them is not followed past `_LOOKS_MOST`."""
        self.fetch_looks += 1
        return self.fetch_looks <= _LOOKS_MOST

    def _names_in(self, body: Node) -> list[Value]:
        """The command behind each wrapper, for every command in this part of the line."""
        return [self._final(*self._name_args(n))[0] for n in _walk(body) if n.type == "command"]

    # a file this line downloads, then runs ─────────────────────────────────
    def _file_keys(self, value: Value, raw: Optional[str] = None) -> set:
        """What two words must share to be the same file. A value known only at
        run time is the same file only when it is written the same way (`"$f"`)."""
        if value is None:
            raw = re.sub(r"\$\{(\w+)\}", r"$\1", (raw or "").strip().strip('"'))  # `"${F}"` is `"$F"`
            return {("as written", raw)} if "$" in raw or "`" in raw else set()
        if self._windows:
            value = value.replace("\\", "/")
        if value in ("", "-") or value in self.rules.harmless_devices or re.search(r"[*?\[]", value):
            return set()
        keys: set = set()
        for base in islice(dict.fromkeys(self.workdirs or [self.cwd]), _FOLDERS_MOST):
            if base is None and not (value.startswith(("/", "~")) or _posix(value) != value):
                keys.add(("relative", self._fold(posixpath.normpath(value))))
            else:
                keys.add(self._fold(self._absolute(value, base or self.cwd)))
        return keys

    def _note_fetched(self, value: Value, raw: Optional[str] = None) -> None:
        keys = self._file_keys(value, raw) if len(self.fetched) < _FETCHED_MOST else set()
        if keys:
            self.fetched.append((keys, value if value is not None else (raw or "").strip().strip("\"'")))

    def _runs_fetched(self, value: Value, raw: Optional[str] = None) -> None:
        keys = self._file_keys(value, raw) if self.fetched else set()
        for fetched, shown in self.fetched:
            if keys & fetched:
                if shown not in self.fetch_said:  # one command can reach here twice
                    self.fetch_said.add(shown)
                    self.flag("ask", "fetch.then_run", f"`{shown}` is downloaded and then run by this same command")
                return

    def _arg_raws(self, node: Node) -> list[Optional[str]]:
        """The text of each argument as written, one for one with `_name_args`."""
        name_node = node.child_by_field_name("name")
        if name_node is None:
            return []
        inner = name_node.named_children[0] if name_node.named_children else name_node
        name = _value(inner, self.env)
        raws: list[Optional[str]] = []
        if name is not None and inner.type not in ("string", "raw_string"):
            raws += [None] * (len(_braces(name)) - 1)
        for a in node.children_by_field_name("argument"):
            value = _value(a, self.env)
            unquoted = a.type == "concatenation" and any(c.type == "word" and b"{" in c.text for c in a.children)
            count = len(_braces(value)) if value is not None and unquoted else 1
            raws += [a.text.decode("utf-8", "replace")] * count
        return raws

    def _fetch_command(self, node: Node, name: str, args: list[Value]) -> None:
        name_node = node.child_by_field_name("name")
        inner = name_node.named_children[0] if name_node.named_children else name_node
        word = _value(inner, self.env)  # with its folders: `./x.sh`, not `x.sh`
        if word is not None and inner.type not in ("string", "raw_string"):
            word = _braces(word)[0]
        raws: Optional[list] = self._arg_raws(node)
        rest = args
        r = self.rules
        while name is not None and (name in r.wrappers or name in r.privilege):  # as `_judge` goes through them
            if name == "su":
                return  # `su -c` text is judged as its own line
            if name in r.privilege:
                rest = _strip_options(rest, takes_value={"-u", "-g", "-U", "-C", "-h", "-p", "--user", "--group",
                                                         "--other-user", "--chdir", "--host", "--prompt"})
            else:
                rest = _unwrap(name, rest)
            if not rest:
                return
            word = name = rest[0]
            rest = rest[1:]
            if name is not None:
                name = posixpath.basename(name.replace("\\", "/"))
        keep = len(rest)
        raws = raws[len(raws) - keep:] if keep <= len(args) and args[len(args) - keep:] == rest else None
        if name == "tee" and self._may_look() and self._fed_by_a_download(node):  # `curl … | tee x.sh`
            for target in _operands(rest):
                self._note_fetched(target)
        self.fetch_step(word, rest, raws)

    def _fed_by_a_download(self, node: Node) -> bool:
        """An earlier stage of the pipeline this command is in downloads."""
        stage, pipeline = node, node.parent
        while pipeline is not None and pipeline.type != "pipeline":
            if pipeline.type in ("program", "list", "subshell", "compound_statement"):
                return False
            stage, pipeline = pipeline, pipeline.parent
        if pipeline is None:
            return False
        for earlier in pipeline.named_children:
            if earlier.id == stage.id:
                return False
            if any(posixpath.basename(n or "") in _FETCHERS for n in self._names_in(earlier)):
                return True
        return False

    def fetch_step(self, word: Value, args: list[Value], raws: Optional[list] = None, notes: bool = True) -> None:
        """One command: does it run a file an earlier command of this line
        downloaded, and (`notes`) does it download one itself. `word` is the
        command as written, with its folders. This only ever adds an ask: if it
        cannot read the command, the rest of the judgement goes on without it."""
        try:
            self._fetch_step(word, args, raws, notes)
        except Exception:  # noqa: BLE001 - never the reason a line is judged less
            pass

    def _fetch_step(self, word: Value, args: list[Value], raws: Optional[list], notes: bool) -> None:
        if word is None:
            return
        if raws is None or len(raws) != len(args):
            raws = [None] * len(args)
        name = posixpath.basename(word.replace("\\", "/"))
        if name.lower().endswith(".exe"):
            name = name[:-4]
        if self._windows:
            name = name.lower()  # `Python.exe` is `python` there
        name = _INTERPRETER_NAMES.sub(lambda m: m.group(1), name)  # python3.12, pypy3, nodejs
        name = {"py": "python", "nodejs": "node", "pypy": "python"}.get(name, name)
        if self.fetched:
            if (re.search(r"[/\\]", word) or word.startswith("~")) and not _DOCUMENT.search(word):
                self._runs_fetched(word)  # `./x.sh`; a bare name is looked up on PATH, not here
            if name in ("cmd", "pwsh", "powershell"):
                first = _first_word_of_code(name, args)  # `cmd /c x.bat`, `powershell -Command ./x.ps1`
                if first is not None and not _DOCUMENT.search(first):  # `cmd /c start out.html` opens it
                    self._runs_fetched(first)
            if name in self.rules.interpreters and _code_on_line(name, args, self.rules) is None:
                for at in _script_candidates(name, args, self.rules, raws):
                    self._runs_fetched(args[at], raws[at])
        if notes and name in _FETCHERS:
            for at, value in _fetch_outputs(name, args):
                self._note_fetched(args[at] if at is not None else value, raws[at] if at is not None else None)

    def _fetched_in(self, node: Node) -> None:
        """`bash < x.sh`: the file is the code."""
        source = node.child_by_field_name("destination")
        if source is None or not self.fetched:
            return
        first = next((n for n in _walk(_redirect_body(node)) if n.type == "command"), None)
        if first is None:
            return
        name, args = self._final(*self._name_args(first))
        if name in self.rules.shells and any(a and re.fullmatch(r"-[A-Za-z]*n[A-Za-z]*", a) for a in args):
            return  # `bash -n < x.sh` reads it for mistakes
        if name in self.rules.interpreters and not _code_or_file(name, args, self.rules):
            self._runs_fetched(_value(source, self.env), source.text.decode("utf-8", "replace"))

    def _output(self, dest: Value) -> None:
        if dest is None:
            self.flag("ask", "redirect.runtime", "output is written to a path known only at run time", "unknown")
            return
        if dest in self.rules.harmless_devices:
            return
        if dest.startswith(self.rules.devices):
            self.flag("deny", "redirect.disk_device", f"output overwrites the disk device `{dest}`", "disk_device")
            return
        if self._where(dest) == "outside":
            self.flag("ask", "redirect.outside", f"output is written to `{dest}` outside the project", "outside")

    def _redirect_reads_secret(self, node: Node) -> bool:
        source = node.child_by_field_name("destination")
        op = "".join(c.text.decode() for c in node.children if not c.is_named)
        path = None if source is None else _value(source, self.env)
        return "<" in op and path is not None and self._is_secret(path)

    def _find_secret(self, args: list[Value]) -> Value:
        """The secret name `find` is told to look for."""
        for i, a in enumerate(args[:-1]):
            if a in ("-name", "-iname", "-path", "-ipath", "-wholename") and args[i + 1] is not None:
                if self._is_secret(args[i + 1]):
                    return args[i + 1]
        return None

    def _redirected_in(self, node: Node) -> None:
        source = node.child_by_field_name("destination")
        path = None if source is None else _value(source, self.env)
        if path is None or not self._is_secret(path):
            return
        parent = node.parent
        body = parent if parent.type == "command" else parent.child_by_field_name("body") or parent
        names = [self._final(*self._name_args(n))[0] for n in _walk(body) if n.type == "command"]
        if self._sends(body):
            self.flag("deny", "secret.send", f"a secret file `{path}` is fed to a command that sends it out",
                      self._where(path))
        elif not names or any(n is None or n.lower() not in secret_files.METADATA_ONLY for n in names):
            self.flag("ask", "secret.read", f"the secret file `{path}` is read through a redirect", self._where(path))

    def _pipeline(self, node: Node) -> None:
        stages = [c for c in node.named_children]
        fed_a_secret = listed_a_secret = False
        for stage in stages:
            if fed_a_secret and self._sends(stage):
                self.flag("deny", "secret.send", "a secret file is sent out through a pipe")
            for n in _walk(stage):
                if n.type != "command":
                    continue
                name, args = self._name_args(n)
                if name is None:
                    continue
                if listed_a_secret and name == "xargs":
                    self.flag("ask", "secret.read", "`xargs` is handed a secret file `find` listed")
                listed_a_secret = listed_a_secret or (name == "find" and self._find_secret(args) is not None)
                fed_a_secret = fed_a_secret or bool(self._named_secrets(name, args))
            redirects = [n for n in _walk(stage) if n.type == "file_redirect"]
            fed_a_secret = fed_a_secret or any(self._redirect_reads_secret(n) for n in redirects)
        # After a heredoc start (`cat <<EOF | bash`) the grammar puts what
        # follows the `|` in a pipeline of its own: its first stage is fed too.
        fed = stages if node.parent is not None and node.parent.type == "heredoc_redirect" else stages[1:]
        for stage in fed:
            command = stage if stage.type == "command" else next(
                (c for c in stage.named_children if c.type == "command"), None)
            if command is None:
                continue
            name, args = self._final(*self._name_args(command))
            if name in self.rules.interpreters and not _code_or_file(name, args, self.rules):
                self.flag("ask", "pipe.into_interpreter", f"output of another command is run as `{name}` code")

    # handlers ───────────────────────────────────────────────────────────
    def _rm(self, name: str, args: list[Value], depth: int) -> None:
        flags = _short_flags(args)
        recursive = bool(flags & {"r", "R"}) or "--recursive" in args
        force = "f" in flags or "--force" in args
        for target in _operands(args):
            where = self._where(target, removes_link=True)
            if where == "unknown":
                self.flag("deny" if (recursive or force) else "ask", "rm.runtime",
                          "`rm` target is known only at run time", "unknown")
            elif where == "outside":
                self.flag("deny" if (recursive or force) else "ask", "rm.outside",
                          f"`rm` reaches outside the project: `{target}`", "outside")
            elif where == "cwd" and (recursive or force):
                self.flag("ask", "rm.project_root", "`rm` removes the whole project directory", "project_root")
            elif recursive and target is not None and _HISTORY.search(target.replace("\\", "/")):
                # Inside the project, but not rebuilt by any install: history, or a
                # worktree holding uncommitted work (#70687, #75861).
                self.flag("ask", "rm.history", f"`rm` removes `{target}`, which no build makes again", where)

    def _ln(self, name: str, args: list[Value], depth: int) -> None:
        operands = _operands(args)
        if not operands or not ("s" in _short_flags(args) or "--symbolic" in args):
            return
        made = operands[-1]
        if made is None:
            self.flag("ask", "link.same_command", "`ln -s` makes a link whose name is known only at run time", "unknown")
        else:
            made = made.rstrip("/") or "/"
            made = made if len(operands) >= 2 else posixpath.basename(made)
            self.made_links.extend(self._absolute(made, base or self.cwd) for base in self.workdirs)

    def _find(self, name: str, args: list[Value], depth: int) -> None:
        roots: list[Value] = []
        lead = next((i for i, a in enumerate(args) if a not in ("-H", "-L", "-P")), len(args))
        follows = "-L" in args[:lead] or "-H" in args[:lead] or "-follow" in args
        for a in args[lead:]:
            if a is not None and (a.startswith("-") or a in ("(", "!")):
                break
            roots.append(a)
        roots = roots or ["."]
        if "-delete" in args:
            for root in roots:
                where = self._where(root)
                if where in ("unknown", "outside"):
                    self.flag("deny", "find.delete_outside", f"`find -delete` under `{root}`", where)
                else:
                    self.flag("ask", "find.delete", "`find -delete` removes files in bulk", where)
        for i, a in enumerate(args):
            if a in ("-exec", "-execdir", "-ok", "-okdir"):
                end = next((j for j in range(i + 1, len(args)) if args[j] in (";", "+")), len(args))
                sub = args[i + 1:end]
                if not sub:
                    continue
                found = self._find_secret(args)
                for root in roots:
                    each = found or root
                    if follows and each is not None:
                        each = each.rstrip("/") + "/"  # what `-L` reaches is behind the link
                    filled = [each if s == "{}" else
                              s.replace("{}", each) if s is not None and each is not None else
                              None if s is not None and "{}" in s else s for s in sub]
                    self._judge(filled[0], filled[1:], depth)

    def _dd(self, name: str, args: list[Value], depth: int) -> None:
        for a in args:
            if a is None:
                self.flag("ask", "dd.runtime", "`dd` operand known only at run time", "unknown")
            elif a.startswith("of="):
                out = a[3:]
                if out.startswith(self.rules.devices):
                    self.flag("deny", "dd.disk_device", f"`dd` writes over the disk device `{out}`", "disk_device")
                elif (where := self._where(out)) in ("outside", "unknown"):
                    self.flag("deny", "dd.outside", f"`dd` writes outside the project: `{out}`", where)
                else:
                    self.flag("ask", "dd.overwrite", "`dd` overwrites a file", where)

    def _truncate(self, name: str, args: list[Value], depth: int) -> None:
        for target in _operands(args, takes_value={"-s", "-r", "--size", "--reference"}):
            where = self._where(target)
            if where in ("outside", "unknown"):
                self.flag("deny", "truncate.outside", f"`truncate` empties a file outside the project: `{target}`", where)
            else:
                self.flag("ask", "truncate.file", "`truncate` empties a file", where)

    def _chmod(self, name: str, args: list[Value], depth: int) -> None:
        if not ({"R"} & _short_flags(args) or "--recursive" in args):
            return
        operands = _operands(args)
        for target in operands[1:]:  # the first operand is the mode / owner
            if (where := self._where(target)) in ("outside", "unknown"):
                self.flag("deny", "chmod.recursive_outside", f"`{name} -R` changes everything under `{target}`", where)

    def _sed(self, name: str, args: list[Value], depth: int) -> None:
        in_place = any(a is not None and (a.startswith("-i") or a.startswith("--in-place")) for a in args)
        if not in_place:
            return
        operands = _operands(args, takes_value={"-e", "-f", "--expression", "--file"})
        has_script_flag = any(a in ("-e", "-f", "--expression", "--file") for a in args)
        files = operands if has_script_flag else operands[1:]
        for target in files:
            if (where := self._where(target)) in ("outside", "unknown"):
                self.flag("ask", "sed.outside", f"`sed -i` edits `{target}` outside the project", where)

    def _cp_mv(self, name: str, args: list[Value], depth: int) -> None:
        """A copy or move onto a path outside the project replaces the file
        there and keeps no copy, the same as `>` onto it. `mv` also takes each
        source away from where it was, so a source outside counts too."""
        target_dir: Value = None
        has_target_dir = False
        # install's `-g bin`, `-gbin`: letters of a value are no options
        own = [a for a in args if name != "install" or not (a and re.match(r"-[gomS]", a))]
        flags = _short_flags([a for a in own if not (a and re.match(r"-[A-Za-z]*t.", a))])
        bundled = {a for a in own if a and re.fullmatch(r"-[A-Za-z]+t", a)}  # `-rt dir`
        for i, a in enumerate(args):
            if a in ("-t", "--target-directory") or a in bundled:
                has_target_dir = True
                target_dir = args[i + 1] if i + 1 < len(args) else None
            elif a is not None and a.startswith("--target-directory="):
                has_target_dir = True
                target_dir = a.split("=", 1)[1]
            elif a in own and a is not None and (m := re.fullmatch(r"-[A-Za-z]*t(.+)", a)):
                has_target_dir = True
                target_dir = m.group(1)
        if name == "install" and "d" in flags:
            return  # makes directories, replaces nothing
        values = {"-m", "--mode", "-o", "--owner", "-g", "--group"} if name == "install" else set()
        operands = _operands(args, takes_value={"-t", "--target-directory", "-S", "--suffix"} | values | bundled)
        if has_target_dir:
            dests, sources = [target_dir], operands
        elif len(operands) >= 2:
            dests, sources = operands[-1:], operands[:-1]
        else:
            return
        keeps_old = bool(flags & {"n", "b"}) or any(
            a is not None and (a in ("--no-clobber", "--update=none") or a.startswith("--backup"))
            for a in args)
        if not keeps_old:
            for dest in dests:
                where = self._where(dest)
                if where not in ("outside", "unknown"):
                    continue
                said = "a path known only at run time" if dest is None else f"`{dest}` outside the project"
                if name != "mv":
                    self.flag("ask", "cp.outside", f"`{name}` writes over {said}", where)
                else:
                    self.flag("ask", "mv.outside", f"`mv` writes over {said}", where)
        if name == "mv":
            for source in sources:
                if (where := self._where(source, removes_link=True)) in ("outside", "unknown"):
                    said = "a path known only at run time" if source is None else f"`{source}` outside the project"
                    self.flag("ask", "mv.outside", f"`mv` takes away {said}", where)

    def _tee(self, name: str, args: list[Value], depth: int) -> None:
        for dest in _operands(args):
            self._output(dest)

    def _tar(self, name: str, args: list[Value], depth: int) -> None:
        short = _tar_short(args)
        letters = {letter for letter, _ in short}
        dests: list[Value] = []
        if "x" in letters or "--extract" in args or "--get" in args:
            dests = [v for letter, v in short if letter == "C"] + _option_values(
                args, ("--directory", "--dir", "--one-top-level"))
            dests = [v and v.rstrip("/") + "/x" for v in dests or ["."]]
        elif letters & {"c", "r", "u", "A"} or {"--create", "--append", "--update"} & set(args):
            dests = [v for letter, v in short if letter == "f"] + _option_values(args, ("--file",))
        for dest in dests:
            if dest != "-" and (where := self._where(dest)) in ("outside", "unknown"):
                said = "a path known only at run time" if dest is None else f"`{dest}` outside the project"
                self.flag("ask", "tar.outside", f"`tar` writes over {said}", where)

    def _unzip(self, name: str, args: list[Value], depth: int) -> None:
        dests: list[Value] = []
        for i, a in enumerate(args):
            if a is not None and (m := re.fullmatch(r"-[A-Za-z]*?d(.*)", a)):
                dests.append(m.group(1) or (args[i + 1] if i + 1 < len(args) else None))
        if not dests and any(a and re.fullmatch(r"-[a-ce-zA-Z]*[ltpvZ][a-ce-zA-Z]*", a) for a in args):
            return  # lists or tests, writes nothing
        for dest in [v and v.rstrip("/") + "/x" for v in dests or ["."]]:
            if (where := self._where(dest)) in ("outside", "unknown"):
                said = "a path known only at run time" if dest is None else f"`{dest}` outside the project"
                self.flag("ask", "unzip.outside", f"`unzip` writes over {said}", where)

    def _rsync(self, name: str, args: list[Value], depth: int) -> None:
        """`--delete` empties the destination of what the source lacks, so outside
        the project it is `rm -rf`. A remote destination cannot be looked at."""
        operands = _operands(args, takes_value=_RSYNC_VALUES)
        dry = "--dry-run" in args or any(a and re.fullmatch(r"-(?![efBTM])[A-Za-z]*n[A-Za-z]*", a) for a in args)
        if len(operands) < 2 or dry:
            return
        dest = operands[-1]
        deletes = any(a is not None and (a == "--del" or a.startswith("--delete")) for a in args)
        if "--remove-source-files" in args:
            for source in operands[:-1]:
                if (where := self._where(source)) in ("outside", "unknown"):
                    said = "a path known only at run time" if source is None else f"`{source}` outside the project"
                    self.flag("ask", "rsync.outside", f"`rsync` takes away {said}", where)
        if dest is not None and re.match(r"^(rsync://|[^/\\:]{2,}:)", dest):
            if deletes:
                self.flag("ask", "rsync.delete", f"`rsync --delete` removes files on another machine: `{dest}`")
            return
        where = self._where(dest)
        if where not in ("outside", "unknown"):
            return
        said = "a path known only at run time" if dest is None else f"`{dest}` outside the project"
        if deletes:
            # a run-time destination may be another machine (`deploy@$HOST:/srv`)
            self.flag("deny" if where == "outside" else "ask", "rsync.delete",
                      f"`rsync --delete` removes files under {said}", where)
        else:
            self.flag("ask", "rsync.outside", f"`rsync` writes over {said}", where)

    def _git(self, name: str, args: list[Value], depth: int) -> None:
        i = 0
        # Paths are looked up on disk only from the folder the line starts in.
        base: str | None = self.cwd if set(self.workdirs or [self.cwd]) == {self.cwd} and not (
            "GIT_WORK_TREE" in self.env or "GIT_WORK_TREE" in self.known_env) else None
        configs: list[Value] = []  # `-c key=value`
        while i < len(args):
            a = args[i]
            if a is not None and a.startswith("--work-tree="):
                base = None
            if a is not None and a.startswith("--config-env="):
                # `--config-env=alias.x=VAR`: the key is known, the value is in the environment
                configs.append("\0" + a.partition("=")[2].partition("=")[0])
            if a in ("-C", "-c", "--git-dir", "--work-tree", "--namespace"):
                if a == "-c":
                    configs.append(args[i + 1] if i + 1 < len(args) else "")
                if a == "--work-tree":
                    base = None
                if a == "-C":
                    d = args[i + 1] if i + 1 < len(args) else None
                    base = None if d is None or base is None else self._absolute(d, base)
                i += 2
                continue
            if a is not None and a.startswith("-"):
                i += 1
                continue
            break
        if i >= len(args):
            return
        sub, rest = args[i], args[i + 1:]
        if sub is None:
            self.flag("ask", "git.runtime", "the git subcommand is known only at run time")
            return
        if configs:
            # The alias is judged as what it stands for, and the name as written still is:
            # a `git-<name>` program on PATH comes before an alias.
            self._git_inline_config(name, configs, sub, rest, depth)
        flags = _short_flags(rest)
        if sub == "config":
            self._git_config(rest, depth)
        elif sub == "push":
            if "--force" in rest or "f" in flags or any(a and a.startswith("+") for a in rest):
                self.flag("deny", "git.push_force", "`git push --force` rewrites history others share")
            elif any(a and (a.startswith("--force-with-lease") or a == "--force-if-includes") for a in rest):
                self.flag("ask", "git.push_force_with_lease", "`git push --force-with-lease` rewrites remote history")
            elif "--delete" in rest or "d" in flags or "--mirror" in rest or any(
                    a and a.startswith(":") for a in rest):
                self.flag("ask", "git.push_delete", "`git push` deletes or mirrors remote refs")
        elif sub == "reset" and "--hard" in rest:
            self.flag("ask", "git.reset_hard", "`git reset --hard` discards uncommitted work")
        elif sub == "clean" and ("f" in flags or "--force" in rest):
            self.flag("ask", "git.clean", "`git clean -f` deletes untracked files")
        elif sub == "branch" and ("D" in flags or ("--delete" in rest and "--force" in rest)):
            self.flag("ask", "git.branch_delete", "`git branch -D` deletes an unmerged branch")
        elif sub in ("filter-branch", "filter-repo"):
            self.flag("ask", "git.rewrite_history", f"`git {sub}` rewrites history")
        elif sub in ("checkout", "restore", "switch") and _discards_changes(sub, rest, self._git_path_kind(base)):
            # `git checkout -- .` / `git restore src` overwrite edits the way `reset --hard` does.
            # One named file (`git checkout -- a.py`) is how an agent undoes its own edit: no decision.
            self.flag("ask", "git.discard_changes", f"`git {sub}` overwrites uncommitted changes")
        elif sub == "rm" and ("r" in flags or "-r" in rest) and any(
                o in (".", "./", "*", ":/") for o in _operands(rest)) and "--cached" not in rest:
            self.flag("ask", "git.discard_changes", "`git rm -r .` deletes every tracked file")
        elif sub == "stash" and rest[:1] in (["drop"], ["clear"]):
            self.flag("ask", "git.stash_drop", f"`git stash {rest[0]}` deletes stashed work")
        elif sub == "stash" and {"-h", "--help"} & set(rest):
            pass
        elif sub == "stash" and rest[:1] in (["pop"], ["apply"], ["branch"]):
            # Puts back the newest stash, which may be someone else's or an old one, and
            # without --index drops what was staged.
            self.flag("ask", "git.stash", f"`git stash {rest[0]}` writes a stash, maybe not this one, over the files")
        elif sub == "stash" and (not rest or rest[0] is None or rest[0].startswith("-")
                                 or rest[0] not in ("list", "show", "create", "store")):
            # `git stash`, `push`, `save`: uncommitted work, maybe the user's or another
            # agent's, leaves the folder.
            self.flag("ask", "git.stash", "`git stash` takes uncommitted changes out of the folder")

    def _git_path_kind(self, base: str | None):
        """What a git path names on disk: "dir", "file", or None when it is not there."""
        def kind(path: str) -> str | None:
            if base is None:
                return None
            native = self._native(self._absolute(path, base))
            try:
                return "dir" if os.path.isdir(native) else "file" if os.path.isfile(native) else None
            except (OSError, ValueError):
                return None
        return kind

    def _aside(self, judge) -> None:
        """Judge something more without using up this line's record of what it
        downloaded: that record has a size limit the line itself needs."""
        kept = (list(self.fetched), set(self.fetch_said), self.fetch_looks)
        try:
            judge()
        finally:
            self.fetched, self.fetch_said, self.fetch_looks = kept[0], kept[1], kept[2]

    def _git_inline_config(self, name: str, configs: list[Value], sub: str, rest: list[Value],
                           depth: int) -> None:
        """`git -c alias.x='stash pop' x`, `git -c core.pager='…' log`: what the
        alias stands for, and what a setting makes git run."""
        self._aside(lambda: self._git_inline_config_now(name, configs, sub, rest, depth))

    def _git_inline_config_now(self, name: str, configs: list[Value], sub: str, rest: list[Value],
                               depth: int) -> None:
        aliases: dict[str, Value] = {}
        for c in configs:
            if c is None:
                continue  # `-c "user.email=$E"`: an unknown setting, most often harmless
            if c.startswith("\0"):  # `--config-env`: a known key, a value from the environment
                key = c[1:].lower()
                if key.startswith("alias."):
                    aliases[key[len("alias."):]] = None
                elif _git_runs(key, "!x"):
                    self.flag("ask", "code.runtime", "`git` runs code known only at run time")
                continue
            key, eq, value = c.partition("=")
            key = key.lower()
            if key.startswith("alias."):
                aliases[key[len("alias."):]] = value if eq else ""
            elif eq and _git_run_text(key, value):
                self.run(_git_run_text(key, value), depth + 1)  # run by git on this computer, through a shell
        if sub in _GIT_COMMANDS or sub.lower() not in aliases:
            return  # git does not let an alias stand in for its own commands
        if depth + 1 > _MAX_DEPTH:
            self.flag("ask", "parse.too_deep", "commands nested too deep to read")
            return
        value = aliases[sub.lower()]
        if value is None:
            self.flag("ask", "git.runtime", "the git subcommand is known only at run time")
            return
        if value.startswith("!"):
            # git puts the words after the alias at the end of its shell command
            tail = " ".join('"$_bdx_unknown"' if r is None else shlex.quote(r) for r in rest)
            self.run(value[1:] + (" " + tail if tail else ""), depth + 1)
            return
        try:
            words: list[Value] = shlex.split(value)
        except ValueError:
            self.flag("ask", "git.runtime", "the git subcommand is known only at run time")
            return
        # The same settings hold for what the alias stands for (`alias.a=b`, `alias.b=…`).
        again: list[Value] = [w for c in configs for w in ("-c", c)]
        self._git(name, again + words + rest, depth + 1)

    def _git_config(self, rest: list[Value], depth: int) -> None:
        """`git config alias.nuke 'reset --hard'` makes `git nuke` do that later,
        in this session or another; `git config core.pager '…'` makes git run it."""
        words = list(rest)
        if words[:1] in (["set"], ["--add"], ["--replace-all"]):
            words = words[1:]
        elif words[:1] and words[0] is not None and not words[0].startswith("-") and words[0] in (
                "get", "list", "unset", "rename-section", "remove-section", "edit"):
            return
        operands: list[Value] = []
        i = 0
        while i < len(words):
            a = words[i]
            if a is not None and a.startswith("-"):
                if a.startswith(("--get", "--unset", "--list", "--remove-section", "--rename-section",
                                 "--edit")) or a in ("-l", "-e"):
                    return
                i += 2 if a in ("-f", "--file", "--blob", "--type", "--default", "--comment", "--value") else 1
                continue
            operands.append(a)
            i += 1
        if len(operands) < 2 or operands[0] is None:
            return
        key, value = operands[0].lower(), operands[1]
        alias = key.startswith("alias.")
        if not alias and not _git_runs(key, "!x" if value is None else value):  # unknown: only for a key git runs
            return

        def say() -> None:
            if alias:
                self.flag("ask", "git.alias",
                          f"`git config {operands[0]}` makes `git {operands[0][len('alias.'):]}` run a risky command")
            else:
                self.flag("ask", "git.config_command", f"`git config {operands[0]}` sets a risky command for git to run")

        if value is None:
            say()
            return
        if depth + 1 > _MAX_DEPTH:
            self.flag("ask", "parse.too_deep", "commands nested too deep to read")
            return
        inner = _Judge(cwd=self.cwd, home=self.home, rules=self.rules)
        inner.workdirs = [inner.cwd]
        if not alias:
            inner.run(_git_run_text(key, value) or "", depth + 1)
        elif value.startswith("!"):
            inner.run(value[1:], depth + 1)
        else:
            try:
                inner._git("git", shlex.split(value), depth + 1)
            except ValueError:
                inner.flag("ask", "git.runtime", "the git subcommand is known only at run time")
        if inner.decision is None:
            return
        say()
        for finding, reason in zip(inner.findings, inner.reasons):
            # It runs later, maybe elsewhere: ours ask; an org's own rule keeps its level.
            level = finding.level if finding.rule.startswith("custom.") else "ask"
            self._record(level, finding.rule, reason, None)

    def _db(self, name: str, args: list[Value]) -> None:
        r = self.rules
        text = " ".join(a for a in args if a is not None)
        for pattern in r.db_destructive:
            if re.search(pattern, text, flags=re.I):
                self.flag("deny", "db.destructive", f"`{name}` runs a destructive statement")
                return
        for i, a in enumerate(args):
            if a in r.db_code_flags and (i + 1 >= len(args) or args[i + 1] is None):
                self.flag("ask", "db.runtime", f"`{name}` runs a statement known only at run time")
            if a in r.db_file_flags:
                self.flag("ask", "db.file", f"`{name}` runs statements from a file")

    def _remote(self, name: str, words: list[Value], shell: bool, depth: int) -> None:
        """A command run inside a container or on another machine (#37574).
        Its paths are not this computer's, so it is read on its own, as if
        from a folder of its own, and what it would hold or block asks.
        What this command reads on stdin reaches the remote command too: run
        as code there when it is a shell or interpreter reading it."""
        how, text = self.stdin_now
        if not words and not (shell and how):
            return
        if depth + 1 > _MAX_DEPTH:
            self.flag("ask", "parse.too_deep", "commands nested too deep to read")
            return
        inner = _Judge(cwd=_REMOTE_CWD, home=_REMOTE_HOME, rules=self.rules)
        inner.workdirs = [inner.cwd]
        # A command there with no stdin of its own reads this one (`ssh jump ssh host`).
        inner.stdin_base = (how, text)
        readers: list[tuple[str, list[Value]]] = []  # what reads stdin as code there
        if not words:
            readers.append(("sh", []))  # `ssh host`: the login shell reads stdin
        elif not shell:
            name0 = words[0]
            if name0 is not None:  # `bin/console`, as `_name_args` reads a name
                name0 = posixpath.basename(name0.replace("\\", "/"))
                name0 = name0[:-4] if name0.lower().endswith(".exe") else name0
            inner.stdin_now = (how, text)
            inner._judge(name0, words[1:], depth + 1)
            readers.append((name0, words[1:]))
        elif any(w is None for w in words):
            inner._judge("sh", ["-c", None], depth + 1)
        else:
            line = " ".join(words)
            inner.run(line, depth + 1)
            if how:
                for n in _walk(_PARSER.parse(line.encode("utf-8")).root_node):
                    if n.type == "command":
                        readers.append(inner._final(*inner._name_args(n)))
        said = set()  # the same text read by many readers is judged once (`ssh h 'sh;sh;…'`)
        for name0, args in readers if how else ():
            name0, args = inner._final(name0, args)
            if name0 is None or name0 not in self.rules.interpreters or _code_or_file(name0, args, self.rules):
                continue
            key = "sh" if name0 in self.rules.shells else name0
            if key in said:
                continue
            said.add(key)
            if how == "pipe":
                inner.flag("ask", "pipe.into_interpreter", f"output of another command is run as `{name0}` code")
            elif text is None:
                inner.flag("ask", "code.stdin_runtime", f"text known only at run time is fed into `{name0}` as code")
            elif name0 in self.rules.shells:
                inner.stdin_base = (None, None)  # the text is that shell's stdin, read as its code
                inner.run(text, depth + 1)
            else:
                inner._scan_code(name0, text)
        if inner.decision is None:
            return
        self.flag("ask", "remote.run", f"`{name}` runs a risky command inside a container or on another machine")
        for finding, reason in zip(inner.findings, inner.reasons):
            # An org's own rule keeps its level; ours ask: where a path lands there is not known here.
            level = finding.level if finding.rule.startswith("custom.") else "ask"
            self._record(level, finding.rule, reason, None)

    def _ssh(self, name: str, args: list[Value], depth: int) -> None:
        """`ssh host cmd …`: the words reach the remote shell as one line.
        ssh reads its options before and after the host."""
        i, host, values = 0, False, []
        while i < len(args):
            a = args[i]
            if a is None or not a.startswith("-"):
                if host:
                    break
                host = True
                i += 1
                continue
            i += 1
            if a == "--":
                if not host and i < len(args):
                    host = True
                    i += 1  # the host
                break
            letters = a[1:]
            for k, ch in enumerate(letters):
                if ch in "nf":  # stdin from /dev/null
                    self.stdin_now = (None, None)
                if ch in _SSH_VALUE_FLAGS:
                    if k == len(letters) - 1:
                        values.append((ch, args[i] if i < len(args) else None))
                        i += 1  # `-p 22`: the value is the next word
                    else:
                        values.append((ch, letters[k + 1:]))  # `-p22`
                    break
        remote = None  # `-o RemoteCommand=…`: the line the remote shell runs when none follows the host
        for ch, value in values:
            # Run by ssh on this computer, through a shell.
            m = re.match(r"(?i)\s*(ProxyCommand|LocalCommand|KnownHostsCommand|RemoteCommand)\s*[= ]\s*(.*)",
                         value or "", re.S) if ch == "o" else None
            if value is None and ch == "o":
                self.flag("ask", "code.runtime", "`ssh` runs code known only at run time")
            elif m and m.group(2).lower() != "none":
                if m.group(1).lower() == "remotecommand":
                    remote = m.group(2)
                else:
                    self.run(m.group(2), depth + 1)
        if host:
            self._remote(name, args[i:] or ([remote] if remote is not None else []), True, depth)

    def _sshpass(self, name: str, args: list[Value], depth: int) -> None:
        """`sshpass -p pw ssh host …`: it types the password for the command after its options."""
        rest = _strip_options(args, {"-p", "-f", "-d", "-P"})
        if rest:
            self._judge(rest[0], rest[1:], depth)

    def _infra(self, name: str, args: list[Value], depth: int) -> None:
        inner = _container_command(name, args)
        if inner is not None:
            if not _exec_reads_stdin(name, args, inner):
                self.stdin_now = (None, None)
            self._remote(name, inner, False, depth)
        words = [a for a in args if a is not None]
        kind = _DOCKER_LIKE.get(name, name)  # podman takes docker's commands
        if name in ("terraform", "tofu"):
            if "destroy" in words or ("apply" in words and "-destroy" in words):
                self.flag("deny", "iac.destroy", f"`{name}` destroys infrastructure")
        elif name == "pulumi" and "destroy" in words:
            self.flag("deny", "iac.destroy", "`pulumi destroy` destroys infrastructure")
        elif name == "kubectl" and "delete" in words:
            self.flag("deny", "k8s.delete", "`kubectl delete` removes cluster resources")
        elif name == "helm" and ("uninstall" in words or "delete" in words):
            self.flag("ask", "helm.uninstall", "`helm uninstall` removes a release")
        elif name == "aws" and len(words) >= 2:
            service, op = words[0], words[1]
            if service == "s3" and op == "rm":
                self.flag("deny" if "--recursive" in words else "ask", "s3.rm", "`aws s3 rm` deletes objects")
            elif service == "s3" and op == "rb":
                self.flag("deny", "s3.rb", "`aws s3 rb` deletes a bucket")
            elif op.startswith(("delete-", "terminate-", "remove-")):
                self.flag("deny", "cloud.delete", f"`aws {service} {op}` deletes cloud resources")
        elif name in ("gcloud", "az") and "delete" in words:
            self.flag("deny", "cloud.delete", f"`{name} … delete` deletes cloud resources")
        elif kind == "docker" and (words[:2] in (["system", "prune"], ["volume", "prune"],
                                                  ["volume", "rm"], ["image", "prune"])):
            self.flag("ask", "docker.prune", f"`{name}` prune removes data")
        elif (kind == "docker-compose" or (kind == "docker" and words[:1] == ["compose"])) and "down" in words and (
                "-v" in words or "--volumes" in words):
            # #63644: the database lived in the volume
            said = f"{name} compose" if kind == "docker" else name
            self.flag("ask", "docker.prune", f"`{said} down -v` deletes the project's volumes")
        if name in ("terraform", "tofu") and "apply" in words and any(
                w in ("-auto-approve", "--auto-approve") for w in words) and "-destroy" not in words:
            self.flag("ask", "iac.auto_approve", f"`{name} apply -auto-approve` changes infrastructure without a review")

    def _awk(self, name: str, args: list[Value], depth: int) -> None:
        """An awk program that runs commands (`system()`, `| getline`, `print | "…"`)."""
        rest = _strip_options(args, {"-F", "-v", "-f", "--field-separator", "--assign", "--file"})
        if "-f" in args or "--file" in args or not rest:
            return  # a program file: what it runs is not on the line
        program = rest[0]
        if program is None:
            self.flag("ask", "code.runtime", f"`{name}` runs a program known only at run time")
        # String literals become S, so a `|` inside one (`print $2" | "$3`) is not a pipe.
        elif re.search(r"\bsystem\s*\(|\|\s*getline|\|\s*S", re.sub(r'"(\\.|[^"\\])*"', "S", program)):
            self.flag("ask", "code.inline_risky", f"`{name}` program runs other commands")

    def _mirror(self, name: str, args: list[Value], depth: int) -> None:
        """Copies that delete what the source lacks, like `rsync --delete`."""
        words = [a.lower() for a in args if a is not None]
        if name == "robocopy" and ({"/mir", "/purge"} & set(words)):
            self.flag("ask", "mirror.delete", "`robocopy /MIR` deletes files the source does not have")
        elif name == "lftp" and any("mirror" in w for w in words) and any("--delete" in w for w in words):
            # `lftp mirror --delete …` or the same inside `lftp -e "…"`
            self.flag("ask", "mirror.delete", "`lftp mirror --delete` deletes files the source does not have")

    def _gh(self, name: str, args: list[Value], depth: int) -> None:
        words = [a for a in args if a is not None]
        if words[:2] == ["repo", "delete"]:
            self.flag("deny", "gh.delete", "`gh repo delete` deletes a repository")
        elif words[:1] == ["api"] and any(
                (w in ("-X", "--method") and i + 1 < len(words) and words[i + 1].upper() == "DELETE")
                or w.upper() in ("-XDELETE", "--METHOD=DELETE") for i, w in enumerate(words)):
            self.flag("ask", "gh.delete", "`gh api` sends a DELETE")

    def _firebase(self, name: str, args: list[Value], depth: int) -> None:
        op = next((a for a in args if a is not None and not a.startswith("-")), "")
        if re.fullmatch(r"(hosting:disable|firestore:delete|database:remove|functions:delete|"
                        r"hosting:channel:delete|apps:delete|projects:delete)", op):
            self.flag("ask", "cloud.delete", f"`firebase {op}` deletes or takes down cloud resources")

    def _wsl(self, name: str, args: list[Value], depth: int) -> None:
        """`wsl` runs a Linux command: after `-e`/`--exec` as given, after `--`
        or on its own through the distro's shell."""
        i = 0
        while i < len(args) and args[i] is not None and args[i].startswith("-"):
            a = args[i]
            if a in ("--unregister",):
                self.flag("deny", "wsl.unregister", "`wsl --unregister` deletes the distro and every file in it")
                return
            if a in ("-e", "--exec"):
                rest = args[i + 1:]
                if rest:
                    self._judge(rest[0], rest[1:], depth)
                return
            if a == "--":
                i += 1
                break
            i += 2 if a in ("-d", "--distribution", "-u", "--user", "--cd", "--shell-type") else 1
        rest = args[i:]
        if rest:
            # The words reach the distro's shell as one line, with the quoting
            # they had on this side: read them both as a command and as that line.
            self._judge(rest[0], rest[1:], depth)
            if any(w is None or re.search(r"[;&|<>`$()]", w) for w in rest):
                self._judge("sh", ["-c", None if any(w is None for w in rest) else " ".join(rest)], depth)

    def _device(self, name: str, args: list[Value], depth: int) -> None:
        """A phone or other device on the end of `adb` / `fastboot`: its data
        is not in the project, and a wipe there has no undo."""
        if name == "fastboot" and "-w" in args:
            self.flag("deny", "device.wipe", "`fastboot -w` wipes data on the device")
            return
        words = _strip_options(args, takes_value={"-s", "-t", "-H", "-P", "-L", "--one-device"})
        if not words or words[0] is None:
            return
        op, rest = words[0], words[1:]
        if name == "fastboot":
            if op in ("erase", "format", "wipe-super") or (
                    op in ("flashing", "oem") and rest[:1] in (["unlock"], ["unlock_critical"])):
                self.flag("deny", "device.wipe", f"`fastboot {op}` wipes data on the device")
            elif op in ("flash", "flashall", "update"):
                self.flag("ask", "device.flash", f"`fastboot {op}` overwrites a partition on the device")
            return
        if op == "uninstall":
            self.flag("ask", "device.app_data", "`adb uninstall` removes an app and its data from the device")
        elif op == "shell":
            text = " ".join("?" if a is None else a for a in rest)
            if re.search(r"\b(pm|cmd\s+package)\s+(clear|uninstall)\b", text):
                self.flag("ask", "device.app_data", "`adb shell` clears or removes an app's data on the device")
            elif re.search(r"(^|[;&|]\s*)(rm|recovery|wipe)\b", text.strip()):
                self.flag("ask", "device.app_data", "`adb shell` deletes or wipes data on the device")


_HANDLERS = {
    "rm": _Judge._rm, "rmdir": _Judge._rm, "unlink": _Judge._rm, "ln": _Judge._ln,
    "find": _Judge._find, "dd": _Judge._dd, "truncate": _Judge._truncate,
    "chmod": _Judge._chmod, "chown": _Judge._chmod, "chgrp": _Judge._chmod,
    "sed": _Judge._sed, "cp": _Judge._cp_mv, "mv": _Judge._cp_mv, "install": _Judge._cp_mv,
    "git": _Judge._git, "tee": _Judge._tee, "tar": _Judge._tar, "unzip": _Judge._unzip,
    "rsync": _Judge._rsync,
    "terraform": _Judge._infra, "tofu": _Judge._infra, "pulumi": _Judge._infra,
    "kubectl": _Judge._infra, "helm": _Judge._infra, "aws": _Judge._infra,
    "gcloud": _Judge._infra, "az": _Judge._infra, "docker": _Judge._infra,
    "adb": _Judge._device, "fastboot": _Judge._device,
    "awk": _Judge._awk, "gawk": _Judge._awk, "mawk": _Judge._awk, "nawk": _Judge._awk,
    "wsl": _Judge._wsl, "docker-compose": _Judge._infra,
    "podman": _Judge._infra, "podman-compose": _Judge._infra,
    "robocopy": _Judge._mirror, "lftp": _Judge._mirror, "gh": _Judge._gh, "firebase": _Judge._firebase,
    "ssh": _Judge._ssh, "sshpass": _Judge._sshpass,
}


# ── helpers ─────────────────────────────────────────────────────────────────

# Commands that can change any variable without an assignment we can see.
_REASSIGNS = frozenset({
    "eval", "source", ".", "read", "mapfile", "readarray", "getopts", "unset",
    "let", "declare", "typeset", "local", "readonly", "printf",  # printf -v
})


_NOT_STRAIGHT = (False, None)


def _straight_line(assignment: Node) -> tuple[bool, Optional[Node]]:
    """(holds, scope) for `X=…` / `export X=…` running in this shell.

    Top level: holds for the rest of the line (scope None). Inside an
    `a && X=… && b` chain: holds only for later uses inside that same chain,
    because those run only if the assignment did; after the chain ends the
    assignment may not have run (scope = the chain). A subshell, pipeline
    stage, `||`, if/for/while/case body or function body fails.
    """
    parent = assignment.parent
    while parent is not None and parent.type == "variable_assignments":
        parent = parent.parent
    if parent is not None and parent.type == "declaration_command":
        if not parent.children or parent.children[0].type != "export":
            return _NOT_STRAIGHT
        parent = parent.parent
    scope = None
    # tree-sitter hangs the redirect of `a && b > f` on the whole chain
    # (redirected_statement over the list); bash gives it to `b`, which runs
    # only after the assignment did, so the wrapper stays inside the scope.
    while parent is not None and parent.type in ("list", "redirected_statement"):
        if parent.type == "list":
            operators = {c.type for c in parent.children if not c.is_named}
            if operators != {"&&"}:
                return _NOT_STRAIGHT
        elif parent.child_by_field_name("body") is None or parent.child_by_field_name("body").type != "list":
            return _NOT_STRAIGHT
        scope = parent
        parent = parent.parent
    if parent is None or parent.type != "program":
        return _NOT_STRAIGHT
    return True, scope


def _walk(node: Node):
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(reversed(n.children))


_RSYNC_VALUES = frozenset({"-e", "--rsh", "--exclude", "--include", "--filter", "-f", "--files-from",
                           "--exclude-from", "--include-from", "--port", "--password-file", "--rsync-path",
                           "--log-file", "--bwlimit", "--timeout", "-T", "--temp-dir", "--partial-dir",
                           "--backup-dir", "--compare-dest", "--link-dest", "--copy-dest", "--chmod",
                           "--chown", "--max-size", "--min-size", "--out-format", "--info", "--debug",
                           "--suffix", "--block-size", "--log-file-format", "--iconv", "--sockopts",
                           "--contimeout", "--address", "--skip-compress", "--compress-choice", "--max-delete",
                           "--modify-window", "-B", "--stop-after", "--stop-at", "--max-alloc", "-M",
                           "--remote-option", "--checksum-choice", "--compress-level", "--groupmap",
                           "--usermap", "--write-batch", "--only-write-batch", "--read-batch",
                           "--protocol", "--early-input"})
_MAX_BRACE_WORDS = 1024
_MAX_BRACE_LENGTH = 2048
_TAR_VALUE_LETTERS = "fCTXbKNFgHILV"


def _brace_split(word: str) -> Optional[list[str]]:
    """The words the first `{a,b}` in `word` makes, or None when it has no such brace."""
    open_braces: list[list[int]] = []
    best: Optional[list[int]] = None
    for i, ch in enumerate(word):
        if ch == "{":
            open_braces.append([i])
        elif ch == "," and open_braces:
            open_braces[-1].append(i)
        elif ch == "}" and open_braces:
            cuts = open_braces.pop()
            if len(cuts) > 1 and (best is None or cuts[0] < best[0]):
                best = cuts + [i]
    if best is None:
        return None
    return [word[:best[0]] + word[a + 1:b] + word[best[-1] + 1:] for a, b in zip(best, best[1:])]


def _braces(word: str) -> list[Value]:
    """What the shell makes of an unquoted word. Too many words is a path not known."""
    if "{" in word and len(word) > _MAX_BRACE_LENGTH:
        return [None]
    done: list[Value] = []
    todo = [word]
    while todo:
        if len(done) + len(todo) > _MAX_BRACE_WORDS:
            return [None]
        current = todo.pop()
        split = _brace_split(current)
        if split is None:
            done.append(current)
        else:
            todo.extend(reversed(split))
    return done


def _env_dirs(options: list[Value]) -> list[Value]:
    """Each directory `env` moves to, in order: `-C d`, `-iC d`, `-Cd`, `--chdir d`, `--chdir=d`."""
    out: list[Value] = []
    for i, a in enumerate(options):
        if a is None:
            continue
        m = re.fullmatch(r"-[iv0]*C(.*)|--chdir(?:=(.*))?", a)
        if m:
            given = m.group(1) or m.group(2)
            out.append(given or (options[i + 1] if i + 1 < len(options) else None))
    return out


def _tar_short(args: list[Value]) -> list[tuple[str, Value]]:
    """Each short option of `tar` with its value: `-xC dir`, `-Cdir`, `-czfa.tgz`, and the
    old form with no dash, where the values follow in order (`xfC a.tar dir`)."""
    out: list[tuple[str, Value]] = []
    taken: set[int] = set()
    for i, a in enumerate(args):
        dashed = a is not None and a.startswith("-") and not a.startswith("--") and a != "-"
        if i in taken or a is None or not (dashed or (i == 0 and not a.startswith("-"))):
            continue
        word = a[1:] if dashed else a
        following = i + 1
        for k, letter in enumerate(word):
            if letter not in _TAR_VALUE_LETTERS:
                out.append((letter, None))
            elif dashed and word[k + 1:]:
                out.append((letter, word[k + 1:]))
                break
            else:
                out.append((letter, args[following] if following < len(args) else None))
                taken.add(following)
                following += 1
                if dashed:
                    break
    return out


def _option_values(args: list[Value], names: tuple[str, ...]) -> list[Value]:
    """The values of an option: `-C dir`, `-Cdir`, `--directory dir`, `--directory=dir`."""
    out: list[Value] = []
    for i, a in enumerate(args):
        if a is None:
            continue
        for n in names:
            if a == n:
                out.append(args[i + 1] if i + 1 < len(args) else None)
            elif a.startswith(n + "=") if n.startswith("--") else a.startswith(n):
                out.append(a[len(n) + n.startswith("--"):])
    return out


def _operands(args: list[Value], takes_value: frozenset[str] | set[str] = frozenset()) -> list[Value]:
    out: list[Value] = []
    skip = False
    after_dashdash = False
    for a in args:
        if skip:
            skip = False
            continue
        if after_dashdash:
            out.append(a)
        elif a == "--":
            after_dashdash = True
        elif a is not None and a.startswith("-") and a != "-":
            if a in takes_value:
                skip = True
        else:
            out.append(a)
    return out


def _piped_commands(root: Node) -> set:
    """Ids of the commands that read the output of another one: in a stage
    after the first of a pipeline, or the first after a heredoc start
    (`cat <<EOF | ssh h`), as `_pipeline` reads the stages it calls fed;
    a command in a group or subshell there too (`cat x | (cd /tmp && ssh h)`).
    One walk of the line, so a long line is not climbed once per command."""
    ids: set = set()
    for line in _walk(root):
        if line.type != "pipeline":
            continue
        stages = list(line.named_children)
        after_heredoc = line.parent is not None and line.parent.type == "heredoc_redirect"
        for stage in stages if after_heredoc else stages[1:]:
            ids.update(n.id for n in _walk(stage) if n.type == "command")
    return ids


def _positional(args: list[Value]) -> list[Value]:
    return [a for a in args if a is None or not a.startswith("-")]


def _code_or_file(name: str, args: list[Value], rules: CommandRules) -> bool:
    """True when the interpreter is told what to run, so stdin is data.
    `bash /dev/stdin` and `bash -s arg` still run stdin."""
    if _code_on_line(name, args, rules) is not None:
        return True
    if name in rules.shells and any(a is not None and re.fullmatch(r"-[A-Za-z]*s[A-Za-z]*", a) for a in args):
        return False
    at = _first_operand(name, args, rules)
    return at is not None and args[at] not in _STDIN_FILES


def _first_operand(name: str, args: list[Value], rules: CommandRules) -> Optional[int]:
    """The first word that is not an option or an option's value
    (`bash -euo pipefail x.sh`: `x.sh`, not `pipefail`)."""
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            return i + 1 if i + 1 < len(args) else None
        if a is not None and (a.startswith("-") or name in rules.shells and a.startswith("+")):
            i += 2 if _takes_value(name, a, rules) else 1
            continue
        return i
    return None


def _takes_value(name: str, flag: str, rules: CommandRules) -> bool:
    """The interpreter option's value is the next word (`-o pipefail`, `-W ignore`)."""
    if flag in _SCRIPT_VALUE_FLAGS.get(name, frozenset()):
        return True
    return name in rules.shells and (flag in _SHELL_VALUE_FLAGS or flag in ("--rcfile", "--init-file")
                                     or re.fullmatch(r"[-+][A-Za-z]*[oO]", flag) is not None)


_STDIN_FILES = frozenset({"/dev/stdin", "/dev/fd/0", "/proc/self/fd/0"})


# ── a file the line downloads ───────────────────────────────────────────────
# Kept in code, not in the rule values: a signed bundle stands in for those
# whole, and this is how two programs are read, not a list to tune.
_FETCHERS = frozenset({"curl", "wget"})
_CURL_VALUE_LETTERS = "AbcCdDeEFHKmoPQrtTuUwxXyYz"  # short options that take a value
_CURL_VALUE_WORDS = frozenset({
    "--max-time", "--connect-timeout", "--retry", "--retry-delay", "--retry-max-time", "--header",
    "--data", "--data-raw", "--data-binary", "--data-urlencode", "--json", "--form", "--form-string",
    "--user", "--user-agent", "--request", "--proxy", "--cacert", "--cert", "--key", "--referer",
    "--cookie", "--cookie-jar", "--write-out", "--range", "--limit-rate", "--config", "--upload-file",
    "--resolve", "--interface", "--oauth2-bearer", "--proto", "--ciphers", "--dump-header",
    "--stderr", "--trace", "--trace-ascii", "--netrc-file", "--unix-socket", "--speed-limit", "--speed-time",
})
_WGET_VALUE_LETTERS = "oaiBtOTwQPUlARDIXe"
_WGET_VALUE_WORDS = frozenset({
    "--output-file", "--append-output", "--input-file", "--base", "--tries", "--timeout", "--wait",
    "--quota", "--user-agent", "--header", "--level", "--accept", "--reject", "--domains",
    "--include-directories", "--exclude-directories", "--execute", "--user", "--password",
    "--post-data", "--post-file", "--limit-rate", "--load-cookies", "--save-cookies", "--referer",
    "--ca-certificate", "--certificate", "--private-key", "--method", "--body-data", "--body-file",
})
# Options whose next word is their value, not the script (`python -W ignore x.py`).
_SCRIPT_VALUE_FLAGS = {
    "python": frozenset({"-W", "-X", "--check-hash-based-pycs"}),
    "python3": frozenset({"-W", "-X", "--check-hash-based-pycs"}),
    "node": frozenset({"-r", "--require", "--import", "--loader", "--experimental-loader",
                       "--conditions", "-C", "--env-file", "--title"}),
    "ruby": frozenset({"-I", "-r", "-C", "-E", "-K", "-x"}),
    "perl": frozenset({"-I", "-M", "-m", "-x"}),
    "php": frozenset({"-c", "-d", "-z", "-t", "-S"}),
    "deno": frozenset({"-c", "--config", "--import-map", "--lock", "--cert", "--location", "--seed",
                       "--env-file", "--reload", "-r"}),
    "bun": frozenset({"-c", "--config", "--cwd", "--env-file", "--preload", "-r", "--tsconfig-override"}),
}
# Options that only check the file for mistakes.
_CHECK_ONLY = {
    "node": frozenset({"--check", "-c"}), "php": frozenset({"-l", "--syntax-check"}),
    "ruby": frozenset({"-c", "-wc"}), "perl": frozenset({"-c", "-wc"}),
}
# powershell.exe options that take a value (any start of the name is accepted), with their short forms.
_POWERSHELL_VALUE_NAMES = (  # (name, fewest letters that still mean it)
    ("executionpolicy", 2), ("ep", 2), ("windowstyle", 1), ("version", 1), ("configurationname", 3),
    ("workingdirectory", 2), ("wd", 2), ("inputformat", 2), ("if", 2), ("outputformat", 1), ("of", 2),
    ("psconsolefile", 2), ("custompipename", 2), ("settingsfile", 2), ("encodedarguments", 8), ("ea", 2),
)
_INTERPRETER_NAMES = re.compile(r"^(python|pypy|ruby|perl|php|lua|node)[\d.]+$")  # python3.12, node18
# Opening one of these runs nothing of its own.
_DOCUMENT = re.compile(r"(?i)\.(png|jpe?g|gif|bmp|svg|webp|ico|tiff?|heic|pdf|html?|txt|md|csv|tsv|json|ya?ml|xml|log|"
                       r"docx?|xlsx?|pptx?|epub|mp[34]|mov|avi|mkv|wav|flac|zip|tar|gz|tgz|7z)$")
_FETCHED_MOST = 64   # downloads kept for one line; past that the line is not followed further
_FOLDERS_MOST = 32   # folders a relative name is tried in
_LOOKS_MOST = 200    # redirects and `tee`s of one line that are looked through for a download


def _redirect_body(node: Node) -> Node:
    """What a redirect is attached to."""
    parent = node.parent
    if parent is not None and parent.type == "heredoc_redirect" and parent.parent is not None:
        # `cat <<EOF > f && more`: the parser puts the `>` and the rest of that line inside the
        # here-document's node; the redirect is the command's that owns the here-document.
        parent = parent.parent
    if parent is None:
        return node
    body = parent if parent.type == "command" else parent.child_by_field_name("body") or parent
    # The parser hangs the redirect of `a && b > f` on the whole chain; the shell gives it to `b`.
    while body.type == "list" and body.named_children:
        body = body.named_children[-1]
    return body


def _url_name(url: str) -> Optional[str]:
    """The file name a URL ends in, as `curl -O` and `wget` take it."""
    path = re.sub(r"^[A-Za-z][A-Za-z0-9+.-]*://[^/?#]*", "", url) if "://" in url else url.partition("/")[2]
    path = re.split(r"[?#]", path, maxsplit=1)[0]
    name = path.rsplit("/", 1)[-1]
    return name or None


def _fetch_outputs(name: str, args: list[Value]) -> list[tuple[Optional[int], Value]]:
    """The files `curl` or `wget` writes: (index of the argument that names
    the file, None) or (None, a name worked out from the URL)."""
    curl = name == "curl"
    if not curl and "--spider" in args:
        return []  # looks, saves nothing
    letters = _CURL_VALUE_LETTERS if curl else _WGET_VALUE_LETTERS
    words = _CURL_VALUE_WORDS if curl else _WGET_VALUE_WORDS
    long_out = ("--output",) if curl else ("--output-document",)
    long_dir = "--output-dir" if curl else "--directory-prefix"
    named: list[tuple[Optional[int], Value]] = []
    urls: list[str] = []
    folder: Value = ""
    remote = not curl  # wget saves under the URL's name unless -O says otherwise
    i = 0
    while i < len(args):
        a = args[i]
        i += 1
        if a is None:
            continue
        if a.startswith("--"):
            option, eq, value = a.partition("=")
            if option in long_out:
                named.append((None, value) if eq else (i if i < len(args) else None, None))
                i += 0 if eq else 1
            elif option == long_dir:
                folder = value if eq else (args[i] if i < len(args) else None)
                i += 0 if eq else 1
            elif option in ("--remote-name", "--remote-name-all"):
                remote = True
            elif option == "--url" and not eq and i < len(args):
                if args[i] is not None:
                    urls.append(args[i])
                i += 1
            elif option in words and not eq:
                i += 1
        elif a.startswith("-") and len(a) > 1:
            cluster = a[1:]
            for k, letter in enumerate(cluster):
                if curl and letter == "O":
                    remote = True
                elif letter in letters:
                    attached = cluster[k + 1:]
                    if letter == ("o" if curl else "O"):
                        named.append((None, attached) if attached else (i if i < len(args) else None, None))
                    elif not curl and letter == "P":
                        folder = attached or (args[i] if i < len(args) else None)
                    if not attached:
                        i += 1
                    break
        else:
            urls.append(a)
    named = [(at, value) for at, value in named if at is not None or value is not None]
    if curl and folder and named:  # `--output-dir d -o x`
        named = [(None, None if folder is None or (args[at] if at is not None else value) is None
                  else posixpath.join(folder, args[at] if at is not None else value)) for at, value in named]
    if named and not curl:
        return named  # `wget -O x`: everything goes into the one file
    if remote and folder is not None:
        for url in urls:
            last = _url_name(url) or (None if curl else "index.html")
            if last:
                named.append((None, posixpath.join(folder, last) if folder else last))
    return named


def _powershell_option(arg: str) -> Optional[str]:
    """What a powershell.exe option is: "file", "command", "value" (its next
    word is its value) or "switch"; None when the word is no option. The
    program takes `-` or `/` and any start of a name that is long enough."""
    if arg[:1] not in "-/" or len(arg) < 2:
        return None
    given = arg[1:].lower()
    if any(len(given) >= least and full.startswith(given) for full, least in _POWERSHELL_VALUE_NAMES):
        return "value"
    if "file".startswith(given):
        return "file"
    if "command".startswith(given):
        return "command"
    return "switch"


def _first_word_of_code(name: str, args: list[Value]) -> Value:
    """The program `cmd /c …` or `powershell -Command …` starts with, when it is on the line."""
    for i, a in enumerate(args[:-1]):
        if a is None:
            continue
        if name == "cmd":
            found = a.lower() in ("/c", "//c", "/k", "//k", "/r", "//r")
        else:
            found = _powershell_option(a) == "command"
        if found:
            if args[i + 1] is None:
                return None
            code = " ".join(a for a in args[i + 1:i + 4] if a is not None)  # one string, or words of their own
            words = code.strip().lstrip("&").split()
            if words[:1] in (["call"], ["."], ["start"]) and len(words) > 1:  # `cmd /c call x.bat`, `pwsh -c '. ./x.ps1'`
                words = words[1:]
            return words[0].strip("'\"") if words else None
    return None


def _script_candidates(name: str, args: list[Value], rules: CommandRules,
                       raws: Optional[list] = None) -> list[int]:
    """Where the script file can be among an interpreter's arguments: the
    first word that is not an option or an option's value, and before it any
    word known only at run time (`python3 $FLAGS x.py`: it may be an option,
    it may be the script). Empty when the interpreter runs no file, or only
    checks one (`bash -n`, `node --check`, `php -l`)."""
    check = _CHECK_ONLY.get(name, frozenset())
    shell = name in rules.shells
    powershell = name in ("pwsh", "powershell")
    found: list[int] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a is None:
            found.append(i)  # the same file only if it is written the same way
            raw = (raws[i] if raws and i < len(raws) else None) or ""
            if not re.fullmatch(r"""["']?\$(?:\w+|\{\w+\}|[@*])["']?""", raw.strip()):
                return found  # `"$DIR/check.py"`: more than a bare variable is the script, not an option
            i += 1
            continue
        if powershell:
            kind = _powershell_option(a)
            if kind == "file":
                return found + [i + 1] if i + 1 < len(args) else found
            if kind == "command":
                return []  # code, read elsewhere
            if kind is not None:
                following = args[i + 1] if i + 1 < len(args) else None
                # the next word is the value only when it is not an option itself (`-ep -File x.ps1`)
                i += 2 if kind == "value" and not (following or "").startswith(("-", "/")) else 1
                continue
            return found + [i]
        if a == "--":
            return found + [i + 1] if i + 1 < len(args) else found
        if a in check or shell and re.fullmatch(r"-[A-Za-z]*n[A-Za-z]*", a):
            return []  # reads it for mistakes, does not run it
        if name in ("python", "python3") and re.fullmatch(r"-[bBdEhiIOqsSuvVx]*m.*", a):
            return []  # a module, by name
        if a.startswith("-") and a != "-" or shell and a.startswith("+"):
            i += 2 if _takes_value(name, a, rules) else 1
            continue
        if name in ("deno", "bun") and a == "run":
            i += 1
            continue
        return found + [i]
    return found


# Short flags run together (`bash -lc`, `perl -le`, `python -Ic`). A shell
# takes its code from the first argument after its options; these take it
# from the rest of the cluster, or the next argument. Letters that take a
# value before the code letter make the rest that value, not code.
_CLUSTERED = {"python": "WXmc", "python3": "WXmc", "perl": "iIMmxCFdD0", "ruby": "IrCEFKTWxi0"}
_SHELL_VALUE_FLAGS = frozenset({"-o", "+o", "-O", "+O"})


def _code_on_line(name: str, args: list[Value], rules: CommandRules) -> Optional[tuple[int, Value]]:
    """(the code flag's index, the code) when this interpreter is given code
    on the line, the code None when it is known only at run time; None when
    no code flag is there."""
    flags = rules.code_flags.get(name)
    if not flags:
        return None
    letters = [f[1] for f in flags if len(f) == 2 and f[0] == "-" and f[1].isalpha()]
    for i, a in enumerate(args):
        if a is None:
            continue
        attached = ""
        if a not in flags:
            m = re.fullmatch(r"-([A-Za-z]{2,})", a)
            if m is None:
                continue
            cluster = m.group(1)
            if name in rules.shells:
                if not any(x in cluster for x in letters):
                    continue
                if "o" in cluster or "O" in cluster:
                    return i, None  # `-eo pipefail`: which argument is the code is not worth guessing
            elif name in _CLUSTERED:
                at = min((cluster.index(x) for x in letters if x in cluster), default=None)
                if at is None or any(x in _CLUSTERED[name] for x in cluster[:at]):
                    continue
                attached = cluster[at + 1:]
            else:
                continue
        if attached:
            return i, attached
        if name in rules.shells:
            j = i + 1
            while j < len(args) and args[j] is not None and args[j][:1] in "-+":
                j += 2 if args[j] in _SHELL_VALUE_FLAGS else 1
                if args[j - 1] == "--":
                    break
            return i, args[j] if j < len(args) else None
        return i, args[i + 1] if i + 1 < len(args) else None
    return None


def _strip_options(args: list[Value], takes_value: set[str]) -> list[Value]:
    i = 0
    while i < len(args) and args[i] is not None and args[i].startswith("-"):
        i += 2 if args[i] in takes_value else 1
    return args[i:]


def _unwrap(name: str, args: list[Value]) -> list[Value]:
    """The command a wrapper runs, with the wrapper's own options removed."""
    if name == "env":
        i = 0
        while i < len(args) and args[i] is not None and (args[i].startswith("-") or "=" in args[i]):
            i += 2 if args[i] in ("--chdir", "--unset") or re.fullmatch(r"-[iv0]*[uCS]", args[i]) else 1
        return args[i:]
    if name == "nice":
        return _strip_options(args, {"-n", "--adjustment"})
    if name == "timeout":
        rest = _strip_options(args, {"-s", "-k", "--signal", "--kill-after"})
        return rest[1:]  # the duration
    if name == "xargs":
        return _strip_options(args, {"-I", "-i", "-n", "-P", "-L", "-s", "-d", "-E", "-a"})
    if name == "stdbuf":
        return _strip_options(args, {"-i", "-o", "-e"})
    if name == "exec":
        return _strip_options(args, {"-a"})
    if name in ("strace", "ltrace"):
        return _strip_options(args, {"-o", "-e", "-p", "-s", "-u", "-E", "-a", "-b", "-I", "-O", "-P", "-S", "-X", "-n"})
    if name == "systemd-run":
        return _strip_options(args, {"-p", "--property", "-u", "--unit", "--uid", "--gid", "-E", "--setenv",
                                     "--working-directory", "-M", "--machine", "-H", "--host",
                                     "--description", "--slice", "--on-calendar", "--on-active"})
    if name == "chroot":
        return _strip_options(args, set())[1:]  # the new root
    if name == "screen":
        i = 0
        while i < len(args) and args[i] is not None and args[i].startswith("-"):
            # `-dmS name`: a cluster ending in a letter that takes a value takes the next word
            i += 2 if args[i] == "-Logfile" or args[i][-1:] in "Scehpst" else 1
        return args[i:]
    # These hand their command to a shell as one string.
    if name == "flock":
        rest = _strip_options(args, {"-w", "--wait", "--timeout", "-E", "--conflict-exit-code"})[1:]  # the lock
        if rest[:1] in (["-c"], ["--command"]):
            return ["sh", "-c", rest[1] if len(rest) > 1 else None]
        return rest
    if name == "watch":
        return _as_shell_code(_strip_options(args, {"-n", "--interval", "-d", "-q", "--equexit"}))
    if name == "script":
        for i, a in enumerate(args):
            if a in ("-c", "--command") or (a and re.fullmatch(r"-[a-zA-Z]*c", a)):
                return ["sh", "-c", args[i + 1] if i + 1 < len(args) else None]
        return []  # an interactive shell: what it runs is typed later
    if name == "tmux":
        return _tmux_command(args)
    return _strip_options(args, set())


# Tools that wipe a database by design. Matched on the words of the line when
# it starts with one of these names (directly, or through npx / pnpm / sail …),
# so `git commit -m "prisma migrate reset"` is not a match.
_DB_RESET_NAMES = frozenset({
    "npx", "pnpx", "bunx", "pnpm", "yarn", "npm", "bun", "prisma", "drizzle-kit", "php", "artisan", "sail",
    "supabase", "alembic", "python", "python3", "rails", "rake", "console", "symfony", "knex", "sequelize",
    "typeorm", "dropdb",
})
_DB_RESETS = (
    r"\bprisma\s+migrate\s+reset\b", r"\bprisma\s+db\s+push\b.*--(force-reset|accept-data-loss)\b",
    r"\bdrizzle-kit\s+(push\b.*--force\b|drop\b)",
    r"\bartisan\s+(migrate:(fresh|reset|refresh)|db:wipe)\b",
    r"\bsupabase\s+db\s+reset\b",
    r"\balembic\s+downgrade\s+base\b",
    r"\bdoctrine:(fixtures:load(?!.*--append)|database:drop|schema:drop)\b",
    r"\b(rails|rake)\s+db:(drop|reset|purge|schema:load)\b",
    r"\bmanage\.py\s+(flush|reset_db)\b",
    r"\bknex\s+migrate:rollback\b.*--all\b", r"\bsequelize(-cli)?\s+db:drop\b", r"\btypeorm\s+schema:drop\b",
    r"^dropdb\b",
)


_CHECKOUT_VALUES = {"-b", "-B", "--orphan", "--conflict", "-t", "--track"}
_RESTORE_VALUES = {"-s", "--source", "--conflict"}


# git runs these settings' values through a shell.
_GIT_RUNS = re.compile(r"core\.(sshcommand|pager|editor|fsmonitor|askpass|gitproxy|alternaterefscommand)"
                       r"|sequence\.editor|diff\.external|interactive\.difffilter|sendemail\.sendmailcmd"
                       r"|gpg(\.\w+)?\.program|gpg\.ssh\.defaultkeycommand|pager\.[\w-]+"
                       r"|diff\.[^.]+\.(textconv|command)|(diff|merge)tool\.[^.]+\.cmd|(browser|man)\.[^.]+\.cmd"
                       r"|trailer\.[^.]+\.(command|cmd)|remote\.[^.]+\.(uploadpack|receivepack)"
                       r"|sendemail\.(tocmd|cccmd|headercmd)|hook\.[^.]+\.command"
                       r"|merge\.[^.]+\.driver|filter\.[^.]+\.(clean|smudge|process)|uploadpack\.packobjectshook")


def _git_run_text(key: str, value: str) -> Optional[str]:
    """The shell command git runs for a setting, or None when it runs none.
    `core.fsmonitor` and `pager.x` also take true/false."""
    v = value.strip()
    if key == "credential.helper" or re.fullmatch(r"credential\..+\.helper", key):
        if not v:
            return None
        # `!cmd` as written, an absolute path as is, a name as `git credential-<name>`
        return v[1:] if v.startswith("!") else v if v.startswith("/") else "git credential-" + v
    if re.fullmatch(r"submodule\..+\.update", key):
        return v[1:] if v.startswith("!") else None
    if not _GIT_RUNS.fullmatch(key) or v.lower() in ("", "true", "false", "yes", "no", "on", "off", "0", "1"):
        return None
    if re.fullmatch(r"gpg(\.\w+)?\.program", key):
        return shlex.quote(v)  # a program, run without a shell: spaces and brackets are its name
    return v


def _git_runs(key: str, value: str) -> bool:
    return _git_run_text(key, value) is not None


# git's own commands: an alias of the same name is ignored.
_GIT_COMMANDS = frozenset("""
add am annotate apply archive bisect blame branch bundle cat-file check-attr check-ignore check-mailmap
check-ref-format checkout checkout-index cherry cherry-pick clean clone column commit commit-graph
commit-tree config count-objects credential describe diagnose diff diff-files diff-index diff-tree difftool
fast-export fast-import fetch fetch-pack fmt-merge-msg for-each-ref for-each-repo format-patch
fsck gc get-tar-commit-id grep hash-object help hook http-backend index-pack init interpret-trailers
log ls-files ls-remote ls-tree mailinfo mailsplit maintenance merge merge-base merge-file merge-index merge-tree
mktag mktree multi-pack-index mv name-rev notes pack-objects pack-redundant pack-refs patch-id prune prune-packed
pull push range-diff read-tree rebase reflog remote repack replace rerere reset restore rev-list
rev-parse revert rm send-pack shortlog show show-branch show-index show-ref sparse-checkout stash
status stripspace submodule switch symbolic-ref tag unpack-file unpack-objects update-index update-ref
update-server-info var verify-commit verify-pack verify-tag version whatchanged worktree write-tree
""".split())


def _discards_changes(sub: str, rest: list[Value], kind) -> bool:
    """`git checkout|restore|switch` that overwrites edits in more than one named file.
    `kind(path)` says whether the path is a folder or a file on disk."""
    words = set(rest)
    if sub != "restore" and ("--force" in words or "f" in _short_flags(rest)) or "--discard-changes" in words:
        return True
    if any(a is not None and a.startswith("--pathspec-from-file") for a in rest):
        return True
    if sub == "switch":
        return False
    if sub == "restore":
        staged = {"--staged", "-S"} & words
        worktree = {"--worktree", "-W"} & words
        return (not staged or bool(worktree)) and _folder_paths(_operands(rest, _RESTORE_VALUES), kind)
    # checkout
    if "--" in rest:
        return _folder_paths(rest[rest.index("--") + 1:], kind)
    if {"-b", "-B", "--orphan"} & words or any(a and a.startswith("--orphan=") for a in rest):
        return False
    operands = _operands(rest, _CHECKOUT_VALUES)
    if not operands:
        return False
    if len(operands) == 1:
        # `git checkout main` is a branch, `git checkout .` a path; `src` is a
        # path when it is a folder here or starts `./`. `"$BRANCH"`: a branch.
        p = operands[0]
        if p is None:
            return False
        if p.startswith(("./", ".\\")) or kind(p) == "dir":
            return _folder_paths([p], kind)
        return _broad_paths([p])
    # `git checkout HEAD src`: what follows the first is paths, and the first
    # too when it is a folder here (`git checkout src a.py`).
    first = operands[0]
    if first is not None and kind(first) == "dir":
        return True
    return _folder_paths(operands[1:], kind)


def _folder_paths(paths: list[Value], kind) -> bool:
    """`_broad_paths`, or a folder on disk, or a glob (`*.py`), or - when the
    path is not on disk - a name with no file extension (`src`, `lib/x`):
    more than an agent's one edit."""
    if _broad_paths(paths):
        return True
    for p in paths:
        if p.startswith(":") or any(c in p for c in "*?["):
            return True
        found = kind(p)
        if found == "dir":
            return True
        if found == "file":
            continue
        last = p.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
        if "." not in last:
            return True
    return False


def _broad_paths(paths: list[Value]) -> bool:
    """A pathspec that reaches every file or a whole folder: `.`, `*`, `:/`,
    `src/`, or one known only at run time."""
    return any(p is None or p.rstrip("/") in ("", ".", "*", ":", ":/*", "./*") or p.startswith(":/")
               or p.endswith("/") or p in ("..", "../") for p in paths)


_HISTORY = re.compile(r"(^|/)\.git/?$|(^|/)\.claude/worktrees(/|$)|(^|/)\.git/(objects|refs)(/|$)")


def _as_shell_code(words: list[Value]) -> list[Value]:
    """`sh -c` with the words joined, as `watch` and `tmux` run them."""
    if not words:
        return []
    return ["sh", "-c", None if any(w is None for w in words) else " ".join(words)]


# A command inside a container or on another machine is judged from here: no
# path of this computer starts with it.
_REMOTE_CWD = "/boxdawn-remote/cwd"
_REMOTE_HOME = "/boxdawn-remote/home"
_SSH_VALUE_FLAGS = frozenset("BbcDEeFIiJLlmOopQRSWw")
_DOCKER_GLOBAL = {"-H", "--host", "-c", "--context", "--config", "-l", "--log-level",
                  "--tlscacert", "--tlscert", "--tlskey"}
_COMPOSE_GLOBAL = {"-f", "--file", "-p", "--project-name", "--project-directory", "--env-file",
                   "--profile", "--ansi", "--progress", "--parallel"}
_EXEC_VALUES = {"-e", "--env", "--env-file", "-u", "--user", "-w", "--workdir", "--detach-keys", "--index"}
_RUN_VALUES = _EXEC_VALUES | {"-l", "--label", "-p", "--publish", "-v", "--volume", "--entrypoint", "--name",
                              "--cap-add", "--cap-drop", "--env-from-file", "--pull"}
_KUBECTL_VALUES = {"-n", "--namespace", "--context", "--kubeconfig", "-s", "--server", "--cluster",
                   "--user", "--token", "-c", "--container", "-f", "--filename", "--pod-running-timeout",
                   "--as", "--as-group", "--request-timeout", "-v"}


def _strip_cluster(args: list[Value], takes_value: set[str]) -> list[Value]:
    """`_strip_options`, where a cluster ending in a letter that takes a
    value (`-itu root`) takes the next word, as Go's flag packages read it."""
    letters = {o[1] for o in takes_value if len(o) == 2}
    i = 0
    while i < len(args) and args[i] is not None and args[i].startswith("-"):
        a = args[i]
        i += 2 if a in takes_value or (not a.startswith("--") and len(a) > 2 and a[-1] in letters
                                         and all(c not in letters for c in a[1:-1])) else 1
    return args[i:]


_DOCKER_LIKE = {"podman": "docker", "podman-compose": "docker-compose"}


def _container_command(name: str, args: list[Value]) -> Optional[list[Value]]:
    """The words `docker exec`, `docker compose exec|run` or `kubectl exec`
    runs inside the container, as given (no shell). None: not one of these.
    podman takes docker's commands."""
    name = _DOCKER_LIKE.get(name, name)
    if name == "kubectl":
        rest = _strip_options(args, _KUBECTL_VALUES)
        if rest[:1] != ["exec"]:
            return None
        rest = rest[1:]
        if "--" in rest:
            return rest[rest.index("--") + 1:]
        return _strip_cluster(_strip_cluster(rest, _KUBECTL_VALUES)[1:], _KUBECTL_VALUES)  # after the pod
    if name == "docker":
        rest = _strip_options(args, _DOCKER_GLOBAL)
        if rest[:2] == ["container", "exec"]:
            rest = rest[1:]
        if rest[:1] == ["exec"]:
            return _strip_cluster(rest[1:], _EXEC_VALUES)[1:]  # the container
        if rest[:1] != ["compose"]:
            return None
        rest = rest[1:]
    elif name != "docker-compose":
        return None
    rest = _strip_options(rest if name == "docker" else args, _COMPOSE_GLOBAL)
    if rest[:1] not in (["exec"], ["run"]):
        return None
    sub = rest[0]
    rest = rest[1:]
    after = _strip_cluster(rest, _EXEC_VALUES if sub == "exec" else _RUN_VALUES)
    entry = _option_values(rest[:len(rest) - len(after)], ("--entrypoint",)) if sub == "run" else []
    if entry and entry[-1] is not None:
        entry = entry[-1].split()  # compose splits it into words
    return entry[-1:] if entry == [None] else entry + after[1:]  # after the service


def _exec_reads_stdin(name: str, args: list[Value], inner: list[Value]) -> bool:
    """`docker exec` and `kubectl exec` pass stdin on only with `-i`;
    `docker compose exec|run` pass it on unless told otherwise."""
    options = args[:len(args) - len(inner)]
    if _DOCKER_LIKE.get(name, name) == "docker-compose" or "compose" in options:
        return True
    return any(a is None or a in ("-i", "--interactive", "--stdin") or re.fullmatch(r"-[A-Za-z]*i[A-Za-z]*", a)
               or (a.startswith(("--interactive=", "--stdin=", "-i=")) and a.split("=", 1)[1].lower() != "false")
               for a in options)


_TMUX_RUNS = frozenset({"new", "new-session", "new-window", "neww", "split-window", "splitw",
                        "run-shell", "run", "respawn-pane", "respawnp", "respawn-window", "respawnw"})


def _tmux_command(args: list[Value]) -> list[Value]:
    """The shell command a tmux subcommand starts, if one is on the line."""
    rest = _strip_options(args, {"-L", "-S", "-f", "-T"})
    if not rest or rest[0] not in _TMUX_RUNS:
        return []
    words = _strip_options(rest[1:], {"-s", "-n", "-c", "-t", "-x", "-y", "-e", "-F", "-l", "-b"})
    return _as_shell_code(words)
