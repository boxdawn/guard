"""Judge a PowerShell command before it runs: deny, ask, or no decision.

The PowerShell tool of Claude Code is on by default on Windows and is the
primary shell there; without Git Bash there is no Bash tool at all (Claude
Code docs, tools-reference "PowerShell tool", 2026-10-30). On 263 PowerShell
commands from real Claude Code sessions, tree-sitter-powershell 0.26.4 could
not read 47; PowerShell's own parser could not read 1.

The command is read by PowerShell's own parser (packaging/psparse, a small
helper built against Windows PowerShell 5.1). This module turns what it sees
into the same rule IDs and the same principles as command_guard: an unknown
value is never a safe one, a parse error asks, unattended turns ask into
deny. Native programs (git, terraform, python -c, bash -c …) go to the Bash
judge's handlers unchanged.
"""
from __future__ import annotations

import base64
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Callable, Optional

from boxdawn_guard import secret_files
from boxdawn_guard.command_guard import (
    CommandRules, Value, Verdict, _MAX_DEPTH, _Judge, _code_or_file,
)

Parse = Callable[[str], dict]


class HelperMissing(Exception):
    pass


def _helper() -> Optional[Path]:
    env = os.environ.get("BDX_PSPARSE")
    if env:
        return Path(env)
    if getattr(sys, "frozen", False):
        return Path(sys.executable).with_name("bdxpsparse.exe")
    return None


def parse(command: str) -> dict:
    exe = _helper()
    if exe is None or not exe.is_file():
        raise HelperMissing(str(exe))
    p = subprocess.run([str(exe)], input=command.encode("utf-8"), capture_output=True,
                       timeout=20, check=True)
    return json.loads(p.stdout.decode("utf-8"))


# ── what PowerShell names mean ──────────────────────────────────────────────

_ALIASES = {
    "rm": "remove-item", "del": "remove-item", "erase": "remove-item", "rd": "remove-item",
    "ri": "remove-item", "rmdir": "remove-item",
    "clc": "clear-content", "sc": "set-content", "tee": "tee-object",
    "iex": "invoke-expression", "start": "start-process", "saps": "start-process",
    "cd": "set-location", "sl": "set-location", "chdir": "set-location",
    "pushd": "push-location",
    "cp": "copy-item", "copy": "copy-item", "cpi": "copy-item",
    "mv": "move-item", "move": "move-item", "mi": "move-item", "ni": "new-item",
}

_V, _S = True, False  # takes a value / is a switch
_COMMON = {
    "verbose": _S, "debug": _S, "erroraction": _V, "warningaction": _V,
    "informationaction": _V, "errorvariable": _V, "warningvariable": _V,
    "informationvariable": _V, "outvariable": _V, "outbuffer": _V,
    "pipelinevariable": _V, "progressaction": _V, "whatif": _S, "confirm": _S,
}
_COMMON_ALIASES = {
    "vb": "verbose", "db": "debug", "ea": "erroraction", "wa": "warningaction",
    "infa": "informationaction", "ev": "errorvariable", "wv": "warningvariable",
    "iv": "informationvariable", "ov": "outvariable", "ob": "outbuffer",
    "pv": "pipelinevariable", "proga": "progressaction", "wi": "whatif", "cf": "confirm",
}
_VARIABLE_PARAMS = frozenset({"errorvariable", "warningvariable", "informationvariable",
                              "outvariable", "pipelinevariable"})
_PATHS = {"path": _V, "literalpath": _V, "filter": _V, "include": _V, "exclude": _V,
          "force": _S, "credential": _V, "stream": _V}
_PATH_ALIASES = {"pspath": "literalpath", "lp": "literalpath"}

# name -> (parameters, aliases, positional order)
_SPECS: dict[str, tuple[dict, dict, tuple]] = {
    "remove-item": ({**_PATHS, "recurse": _S}, _PATH_ALIASES, ("path",)),
    "clear-content": (_PATHS, _PATH_ALIASES, ("path",)),
    "set-content": ({**_PATHS, "value": _V, "encoding": _V, "nonewline": _S, "passthru": _S,
                     "asbytestream": _S}, _PATH_ALIASES, ("path", "value")),
    "out-file": ({"filepath": _V, "literalpath": _V, "encoding": _V, "append": _S, "force": _S,
                  "noclobber": _S, "width": _V, "nonewline": _S, "inputobject": _V},
                 {"path": "filepath", "pspath": "literalpath", "lp": "literalpath",
                  "nooverwrite": "noclobber"}, ("filepath", "encoding")),
    "tee-object": ({"filepath": _V, "literalpath": _V, "append": _S, "variable": _V,
                    "inputobject": _V, "encoding": _V},
                   {"path": "filepath", "pspath": "literalpath", "lp": "literalpath"}, ("filepath",)),
    "invoke-expression": ({"command": _V}, {}, ("command",)),
    "start-process": ({"filepath": _V, "argumentlist": _V, "verb": _V, "workingdirectory": _V,
                       "credential": _V, "loaduserprofile": _S, "nonewwindow": _S, "passthru": _S,
                       "redirectstandarderror": _V, "redirectstandardinput": _V,
                       "redirectstandardoutput": _V, "windowstyle": _V, "wait": _S,
                       "usenewenvironment": _S, "environment": _V},
                      {"pspath": "filepath", "path": "filepath", "args": "argumentlist",
                       "lup": "loaduserprofile", "nnw": "nonewwindow",
                       "rse": "redirectstandarderror", "rsi": "redirectstandardinput",
                       "rso": "redirectstandardoutput"}, ("filepath", "argumentlist")),
    "set-location": ({"path": _V, "literalpath": _V, "passthru": _S, "stackname": _V},
                     _PATH_ALIASES, ("path",)),
    "push-location": ({"path": _V, "literalpath": _V, "passthru": _S, "stackname": _V},
                      _PATH_ALIASES, ("path",)),
    "copy-item": ({**_PATHS, "destination": _V, "recurse": _S, "container": _S, "passthru": _S,
                   "fromsession": _V, "tosession": _V}, _PATH_ALIASES, ("path", "destination")),
    "move-item": ({**_PATHS, "destination": _V, "passthru": _S}, _PATH_ALIASES,
                  ("path", "destination")),
    "new-item": ({"path": _V, "name": _V, "itemtype": _V, "value": _V, "force": _S,
                  "credential": _V}, {"type": "itemtype", "target": "value"}, ("path",)),
}
_DESTROYERS = frozenset({"format-volume", "clear-disk", "initialize-disk", "remove-partition"})
# Anything of these anywhere: a variable may change unseen.
_REASSIGNS = frozenset({"set-variable", "new-variable", "remove-variable", "clear-variable",
                        "invoke-expression"})
# These set a variable only through the `variable:` drive.
_ITEMS = frozenset({"new-item", "set-item", "remove-item", "clear-item", "rename-item",
                    "copy-item", "move-item"})
_SELF = frozenset({"powershell", "pwsh"})
_HARMLESS = frozenset({"nul", "$null"})


# ── evaluate ────────────────────────────────────────────────────────────────

def evaluate_powershell(command: str, *, cwd: str, home: str, rules: CommandRules,
                        unattended: bool = False, known_env: dict[str, str] | None = None,
                        parse: Parse = parse) -> Optional[Verdict]:
    """None when there is no PowerShell parser on this machine and it is not
    Windows (the PowerShell tool is opt-in elsewhere)."""
    judge = _Judge(cwd=cwd, home=home, rules=rules, known_env=dict(known_env or {}))
    ps = _PowerShell(judge, parse, {k.lower(): v for k, v in (known_env or {}).items()}, home)
    try:
        ps.run(command, 0)
    except HelperMissing:
        if os.name != "nt":
            return None
        judge.flag("ask", "guard.crashed", "the PowerShell reader of this guard is missing")
    except Exception as exc:  # noqa: BLE001 - a guard that crashes must not pass
        judge.flag("ask", "guard.crashed", f"the guard could not read this command ({type(exc).__name__})")
    decision = judge.decision
    escalated = unattended and decision == "ask"
    if escalated:
        decision = "deny"
        judge.reasons.append("nobody is present to approve it")
    return Verdict(decision, tuple(judge.reasons), tuple(judge.findings), escalated)


class _PowerShell:
    def __init__(self, judge: _Judge, parse: Parse, known_env: dict, home: str) -> None:
        self.j, self.parse, self.known_env, self.home = judge, parse, known_env, home
        self.env: dict[str, list] = {}

    def run(self, text: str, depth: int) -> None:
        j = self.j
        if depth > _MAX_DEPTH:
            j.flag("ask", "parse.too_deep", "commands nested too deep to read")
            return
        tree = self.parse(text)
        if tree["errors"]:
            j.flag("ask", "parse.unreadable", "the PowerShell syntax could not be read")
        outer = (self.env, j.workdirs)
        commands = tree["commands"]
        self.env = self._collect_env(tree)
        j.workdirs = self._collect_workdirs(commands)
        try:
            fed_a_secret = listed_a_secret = False
            for c in commands:
                self._command(c, depth)
                name = _canonical(c["name"])
                if name is None:
                    continue
                piped = c["pipe_index"] > 0
                fed_a_secret, listed_a_secret = fed_a_secret and piped, listed_a_secret and piped
                args = self._native_args(c)
                if fed_a_secret and name in secret_files.SENDERS:
                    j.flag("deny", "secret.send", f"`{c['name']}` sends a secret file out through a pipe")
                if listed_a_secret and name not in secret_files.METADATA_ONLY:
                    j.flag("ask", "secret.read", f"`{c['name']}` is handed a secret file down the pipe")
                fed_a_secret = fed_a_secret or bool(j._named_secrets(name, args))
                listed_a_secret = listed_a_secret or (name in secret_files.METADATA_ONLY and any(
                    a is not None and not a.startswith("-") and j._is_secret(a) for a in args))
            for w in tree["writes"]:
                if not w["append"]:
                    self._writes(self._value(w["to"], w["start"]), "output")
        finally:
            self.env, j.workdirs = outer

    # values ─────────────────────────────────────────────────────────────
    def _collect_env(self, tree: dict) -> dict:
        """Only `$x = …` as a top-level statement holds; any other way of
        setting a name (nested, +=, foreach, ++, -OutVariable) leaves it
        unknown, and a command that can set any name clears them all."""
        for c in tree["commands"]:
            name = _canonical(c["name"])
            if name in _REASSIGNS or c["op"] == "Dot":
                return {}
            for e in c["elems"]:
                if "p" in e and _resolve_param(e["p"], {}, {}) in _VARIABLE_PARAMS:
                    return {}
        poisoned = {a["var"].lower() for a in tree["assignments"]
                    if a["var"] and not (a["top"] and a["op"] == "Equals")}
        if any(a["var"] is None for a in tree["assignments"]):
            return {}
        env: dict[str, list] = {"home": [(-1, self.home)]}
        for k, v in self.known_env.items():
            env["env:" + k] = [(-1, v)]
        for a in sorted(tree["assignments"], key=lambda a: a["pos"]):
            name = a["var"].lower()
            if name in poisoned or not (a["top"] and a["op"] == "Equals"):
                continue
            env.setdefault(name, []).append((a["pos"], self._value_in(a["value"], a["pos"], env)))
        for name in poisoned:
            env.pop(name, None)
        for c in tree["commands"]:
            if _canonical(c["name"]) not in _ITEMS:
                continue
            for e in c["elems"]:
                parts = [] if "p" in e else e.get("vs", [e.get("v")]) if "splat" not in e else [None]
                values = [self._value_in(v, c["start"], env) for v in parts]
                if any(v is None or v.lower().startswith("variable:") for v in values):
                    return {}
        return env

    def _value_in(self, parts, at: int, env: dict) -> Value:
        if parts is None:
            return None
        if len(parts) == 1 and isinstance(parts[0], dict) and parts[0]["var"].lower() == "null":
            return "$null"
        out = []
        for p in parts:
            if isinstance(p, str):
                out.append(p)
                continue
            name = p["var"].lower()
            if name == "null":
                continue
            seen = [v for pos, v in env.get(name, []) if pos < at]
            if not seen or seen[-1] is None:
                return None
            out.append(seen[-1])
        return "".join(out)

    def _value(self, parts, at: int) -> Value:
        return self._value_in(parts, at, self.env)

    def _elem_values(self, e: dict, at: int) -> list[Value]:
        if "vs" in e:
            return [self._value(v, at) for v in e["vs"]]
        if "splat" in e:
            return [None]
        return [self._value(e.get("v"), at)]

    def _native_args(self, c: dict) -> list[Value]:
        out: list[Value] = []
        for e in c["elems"]:
            if "p" in e:
                out.append(e["raw"] if "a" not in e else None)
            else:
                out.extend(_native_path(v) for v in self._elem_values(e, c["start"]))
        return out

    # binding ────────────────────────────────────────────────────────────
    def _bind(self, c: dict, name: str) -> dict:
        """Parameter name -> list of values, or True/False for a switch."""
        params, aliases, positional = _SPECS[name]
        bound: dict = {}
        free: list[list[Value]] = []  # one entry per argument; `a, b` is one
        elems = c["elems"]
        i = 0
        while i < len(elems):
            e = elems[i]
            i += 1
            if "p" not in e:
                free.append(self._elem_values(e, c["start"]))
                continue
            canon = _resolve_param(e["p"], params, aliases)
            if canon is None:
                continue  # PowerShell refuses an unknown or ambiguous name
            takes = params.get(canon, _COMMON.get(canon))
            if takes:
                if "a" in e:
                    bound.setdefault(canon, []).append(self._value(e["a"], c["start"]))
                elif i < len(elems) and "p" not in elems[i]:
                    bound.setdefault(canon, []).extend(self._elem_values(elems[i], c["start"]))
                    i += 1
            else:
                bound[canon] = not _is_false(e.get("a"))
        slots = [p for p in positional if p not in bound]
        if free and slots:
            # A single open slot takes every argument (`rm a b`); with more,
            # each slot takes one argument, which may be an array (`cp a, b dest`).
            if len(slots) == 1:
                bound[slots[0]] = [v for group in free for v in group]
            else:
                for slot, group in zip(slots, free):
                    bound[slot] = group
        return bound

    def _collect_workdirs(self, commands: list) -> list:
        j = self.j
        dirs = [j.cwd]
        for c in commands:
            name = _canonical(c["name"])
            if name not in ("set-location", "push-location"):
                continue
            b = self._bind(c, name)
            targets = b.get("path") or b.get("literalpath")
            if not targets:
                dirs.append(j.home)
                continue
            t = _native_path(targets[0])
            if t is None or _provider(t):
                dirs.append(None)
            else:
                dirs += [j._absolute(t, j.cwd), j._absolute(t, dirs[-1] or j.cwd)]
        return dirs

    # commands ───────────────────────────────────────────────────────────
    def _command(self, c: dict, depth: int) -> None:
        j = self.j
        raw = c["name"]
        if raw is None and c.get("head_v") is not None:
            raw = _native_path(self._value(c["head_v"], c["start"]))  # `& $exe` with $exe known
        if raw is None:
            if c["op"] in ("Ampersand", "Dot") and c.get("head") == "ScriptBlockExpressionAst":
                return  # `& { … }`: the commands inside are judged on their own
            j.flag("ask", "name.runtime", "the command name is only known at run time")
            return
        name = _canonical(raw)
        if c["op"] == "Dot":
            j.flag("ask", "source.script", f"`. {raw}` runs a script file in this shell")
            return
        if name in _DESTROYERS:
            j.flag("deny", "destroy.by_design", f"`{raw}` destroys data by design")
            return
        if name in _SPECS:
            b = self._bind(c, name)
            if b.get("whatif") is True:
                return
            j._secret_args(name, self._native_args(c))
            getattr(self, "_" + name.replace("-", "_"))(c, b, raw, depth)
            return
        # Any other cmdlet has no handler there and gets no decision.
        self._native(name, self._native_args(c), c, depth)

    def _native(self, name: str, args: list[Value], c: Optional[dict], depth: int) -> None:
        j = self.j
        fed = c is not None and c["pipe_index"] > 0
        text = None
        if fed and c.get("pipe_from_text") not in (None, False):
            text = self._value(c["pipe_from_text"], c["start"])
        if name in _SELF:
            self._powershell_exe(args, fed, text, depth)
            return
        if name == "cmd":
            code = _after(args, ("/c", "/k", "/r"))
            if code is not False:
                if code is None:
                    j.flag("ask", "code.runtime", "`cmd` runs code known only at run time")
                else:
                    j._scan_code("cmd", code)
            return
        if fed and name in j.rules.interpreters and not _code_or_file(name, args, j.rules):
            if c.get("pipe_from_text") is False:
                j.flag("ask", "pipe.into_interpreter", f"output of another command is run as `{name}` code")
                return
            j._judge(name, args, depth, stdin_fed=True, stdin_text=text)
            return
        j._judge(name, args, depth)

    def _powershell_exe(self, args: list[Value], fed: bool, text: Value, depth: int) -> None:
        j = self.j
        lowered = [a.lower() if a else a for a in args]
        for i, a in enumerate(lowered):
            if a is None:
                continue
            flag = a.lstrip("-/")
            if a[:1] not in "-/" or not flag:
                return  # a script file: what it runs is not on the line
            if "command".startswith(flag) and flag.startswith("c"):
                rest = args[i + 1:]
                if any(r is None for r in rest):
                    j.flag("ask", "code.runtime", "`powershell` runs code known only at run time")
                elif rest == ["-"] or not rest:
                    if fed:
                        self._run_or_ask(text, depth)
                else:
                    self.run(" ".join(rest), depth + 1)
                return
            if flag in ("e", "ec") or ("encodedcommand".startswith(flag) and flag.startswith("en")):
                code = args[i + 1] if i + 1 < len(args) else None
                try:
                    decoded = None if code is None else base64.b64decode(code).decode("utf-16-le")
                except ValueError:
                    decoded = None
                self._run_or_ask(decoded, depth)
                return
            if flag in ("file", "f"):
                return
        if fed:
            self._run_or_ask(text, depth)

    def _run_or_ask(self, code: Value, depth: int) -> None:
        if code is None:
            self.j.flag("ask", "code.runtime", "`powershell` runs code known only at run time")
        else:
            self.run(code, depth + 1)

    def _where(self, target: Value, removes_link: bool = False) -> str:
        t = _native_path(target)
        if t is None:
            return "unknown"
        if _provider(t):
            return "outside"
        if re.match(r"^[A-Za-z]:(?![\\/])", t) and len(t) > 2:
            return "unknown"  # C:file is relative to that drive's own current directory
        return self.j._where(t, removes_link)

    def _writes(self, target: Value, what: str) -> None:
        j = self.j
        if target is not None and target.lower() in _HARMLESS:
            return
        where = self._where(target)
        if where == "unknown":
            j.flag("ask", "redirect.runtime", f"{what} is written to a path known only at run time", "unknown")
        elif where == "outside":
            j.flag("ask", "redirect.outside", f"{what} is written to `{target}` outside the project", "outside")

    # cmdlet handlers ────────────────────────────────────────────────────
    def _targets(self, c: dict, b: dict, *names: str) -> list[Value]:
        out: list[Value] = []
        for n in names:
            out.extend(b.get(n) or [])
        if not out and c["pipe_index"] > 0:
            out = [None]  # the paths come down the pipe
        return out

    def _remove_item(self, c, b, raw, depth) -> None:
        j = self.j
        hard = b.get("recurse") is True or b.get("force") is True
        for t in self._targets(c, b, "path", "literalpath"):
            # `-Include` deletes what matches inside the link, not the link.
            where = self._where(t, removes_link=b.get("include") is None)
            if where == "unknown":
                j.flag("deny" if hard else "ask", "rm.runtime",
                       f"`{raw}` target is known only at run time", "unknown")
            elif where == "outside":
                j.flag("deny" if hard else "ask", "rm.outside",
                       f"`{raw}` reaches outside the project: `{t}`", "outside")
            elif where == "cwd" and hard:
                j.flag("ask", "rm.project_root", f"`{raw}` removes the whole project directory", "project_root")

    def _clear_content(self, c, b, raw, depth) -> None:
        j = self.j
        for t in self._targets(c, b, "path", "literalpath"):
            where = self._where(t)
            if where in ("outside", "unknown"):
                j.flag("deny", "truncate.outside", f"`{raw}` empties a file outside the project: `{t}`", where)
            else:
                j.flag("ask", "truncate.file", f"`{raw}` empties a file", where)

    def _set_content(self, c, b, raw, depth) -> None:
        for t in self._targets(c, b, "path", "literalpath"):
            self._writes(t, f"`{raw}` output")

    def _out_file(self, c, b, raw, depth) -> None:
        if b.get("append") is True or b.get("noclobber") is True:
            return
        for t in (b.get("filepath") or []) + (b.get("literalpath") or []):
            self._writes(t, f"`{raw}` output")

    def _tee_object(self, c, b, raw, depth) -> None:
        self._out_file(c, b, raw, depth)

    def _copy_item(self, c, b, raw, depth) -> None:
        # Copy-Item replaces a file already at the destination.
        self._replaces(b, raw, "cp.outside")

    def _move_item(self, c, b, raw, depth) -> None:
        j = self.j
        for t in self._targets(c, b, "path", "literalpath"):
            if (where := self._where(t)) in ("outside", "unknown"):
                said = "a path known only at run time" if t is None else f"`{t}` outside the project"
                j.flag("ask", "mv.outside", f"`{raw}` takes away {said}", where)
        if b.get("force") is True:  # without -Force it refuses to replace a file
            self._replaces(b, raw, "mv.outside")

    def _replaces(self, b, raw, rule: str) -> None:
        j = self.j
        for t in b.get("destination") or ["."]:
            if (where := self._where(t)) not in ("outside", "unknown"):
                continue
            said = "a path known only at run time" if t is None else f"`{t}` outside the project"
            if rule == "cp.outside":
                j.flag("ask", "cp.outside", f"`{raw}` writes over {said}", where)
            else:
                j.flag("ask", "mv.outside", f"`{raw}` writes over {said}", where)

    def _new_item(self, c, b, raw, depth) -> None:
        """`New-Item -Force` replaces a file (or registry key) already there;
        a directory already there is kept."""
        kind = (b.get("itemtype") or ["File"])[0]
        names = b.get("name")
        if kind and ("symboliclink".startswith(kind.lower()) or "junction".startswith(kind.lower())):
            for p in self._targets(c, b, "path") or ["."]:
                t = _native_path(p if not names or p is None or names[0] is None else p.rstrip("/\\") + "/" + names[0])
                if t is not None:
                    self.j.made_links.extend(self.j._absolute(t, base or self.j.cwd) for base in self.j.workdirs)
        if b.get("force") is not True:
            return
        if kind is not None and kind.lower() == "directory":
            return
        for p in self._targets(c, b, "path") or ["."]:
            t = p
            if names:
                t = None if p is None or names[0] is None else p.rstrip("/\\") + "/" + names[0]
            if (where := self._where(t)) in ("outside", "unknown"):
                said = "a path known only at run time" if t is None else f"`{t}` outside the project"
                self.j.flag("ask", "new_item.force_outside", f"`{raw} -Force` replaces {said}", where)

    def _invoke_expression(self, c, b, raw, depth) -> None:
        code = b.get("command")
        if code:
            text = code[0]
        elif c["pipe_index"] > 0 and c.get("pipe_from_text") not in (None, False):
            text = self._value(c["pipe_from_text"], c["start"])
        else:
            text = None
        if text is None:
            self.j.flag("ask", "eval.runtime", f"`{raw}` runs text known only at run time")
        else:
            self.run(text, depth + 1)

    def _start_process(self, c, b, raw, depth) -> None:
        j = self.j
        verb = (b.get("verb") or [""])[0]
        if verb is None or verb.lower() == "runas":
            j.flag("ask", "privilege.elevated", f"`{raw}` may run a program with more rights")
        files = b.get("filepath") or [None]
        program = _native_path(files[0])
        if program is None:
            j.flag("ask", "name.runtime", "the command name is only known at run time")
            return
        args: list[Value] = []
        for a in b.get("argumentlist") or []:
            args.extend([None] if a is None else a.split())
        self._native(_canonical(program), [_native_path(a) for a in args], None, depth)

    def _set_location(self, c, b, raw, depth) -> None:
        pass  # read by _collect_workdirs

    _push_location = _set_location


def _canonical(name: Optional[str]) -> Optional[str]:
    if name is None:
        return None
    # `C:\tools\git.exe` and `Microsoft.PowerShell.Management\Remove-Item` alike
    n = name.replace("/", "\\").rpartition("\\")[2].lower()
    if n.endswith(".exe"):
        n = n[:-4]
    return _ALIASES.get(n, n)


def _is_false(arg) -> bool:
    """`-Recurse:$false`."""
    return bool(arg) and len(arg) == 1 and isinstance(arg[0], dict) and arg[0]["var"].lower() == "false"


def _resolve_param(given: str, params: dict, aliases: dict) -> Optional[str]:
    g = given.lower()
    names = {**{p: p for p in params}, **aliases, **{p: p for p in _COMMON}, **_COMMON_ALIASES}
    if g in names:
        return names[g]
    hits = {names[n] for n in names if n.startswith(g)}
    return hits.pop() if len(hits) == 1 else None


def _provider(path: str) -> bool:
    """HKLM:\\…, Env:…, Cert:\\…, Registry::… — not the file system."""
    if "::" in path:
        return not re.match(r"^(Microsoft\.PowerShell\.Core\\)?FileSystem::", path, re.I)
    m = re.match(r"^([A-Za-z][\w.]*):", path)
    return bool(m) and len(m.group(1)) > 1


def _native_path(v: Value) -> Value:
    """`..\\x` -> `../x` for the path checks; text with spaces or shell
    characters (code, messages) is left as it is."""
    if v is None:
        return None
    m = re.match(r"^(?:Microsoft\.PowerShell\.Core\\)?FileSystem::(.*)$", v, re.I)
    if m:
        v = m.group(1)
    if "\\" in v and not re.search(r"[\s'\"`$;|&<>(){}]", v):
        return v.replace("\\", "/")
    return v


def _after(args: list[Value], flags: tuple) -> Value | bool:
    """The text after the first of `flags` (joined), None if unknown, False if absent."""
    for i, a in enumerate(args):
        if a is not None and a.lower() in flags:
            rest = args[i + 1:]
            return None if any(r is None for r in rest) else " ".join(rest)
    return False
