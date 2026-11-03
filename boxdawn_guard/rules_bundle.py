"""Command rules from a signed server bundle, for customers with an API key.

Without a key nothing here touches the network: the guard runs on the fixed
rules in command_rules_source. With one, `fetch-rules` (run at session
start) asks the server for a signed bundle and stores it as it came; every
hook call then checks the signature and the expiry before using it, and
falls back to the fixed rules on anything wrong. A bundle replaces the fixed
rules as a whole. The request carries the API key only, no commands.

The signature covers the payload bytes as sent (no canonical-JSON step on
either side) and is checked before the payload is parsed. Ed25519, public
keys pinned here by key id. A bundle is valid for 7 days, so a customer who
cannot reach the server keeps the last rules for at most that long.
"""
from __future__ import annotations

import base64
import binascii
import dataclasses
import json
import os
import re
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from boxdawn_guard.command_guard import CommandRules, CustomRule
from boxdawn_guard.command_rules_source import default_command_rules

BUNDLE_VERSION = 1
KIND = "command_rules"
PUBLIC_KEYS = {"k1": "98OuUyiqGYKaDd_DtJr64BMfd0zPAaFxfsRpDvpGvYA="}
RULES_URL = "https://jeonsewon--boxdawn-analyzer-web.modal.run/guard/rules"
FILE_NAME = "rules.json"
# Runs in the background at session start, so a cold server (tens of
# seconds) does not hold the session up.
FETCH_TIMEOUT_SECONDS = 60


class BundleError(ValueError):
    """The bundle cannot be used; the fixed rules apply."""


# ── rules as data ───────────────────────────────────────────────────────────

_SETS = ("interpreters", "shells", "wrappers", "privilege", "source", "always_deny",
         "harmless_devices", "db_clients", "db_code_flags", "db_file_flags", "unattended_modes")
_TUPLES = ("always_deny_prefixes", "devices", "scratch_dirs")
_REGEX_TUPLES = ("db_destructive",)
_MAPS = ("code_flags",)
_REGEX_MAPS = ("inline_code_risky",)
_FIELDS = _SETS + _TUPLES + _REGEX_TUPLES + _MAPS + _REGEX_MAPS


def rules_to_dict(rules: CommandRules) -> dict:
    out: dict[str, Any] = {}
    for f in _SETS:
        out[f] = sorted(getattr(rules, f))
    for f in _TUPLES + _REGEX_TUPLES:
        out[f] = list(getattr(rules, f))
    for f in _MAPS:
        out[f] = {k: sorted(v) for k, v in sorted(getattr(rules, f).items())}
    for f in _REGEX_MAPS:
        out[f] = {k: list(v) for k, v in sorted(getattr(rules, f).items())}
    return out


def _strings(value: Any, field: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise BundleError(f"rules: {field} is not a list of strings")
    return value


def _regexes(value: Any, field: str) -> tuple[str, ...]:
    out = tuple(_strings(value, field))
    for pattern in out:
        try:
            re.compile(pattern)
        except re.error as exc:
            raise BundleError(f"rules: {field} has a bad pattern") from exc
    return out


def _map(value: Any, field: str) -> dict:
    if not isinstance(value, dict):
        raise BundleError(f"rules: {field} is not an object")
    return value


def rules_from_dict(data: Any) -> CommandRules:
    """Every field present and well-typed, nothing else — or BundleError."""
    if not isinstance(data, dict):
        raise BundleError("rules: not an object")
    if set(data) != set(_FIELDS):
        raise BundleError("rules: fields differ from this guard's")
    kw: dict[str, Any] = {}
    for f in _SETS:
        kw[f] = frozenset(_strings(data[f], f))
    for f in _TUPLES:
        kw[f] = tuple(_strings(data[f], f))
    for f in _REGEX_TUPLES:
        kw[f] = _regexes(data[f], f)
    for f in _MAPS:
        kw[f] = {k: frozenset(_strings(v, f)) for k, v in _map(data[f], f).items()}
    for f in _REGEX_MAPS:
        kw[f] = {k: _regexes(v, f) for k, v in _map(data[f], f).items()}
    return CommandRules(**kw)


_CUSTOM_KEYS = {"id", "level", "command", "args", "flags", "note"}
_CUSTOM_MAX = 100  # the server's limit per org (0032)
_COMMAND = re.compile(r"[A-Za-z0-9._+-]{1,64}")
_WORD = re.compile(r"[^\s\x00-\x1f\x7f]{1,128}")


def custom_from_list(data: Any) -> tuple[CustomRule, ...]:
    """The org's rules (`custom` beside `rules`), checked the way the server
    stores them (0032), or BundleError. A bundle from before them has none."""
    if data is None:
        return ()
    if not isinstance(data, list) or len(data) > _CUSTOM_MAX:
        raise BundleError("custom: not a list of at most 100")
    out = []
    for r in data:
        if not isinstance(r, dict) or set(r) != _CUSTOM_KEYS:
            raise BundleError("custom: a rule has other fields")
        args, flags, note = r["args"], r["flags"], r["note"]
        ok = (isinstance(r["id"], str) and re.fullmatch(r"r[0-9]{1,18}", r["id"])
              and r["level"] in ("ask", "deny")
              and isinstance(r["command"], str) and _COMMAND.fullmatch(r["command"])
              and isinstance(args, list) and len(args) <= 8
              and all(isinstance(a, str) and _WORD.fullmatch(a) and not a.startswith("-") for a in args)
              and isinstance(flags, list) and len(flags) <= 8
              and all(isinstance(f, str) and _WORD.fullmatch(f) and f.startswith("-") for f in flags)
              and isinstance(note, str) and len(note) <= 120
              and not re.search(r"[\x00-\x1f\x7f]", note))
        if not ok:
            raise BundleError("custom: a rule is malformed")
        command = r["command"].lower()
        if command.endswith(".exe"):
            command = command[:-4]
        out.append(CustomRule(r["id"], r["level"], command, tuple(args), tuple(flags), note))
    return tuple(out)


# ── the bundle ──────────────────────────────────────────────────────────────

def _b64url(text: Any) -> bytes:
    if not isinstance(text, str) or not text:
        raise BundleError("bundle: field is not a string")
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError) as exc:
        raise BundleError("bundle: field is not base64url") from exc


def verify(response: Any, public_keys: Mapping[str, str] | None = None, *,
           now: float) -> CommandRules:
    """The rules inside `response`, or BundleError. Nothing in the payload is
    read before its signature is checked against a pinned key."""
    return _verified(response, public_keys, now=now)[0]


def _verified(response: Any, public_keys: Mapping[str, str] | None, *,
              now: float) -> tuple[CommandRules, int]:
    public_keys = PUBLIC_KEYS if public_keys is None else public_keys
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    if not isinstance(response, dict):
        raise BundleError("bundle: not an object")
    kid = response.get("kid")
    if not isinstance(kid, str) or kid not in public_keys:
        raise BundleError("bundle: unknown key id")
    payload = _b64url(response.get("payload"))
    signature = _b64url(response.get("sig"))
    try:
        Ed25519PublicKey.from_public_bytes(_b64url(public_keys[kid])).verify(signature, payload)
    except InvalidSignature as exc:
        raise BundleError("bundle: signature does not verify") from exc
    try:
        body = json.loads(payload)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise BundleError("bundle: payload is not JSON") from exc
    if not isinstance(body, dict) or body.get("v") != BUNDLE_VERSION:
        raise BundleError("bundle: unknown version")
    # Signed inside, so another kind of bundle (the autofix rules) or a
    # payload signed under another key cannot be passed off as this one.
    if body.get("kind") != KIND:
        raise BundleError("bundle: not a command rules bundle")
    if body.get("kid") != kid:
        raise BundleError("bundle: key id mismatch")
    exp = body.get("exp")
    if not isinstance(exp, int) or isinstance(exp, bool):
        raise BundleError("bundle: no expiry")
    if now >= exp:
        raise BundleError("bundle: expired")
    rules = rules_from_dict(body.get("rules"))
    return dataclasses.replace(rules, custom=custom_from_list(body.get("custom"))), exp


def load_rules(data_dir: str | None, *, now: float | None = None,
               public_keys: Mapping[str, str] | None = None) -> CommandRules:
    """The stored bundle's rules if it is there and good, else the fixed rules."""
    return load_stored(data_dir, now=now, public_keys=public_keys)[0]


def load_stored(data_dir: str | None, *, now: float | None = None,
                public_keys: Mapping[str, str] | None = None) -> tuple[CommandRules, int | None]:
    """(rules, the bundle's expiry) from a good stored bundle, else (the fixed
    rules, None). The expiry says the call is judged on a paid bundle."""
    if data_dir:
        path = Path(data_dir) / FILE_NAME
        if path.is_file():
            try:
                return _verified(json.loads(path.read_text(encoding="utf-8")), public_keys,
                                 now=time.time() if now is None else now)
            except (BundleError, OSError, ValueError):
                pass
    return default_command_rules(), None


# ── fetching (session start) ────────────────────────────────────────────────

def fetch(api_key: str | None, data_dir: str | None, *, url: str = RULES_URL,
          now: float | None = None, timeout: float = FETCH_TIMEOUT_SECONDS,
          public_keys: Mapping[str, str] | None = None) -> str:
    """Store a fresh bundle; returns what happened, for the log line.

    A refused key (401/403) deletes the stored bundle and the block record,
    so a revoked key or a plan that no longer includes this stops at the
    next session. A network
    failure keeps it: it is still good until its own expiry.
    """
    if not api_key or not data_dir:
        return "no key"
    # Here, not at the top: every hook call imports this module, and ssl is
    # slow to load.
    import tempfile
    import urllib.error
    import urllib.request

    path = Path(data_dir) / FILE_NAME
    req = urllib.request.Request(url, data=b"{}", method="POST", headers={
        "Authorization": f"Bearer {api_key}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed https URL
            raw = resp.read()
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            path.unlink(missing_ok=True)
            from boxdawn_guard import block_log
            block_log.remove(data_dir)
            return f"refused ({exc.code}); stored bundle and block record removed"
        return f"server error ({exc.code}); kept stored bundle"
    except (urllib.error.URLError, OSError) as exc:
        return f"unreachable ({type(exc).__name__}); kept stored bundle"
    try:
        verify(json.loads(raw), public_keys, now=time.time() if now is None else now)
    except (BundleError, ValueError) as exc:
        return f"bad bundle ({exc}); kept stored bundle"
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".rules.")
    with os.fdopen(fd, "wb") as f:
        f.write(raw)
    os.replace(tmp, path)
    return "stored"
