"""Signed command rules from the server: anything wrong means the fixed rules."""
from __future__ import annotations

import base64
import http.server
import json
import threading

import pytest

pytest.importorskip("tree_sitter_bash")
pytest.importorskip("cryptography")

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: E402

from boxdawn_guard import command_hook, rules_bundle  # noqa: E402
from boxdawn_guard.command_guard import evaluate  # noqa: E402
from boxdawn_guard.command_rules_source import default_command_rules  # noqa: E402
from boxdawn_guard.rules_bundle import (  # noqa: E402
    BundleError, fetch, load_rules, rules_from_dict, rules_to_dict, verify,
)

NOW = 1_800_000_000
KEY = Ed25519PrivateKey.generate()
OTHER = Ed25519PrivateKey.generate()


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _pub(key) -> str:
    return _b64(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))


KEYS = {"t1": _pub(KEY)}


def bundle(rules=None, *, key=KEY, kid="t1", inner_kid=None, kind="command_rules", v=1,
           exp=NOW + 3600, payload=None):
    body = {"v": v, "kind": kind, "kid": inner_kid or kid, "iat": NOW, "exp": exp, "fp": "x",
            "rules": rules_to_dict(rules or default_command_rules())}
    raw = payload if payload is not None else json.dumps(body, sort_keys=True).encode()
    return {"kid": kid, "payload": _b64(raw), "sig": _b64(key.sign(raw))}


def stricter():
    """The fixed rules plus one command that is always denied."""
    d = rules_to_dict(default_command_rules())
    d["always_deny"] = sorted(d["always_deny"] + ["frobnicate"])
    return rules_from_dict(d)


def looser():
    """The fixed rules without `shred`: a bundle can relax as well."""
    d = rules_to_dict(default_command_rules())
    d["always_deny"] = [x for x in d["always_deny"] if x != "shred"]
    return rules_from_dict(d)


def decision(command, rules):
    return evaluate(command, cwd="/w/p", home="/h", rules=rules).decision


# ── rules as data ───────────────────────────────────────────────────────────

def test_the_fixed_rules_round_trip():
    assert rules_from_dict(rules_to_dict(default_command_rules())) == default_command_rules()


@pytest.mark.parametrize("change", [
    lambda d: d.pop("shells"),
    lambda d: d.update(extra=[]),
    lambda d: d.update(shells="bash"),
    lambda d: d.update(shells=["bash", 3]),
    lambda d: d.update(code_flags=["-c"]),
    lambda d: d.update(db_destructive=["(unclosed"]),
    lambda d: d.update(inline_code_risky={"python": ["[bad"]}),
])
def test_malformed_rules_are_refused(change):
    d = rules_to_dict(default_command_rules())
    change(d)
    with pytest.raises(BundleError):
        rules_from_dict(d)


# ── verify ──────────────────────────────────────────────────────────────────

def test_a_good_bundle_gives_its_rules():
    assert verify(bundle(stricter()), KEYS, now=NOW) == stricter()


@pytest.mark.parametrize("make", [
    lambda: bundle(key=OTHER),                       # forged: signed with another key
    lambda: bundle(kid="k9"),                        # key id we do not pin
    lambda: bundle(inner_kid="k1"),                  # payload says another key
    lambda: bundle(kind="autofix_rules"),            # another kind of bundle
    lambda: bundle(v=2),
    lambda: bundle(exp=NOW),                         # expired
    lambda: bundle(exp="never"),
    lambda: bundle(payload=b"not json"),
    lambda: {**bundle(), "sig": "!!"},
    lambda: {**bundle(), "payload": _b64(b'{"v":1}')},  # payload swapped after signing
    lambda: "not an object",
])
def test_a_bad_bundle_is_refused(make):
    with pytest.raises(BundleError):
        verify(make(), KEYS, now=NOW)


def test_the_pinned_production_key_is_32_bytes():
    raw = base64.urlsafe_b64decode(rules_bundle.PUBLIC_KEYS["k1"])
    assert len(raw) == 32


# ── load ────────────────────────────────────────────────────────────────────

def _store(tmp_path, response):
    (tmp_path / "rules.json").write_text(json.dumps(response), encoding="utf-8")


def test_no_data_dir_or_no_file_is_the_fixed_rules(tmp_path):
    assert load_rules(None) == default_command_rules()
    assert load_rules(str(tmp_path)) == default_command_rules()


def test_a_stored_bundle_replaces_the_fixed_rules_both_ways(tmp_path):
    _store(tmp_path, bundle(stricter()))
    rules = load_rules(str(tmp_path), now=NOW, public_keys=KEYS)
    assert decision("frobnicate x", rules) == "deny"
    assert decision("frobnicate x", default_command_rules()) is None
    _store(tmp_path, bundle(looser()))
    rules = load_rules(str(tmp_path), now=NOW, public_keys=KEYS)
    assert decision("shred f", rules) is None
    assert decision("shred f", default_command_rules()) == "deny"


@pytest.mark.parametrize("content", [
    json.dumps(bundle(stricter(), key=OTHER)),
    json.dumps(bundle(stricter(), exp=NOW - 1)),
    "{broken",
    "",
])
def test_a_bad_stored_file_is_the_fixed_rules(tmp_path, content):
    (tmp_path / "rules.json").write_text(content, encoding="utf-8")
    assert load_rules(str(tmp_path), now=NOW, public_keys=KEYS) == default_command_rules()


def test_the_hook_uses_the_stored_bundle(tmp_path, monkeypatch):
    monkeypatch.setattr(rules_bundle, "PUBLIC_KEYS", KEYS)
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(tmp_path))
    payload = {"tool_name": "Bash", "tool_input": {"command": "frobnicate x"},
               "cwd": "/w/p", "permission_mode": "default"}
    assert command_hook.decide(payload) is None
    response = bundle(stricter(), exp=10**12)
    _store(tmp_path, response)
    assert command_hook.decide(payload)["hookSpecificOutput"]["permissionDecision"] == "deny"


# ── fetch ───────────────────────────────────────────────────────────────────

class _Server:
    def __init__(self):
        self.status, self.body, self.seen = 200, b"", []
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                n = int(self.headers.get("Content-Length") or 0)
                outer.seen.append((self.headers.get("Authorization"), self.rfile.read(n)))
                self.send_response(outer.status)
                self.end_headers()
                self.wfile.write(outer.body)

            def log_message(self, *a):
                pass

        self.httpd = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_port}/guard/rules"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()


@pytest.fixture
def server():
    s = _Server()
    yield s
    s.httpd.shutdown()


def _fetch(server, tmp_path, key="bdk_test"):
    return fetch(key, str(tmp_path), url=server.url, now=NOW, public_keys=KEYS)


def test_fetch_stores_a_good_bundle_and_sends_only_the_key(server, tmp_path):
    server.body = json.dumps(bundle(stricter())).encode()
    assert _fetch(server, tmp_path) == "stored"
    assert server.seen == [("Bearer bdk_test", b"{}")]
    assert load_rules(str(tmp_path), now=NOW, public_keys=KEYS) == stricter()


def test_fetch_keeps_the_stored_bundle_on_a_bad_answer(server, tmp_path):
    _store(tmp_path, bundle(stricter()))
    for status, body in [(200, json.dumps(bundle(key=OTHER)).encode()), (200, b"nope"), (500, b"")]:
        server.status, server.body = status, body
        assert _fetch(server, tmp_path).startswith(("bad bundle", "server error"))
        assert load_rules(str(tmp_path), now=NOW, public_keys=KEYS) == stricter()


@pytest.mark.parametrize("status", [401, 403])
def test_fetch_removes_the_stored_bundle_when_the_key_is_refused(server, tmp_path, status):
    _store(tmp_path, bundle(stricter()))
    server.status = status
    assert _fetch(server, tmp_path).startswith("refused")
    assert not (tmp_path / "rules.json").exists()


def test_fetch_keeps_the_stored_bundle_when_unreachable(tmp_path):
    _store(tmp_path, bundle(stricter()))
    result = fetch("bdk_test", str(tmp_path), url="http://127.0.0.1:9/guard/rules", now=NOW,
                   public_keys=KEYS, timeout=2)
    assert result.startswith("unreachable")
    assert (tmp_path / "rules.json").exists()


def test_no_key_makes_no_request(server, tmp_path):
    assert _fetch(server, tmp_path, key="") == "no key"
    assert server.seen == []
