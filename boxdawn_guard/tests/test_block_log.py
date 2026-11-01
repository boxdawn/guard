"""The local block record: only on a paid bundle, only deny/ask, closed values only."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time

import pytest

pytest.importorskip("tree_sitter_bash")
pytest.importorskip("cryptography")

from boxdawn_guard import block_log, command_hook, rules_bundle  # noqa: E402
from boxdawn_guard.command_guard import RULE_IDS, TARGETS, Finding, Verdict  # noqa: E402
from boxdawn_guard.tests.test_rules_bundle import (  # noqa: E402
    KEYS, NOW, _fetch, _store, bundle, server,  # noqa: F401 - server is a fixture
)

SECRET_PATH = "/home/me/clients/acme-secret"
SECRET_VALUE = "hunter2-PGPASSWORD"


def _payload(command, mode="default", tool="Bash"):
    return {"tool_name": tool, "tool_input": {"command": command},
            "cwd": "/work/proj", "permission_mode": mode}


def _lines(data_dir):
    folder = data_dir / block_log.LOG_DIR
    if not folder.is_dir():
        return []
    return [json.loads(x) for p in sorted(folder.glob("blocks-*.jsonl"))
            for x in p.read_text(encoding="ascii").splitlines() if x]


@pytest.fixture
def paid(tmp_path, monkeypatch):
    """A data folder with a good stored bundle, as for a paying customer."""
    monkeypatch.setattr(rules_bundle, "PUBLIC_KEYS", KEYS)
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(tmp_path))
    _store(tmp_path, bundle(exp=10**12))
    return tmp_path


def test_the_fixed_rules_write_nothing(tmp_path, monkeypatch):
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(tmp_path))
    assert command_hook.decide(_payload("rm -rf /")) is not None
    assert command_hook.decide(_payload("git reset --hard HEAD~3")) is not None
    assert not (tmp_path / block_log.LOG_DIR).exists()


def test_an_expired_bundle_writes_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr(rules_bundle, "PUBLIC_KEYS", KEYS)
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(tmp_path))
    _store(tmp_path, bundle(exp=int(time.time()) - 1))
    assert command_hook.decide(_payload("rm -rf /")) is not None
    assert not (tmp_path / block_log.LOG_DIR).exists()


def test_a_deny_and_an_ask_on_the_bundle_are_one_line_each(paid):
    command_hook.decide(_payload("rm -rf /"))
    command_hook.decide(_payload("git reset --hard HEAD~3"))
    lines = _lines(paid)
    assert [x["decision"] for x in lines] == ["deny", "ask"]
    for x in lines:
        assert x["v"] == 1 and x["tool"] == "Bash" and x["rules"] == "bundle"
        assert x["exp"] == 10**12 and x["escalated"] is False and x["findings"]


def test_a_call_let_through_writes_nothing(paid):
    assert command_hook.decide(_payload("ls -la")) is None
    assert command_hook.decide(_payload("rm -rf /", tool="Read")) is None
    assert _lines(paid) == []


def test_an_ask_made_deny_is_marked_escalated(paid):
    command_hook.decide(_payload("git reset --hard HEAD~3", mode="bypassPermissions"))
    (x,) = _lines(paid)
    assert x["decision"] == "deny" and x["escalated"] is True


def test_no_command_path_or_value_reaches_the_line(paid):
    for c in (f"rm -rf {SECRET_PATH}", f"PGPASSWORD={SECRET_VALUE} psql -c 'drop table t'",
              f"dd if=/dev/zero of={SECRET_PATH}/x", f"git push --force origin {SECRET_VALUE}"):
        command_hook.decide(_payload(c))
    raw = "".join(p.read_text(encoding="ascii") for p in (paid / block_log.LOG_DIR).iterdir())
    lines = _lines(paid)
    assert len(lines) == 4
    for needle in (SECRET_PATH, "acme", SECRET_VALUE, "hunter2", "/work/proj", "psql", "drop"):
        assert needle not in raw
    for x in lines:
        assert set(x) == {"v", "t", "tool", "decision", "escalated", "findings", "rules", "exp", "build"}
        for f in x["findings"]:
            assert set(f) == {"rule", "level", "target"}
            assert f["rule"] in RULE_IDS and f["level"] in block_log.LEVELS
            assert f["target"] is None or f["target"] in TARGETS


def test_a_value_outside_its_set_drops_the_line():
    good = Verdict("deny", ("r",), (Finding("rm.outside", "deny", "outside"),))
    assert block_log.entry(good, tool="Bash", exp=1, build=None, now=0) is not None
    for bad in (Verdict("deny", (), (Finding("rm -rf /secret", "deny", None),)),
                Verdict("deny", (), (Finding("rm.outside", "deny", "/secret"),)),
                Verdict("allow", (), ())):
        assert block_log.entry(bad, tool="Bash", exp=1, build=None, now=0) is None
    assert block_log.entry(good, tool="Read", exp=1, build=None, now=0) is None


def test_the_build_id_is_kept_only_when_it_looks_like_one(paid):
    (paid / "current").mkdir()
    (paid / "current" / "BUILD_ID").write_text("6e5ecea0123\n", encoding="ascii")
    command_hook.decide(_payload("rm -rf /"))
    (paid / "current" / "BUILD_ID").write_text("/home/me/not-an-id\n", encoding="ascii")
    command_hook.decide(_payload("rm -rf /"))
    assert [x["build"] for x in _lines(paid)] == ["6e5ecea0123", None]


def test_a_failed_write_leaves_the_decision_alone(paid, monkeypatch):
    (paid / block_log.LOG_DIR).write_text("a file where the folder should be", encoding="ascii")
    out = command_hook.decide(_payload("rm -rf /"))
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"

    def boom(*a, **k):
        raise RuntimeError("disk on fire")
    monkeypatch.setattr(block_log, "_open_append", boom)
    (paid / block_log.LOG_DIR).unlink()
    out = command_hook.decide(_payload("git reset --hard HEAD~3"))
    assert out["hookSpecificOutput"]["permissionDecision"] == "ask"


def _day_files(folder, *days):
    folder.mkdir(exist_ok=True)
    names = [f"blocks-{time.strftime('%Y%m%d', time.gmtime(NOW - d * 86400))}.jsonl" for d in days]
    for n in names:
        (folder / n).write_text("{}\n", encoding="ascii")
    return names


def test_files_older_than_30_days_go(tmp_path):
    folder = tmp_path / block_log.LOG_DIR
    keep, old = _day_files(folder, 30, 31)
    (folder / "notes.txt").write_text("not ours", encoding="ascii")
    block_log.prune(str(tmp_path), now=NOW)
    assert sorted(p.name for p in folder.iterdir()) == sorted([keep, "notes.txt"])


def test_old_files_go_on_any_call_even_without_a_bundle(tmp_path, monkeypatch):
    # The key taken out, nothing new recorded: old lines must still go.
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(tmp_path))
    folder = tmp_path / block_log.LOG_DIR
    _day_files(folder, 400)
    assert command_hook.decide(_payload("ls")) is None
    assert list(folder.iterdir()) == []


def test_prune_without_a_folder_or_dir_is_quiet(tmp_path):
    block_log.prune(None)
    block_log.prune(str(tmp_path))
    assert not (tmp_path / block_log.LOG_DIR).exists()


@pytest.mark.parametrize("status", [401, 403])
def test_a_refused_key_removes_the_record(server, tmp_path, status):  # noqa: F811
    v = Verdict("deny", (), (Finding("rm.outside", "deny", "outside"),))
    assert block_log.record(str(tmp_path), v, tool="Bash", exp=1, now=NOW)
    server.status = status
    assert "block record removed" in _fetch(server, tmp_path)
    assert not (tmp_path / block_log.LOG_DIR).exists()


def test_an_unreachable_server_keeps_the_record(tmp_path):
    v = Verdict("deny", (), (Finding("rm.outside", "deny", "outside"),))
    assert block_log.record(str(tmp_path), v, tool="Bash", exp=1, now=NOW)
    rules_bundle.fetch("bdk_test", str(tmp_path), url="http://127.0.0.1:9/guard/rules",
                       timeout=2, public_keys=KEYS)
    assert len(_lines(tmp_path)) == 1


_WRITER = """
import sys
from boxdawn_guard import block_log
from boxdawn_guard.command_guard import Finding, Verdict
v = Verdict("deny", (), (Finding("rm.outside", "deny", "outside"),))
for _ in range(int(sys.argv[2])):
    assert block_log.record(sys.argv[1], v, tool="Bash", exp=1)
"""


def test_many_writers_at_once_lose_and_break_no_line(tmp_path):
    # Sessions and sub-agents run hooks in parallel. With plain O_APPEND on
    # Windows, 20 writers x 500 lines kept ~6,000 lines, ~800 of them broken.
    writers, each = 20, 200
    env = {**os.environ, "PYTHONPATH": os.pathsep.join(sys.path)}
    procs = [subprocess.Popen([sys.executable, "-c", _WRITER, str(tmp_path), str(each)], env=env)
             for _ in range(writers)]
    assert all(p.wait(timeout=120) == 0 for p in procs)
    assert len(_lines(tmp_path)) == writers * each
