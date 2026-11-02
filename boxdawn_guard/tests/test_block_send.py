"""Sending the block record: only exact lines leave, nothing is lost or sent twice."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time

import pytest

pytest.importorskip("tree_sitter_bash")
pytest.importorskip("cryptography")

from boxdawn_guard import block_log, block_send  # noqa: E402
from boxdawn_guard.command_guard import Finding, Verdict  # noqa: E402
from boxdawn_guard.tests.test_rules_bundle import NOW, server  # noqa: E402,F401 - fixture

DENY = Verdict("deny", (), (Finding("rm.outside", "deny", "outside"),))
ASK = Verdict("ask", (), (Finding("redirect.outside", "ask", "outside"),))


@pytest.fixture(autouse=True)
def _no_grace(monkeypatch):
    """The pause only matters with writers running; see the last test."""
    monkeypatch.setattr(block_send, "RENAME_GRACE_SECONDS", 0)


def _record(data_dir, verdict=DENY, n=1, now=NOW):
    for _ in range(n):
        assert block_log.record(str(data_dir), verdict, tool="Bash", exp=NOW + 86400, now=now)


def _files(data_dir, pattern="*"):
    folder = data_dir / block_log.LOG_DIR
    return sorted(p.name for p in folder.glob(pattern)) if folder.is_dir() else []


def _sent(server):  # noqa: F811
    return [json.loads(body) for _, body in server.seen]


def _send(server, tmp_path, key="bdk_test"):  # noqa: F811
    return block_send.send(key, str(tmp_path), url=server.url.replace("/rules", "/blocks"))


def test_lines_are_sent_with_a_batch_id_and_then_removed(server, tmp_path):  # noqa: F811
    _record(tmp_path, DENY)
    _record(tmp_path, ASK)
    assert _send(server, tmp_path) == "sent 2"
    (body,) = _sent(server)
    assert set(body) == {"batch", "lines"} and len(body["batch"]) == 36
    assert [ln["decision"] for ln in body["lines"]] == ["deny", "ask"]
    assert server.seen[0][0] == "Bearer bdk_test"
    assert _files(tmp_path) == []


def test_only_closed_values_leave_even_from_a_tampered_file(server, tmp_path):  # noqa: F811
    _record(tmp_path)
    day = _files(tmp_path)[0]
    with open(tmp_path / block_log.LOG_DIR / day, "a", encoding="ascii") as f:
        good = json.loads((tmp_path / block_log.LOG_DIR / day).read_text().splitlines()[0])
        f.write(json.dumps({**good, "command": "rm -rf /home/me/secret"}) + "\n")
        f.write(json.dumps({**good, "findings": [{"rule": "rm.outside", "level": "deny",
                                                   "target": "/home/me"}]}) + "\n")
        f.write("not json\n")
    assert _send(server, tmp_path) == "sent 1, dropped 3"
    raw = server.seen[0][1].decode()
    assert "secret" not in raw and "/home/me" not in raw
    assert _files(tmp_path) == []


def test_a_server_error_keeps_the_outbox_and_the_same_batch_goes_again(server, tmp_path):  # noqa: F811
    _record(tmp_path)
    server.status = 503
    assert _send(server, tmp_path).startswith("server error (503)")
    (outbox,) = _files(tmp_path)
    assert outbox.startswith("outbox-")
    server.status = 200
    _record(tmp_path)  # a new line after the failed send: a new day file
    assert _send(server, tmp_path) == "sent 2"
    first, *later = _sent(server)
    # The resend carries the first batch id (the server stores nothing twice);
    # the new line is its own batch. Same-day outboxes go in no fixed order.
    assert sorted(b["batch"] == first["batch"] for b in later) == [False, True]
    assert _files(tmp_path) == []


def test_an_unreachable_server_keeps_everything(tmp_path):
    _record(tmp_path, n=2)
    out = block_send.send("bdk_test", str(tmp_path), url="http://127.0.0.1:9/guard/blocks", timeout=2)
    assert out.startswith("unreachable")
    (outbox,) = _files(tmp_path)
    assert len((tmp_path / block_log.LOG_DIR / outbox).read_text().splitlines()) == 2


@pytest.mark.parametrize("status", [401, 403])
def test_a_refused_key_removes_the_record(server, tmp_path, status):  # noqa: F811
    _record(tmp_path)
    server.status = status
    assert "block record removed" in _send(server, tmp_path)
    assert not (tmp_path / block_log.LOG_DIR).exists()


def test_no_key_or_no_record_sends_nothing(server, tmp_path):  # noqa: F811
    assert block_send.send(None, str(tmp_path)) == "no key"
    assert _send(server, tmp_path) == "nothing to send"
    assert server.seen == []


def test_more_than_the_limit_goes_in_parts(server, tmp_path, monkeypatch):  # noqa: F811
    monkeypatch.setattr(block_send, "MAX_LINES", 3)
    _record(tmp_path, n=5)
    assert _send(server, tmp_path) == "sent 3"
    assert len(_files(tmp_path, "outbox-*")) == 1
    assert _send(server, tmp_path) == "sent 2"
    assert [len(b["lines"]) for b in _sent(server)] == [3, 2]
    assert _files(tmp_path) == []


def test_a_half_written_last_line_is_kept_for_next_time(server, tmp_path):  # noqa: F811
    _record(tmp_path)
    day = tmp_path / block_log.LOG_DIR / _files(tmp_path)[0]
    with open(day, "ab") as f:
        f.write(b'{"v":1,"t"')
    assert _send(server, tmp_path) == "sent 1"
    (outbox,) = _files(tmp_path)
    assert (tmp_path / block_log.LOG_DIR / outbox).read_bytes() == b'{"v":1,"t"'


def test_outbox_files_age_out_like_day_files(tmp_path):
    folder = tmp_path / block_log.LOG_DIR
    folder.mkdir()
    old = folder / "outbox-20200101-6f1c2a9e-3b4d-4e5f-8a7b-0c1d2e3f4a5b.jsonl"
    new = folder / f"outbox-{time.strftime('%Y%m%d', time.gmtime())}-6f1c2a9e-3b4d-4e5f-8a7b-0c1d2e3f4a5b.jsonl"
    old.write_text("x\n")
    new.write_text("x\n")
    block_log.prune(str(tmp_path))
    assert not old.exists() and new.exists()


_WRITER = """
import sys
from boxdawn_guard import block_log
from boxdawn_guard.command_guard import Finding, Verdict
v = Verdict("deny", (), (Finding("rm.outside", "deny", "outside"),))
for _ in range(int(sys.argv[2])):
    assert block_log.record(sys.argv[1], v, tool="Bash", exp=1)
"""


def test_writers_during_a_send_lose_no_line(server, tmp_path, monkeypatch):  # noqa: F811
    """Hooks keep writing while the session-start send renames and removes
    files. Every line written is either sent or still on disk afterwards.
    Without the pause after the rename this lost 4-9 lines on Linux (CI)."""
    monkeypatch.setattr(block_send, "RENAME_GRACE_SECONDS", 2.0)
    writers, each = 10, 200
    env = {**os.environ, "PYTHONPATH": os.pathsep.join(sys.path)}
    procs = [subprocess.Popen([sys.executable, "-c", _WRITER, str(tmp_path), str(each)], env=env)
             for _ in range(writers)]
    results = []

    def sender():
        while any(p.poll() is None for p in procs):
            results.append(_send(server, tmp_path))

    t = threading.Thread(target=sender)
    t.start()
    assert all(p.wait(timeout=180) == 0 for p in procs)
    t.join()
    results.append(_send(server, tmp_path))
    sent = sum(len(b["lines"]) for b in _sent(server))
    left = sum(len(p.read_text().splitlines())
               for p in (tmp_path / block_log.LOG_DIR).glob("*.jsonl")) \
        if (tmp_path / block_log.LOG_DIR).is_dir() else 0
    assert sent + left == writers * each, (sent, left, results[-3:])
    assert len({b["batch"] for b in _sent(server)}) == len(_sent(server))
