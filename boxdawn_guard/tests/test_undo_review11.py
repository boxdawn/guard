"""`undo`: what the eleventh review found, each as a test."""
from __future__ import annotations

import os
import shutil
import time

import pytest

from boxdawn_guard import undo
from boxdawn_guard.tests.test_undo import _payload, _store, _write, project  # noqa: F401 - `project` is a fixture

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")


def _data():
    return os.environ["CLAUDE_PLUGIN_DATA"]


def _held(self, path, lines, append):
    raise PermissionError(13, "another program holds the record")


# -- 1: a row cut short must not take the next one with it ------------------------------------
def test_a_row_after_one_cut_short_is_still_read(project):
    undo.before_command(_payload(project, "echo one"), _data())
    store = _store(project)
    with open(store.log, "ab") as f:
        f.write(b'{"at": 1794700000.0, "n": 2, "commit": "ab')  # the writer ended here
    _write(project, "build/out.txt", b"x")
    undo.before_command(_payload(project, "rm -r build"), _data())
    rows = store.rows()
    assert [r.get("before") for r in rows] == ["echo one", "rm -r build"]
    assert rows[-1].get("n") == 2 and "unprotected" not in rows[-1]


def test_a_row_after_a_whole_one_gets_no_empty_line(project):
    store = _store(project)
    store.note({"unprotected": "one"})
    store.note({"unprotected": "two"})
    with open(store.log, "rb") as f:
        assert f.read().count(b"\n") == 2


# -- 3: one wait for the record per command -----------------------------------------------------
def test_a_command_waits_for_a_held_record_once(project, monkeypatch):
    """The lock held by another snapshot and the record held by another program: the row that
    says so and the row for its failure shared two waits."""
    monkeypatch.setattr(undo, "HOOK_BUDGET", 0.3)
    monkeypatch.setattr(undo, "LOG_WAIT", 1.0)
    other = _store(project)
    assert other.acquire()
    monkeypatch.setattr(undo.Store, "_write_new", _held)
    started = time.perf_counter()
    try:
        with pytest.raises(PermissionError):
            undo.before_command(_payload(project, "echo held"), _data())
    finally:
        other.release()
    assert time.perf_counter() - started < 0.3 + 1.0 + 0.6


# -- 4: the session start says what happened instead of a traceback ------------------------------
def test_the_session_start_answers_when_neither_the_snapshot_nor_its_row_can_be_written(project, monkeypatch):
    monkeypatch.setattr(undo, "LOG_WAIT", 0.1)
    monkeypatch.setattr(undo.Store, "_write_new", _held)
    result = undo.start(project, _data())
    assert result.startswith("failed") and "record could not be written" in result


def test_the_late_snapshot_answers_when_the_lock_is_held_and_its_row_cannot_be_written(project, monkeypatch):
    monkeypatch.setattr(undo, "LOG_WAIT", 0.1)
    other = _store(project)
    assert other.acquire()
    monkeypatch.setattr(undo.Store, "_write_new", _held)
    try:
        result = undo.start(project, _data(), "late", "echo late")
    finally:
        other.release()
    assert result.startswith("failed") and "record could not be written" in result
