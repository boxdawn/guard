"""`undo`: what the short check after the eleventh review found, as a test."""
from __future__ import annotations

import os
import shutil

import pytest

from boxdawn_guard import undo
from boxdawn_guard.tests.test_undo import _payload, project  # noqa: F401 - `project` is a fixture

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")


def test_a_snapshot_over_its_time_is_finished_later_even_when_its_row_cannot_be_written(project, monkeypatch):
    started = []
    monkeypatch.setattr(undo, "start_in_background", lambda *args: started.append(args))
    monkeypatch.setattr(undo, "HOOK_BUDGET", 0.0001)
    monkeypatch.setattr(undo, "LOG_WAIT", 0.1)

    def held(self, path, lines, append):
        raise PermissionError(13, "another program holds the record")
    monkeypatch.setattr(undo.Store, "_write_new", held)
    for i in range(50):
        os.makedirs(os.path.join(project, f"many/d{i}"))
    with pytest.raises(PermissionError):
        undo.before_command(_payload(project, "echo slow"), os.environ["CLAUDE_PLUGIN_DATA"])
    assert started and started[0][1] == "echo slow"
