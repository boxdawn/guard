"""Every test reads the guard's settings from an empty place, not from the machine it runs on."""
from __future__ import annotations

import pytest

from boxdawn_guard import command_hook, undo


def pytest_configure(config):
    config.addinivalue_line("markers", "shipped_hook_budget: keep undo's own HOOK_BUDGET for this test")


@pytest.fixture(autouse=True)
def _no_settings_of_this_machine(tmp_path_factory, monkeypatch):
    place = tmp_path_factory.mktemp("settings")
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(place / "config"))
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(place / "project"))
    monkeypatch.setattr(command_hook, "_MANAGED_SETTINGS", str(place / "managed-settings.json"))
    monkeypatch.setattr(command_hook, "_system_is_korean", lambda: False)  # not this machine's language either


@pytest.fixture(autouse=True)
def _snapshots_do_not_race_a_slow_machine(request, monkeypatch):
    """On a slow runner a snapshot can miss `HOOK_BUDGET` and finish in the background, after
    the test has already changed the files (Windows CI, 11-20: three tests). A test that is
    about what a snapshot holds waits for it here; a test about the budget sets its own, or
    keeps the shipped one with `shipped_hook_budget`."""
    if request.node.get_closest_marker("shipped_hook_budget") is None:
        monkeypatch.setattr(undo, "HOOK_BUDGET", 30.0)
