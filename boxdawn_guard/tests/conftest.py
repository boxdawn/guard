"""Every test reads the guard's settings from an empty place, not from the machine it runs on."""
from __future__ import annotations

import pytest

from boxdawn_guard import command_hook


@pytest.fixture(autouse=True)
def _no_settings_of_this_machine(tmp_path_factory, monkeypatch):
    place = tmp_path_factory.mktemp("settings")
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(place / "config"))
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(place / "project"))
    monkeypatch.setattr(command_hook, "_MANAGED_SETTINGS", str(place / "managed-settings.json"))
