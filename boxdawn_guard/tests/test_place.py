"""The session-start place scripts: which build ends up in `current`.

A session opened before an update keeps its older plugin folder and runs the
place script from it again. That must not put the older build over a newer one.
"""
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[2] / "plugin" / "scripts"
WINDOWS = sys.platform == "win32"

pytestmark = pytest.mark.skipif(
    not SCRIPTS.is_dir() or not (WINDOWS or sys.platform in ("linux", "darwin")),
    reason="needs the plugin scripts and a supported OS",
)


def _dist_name():
    if WINDOWS:
        return "windows-x64"
    arch = "arm64" if platform.machine().lower() in ("arm64", "aarch64") else "x64"
    return ("macos" if sys.platform == "darwin" else "linux") + "-" + arch


def _root(tmp_path, name, build, version):
    """A plugin folder as the release assembles it, with a stand-in binary."""
    root = tmp_path / name
    dist = root / "dist" / _dist_name()
    dist.mkdir(parents=True)
    shutil.copytree(SCRIPTS, root / "scripts")
    (dist / "BUILD_ID").write_text(build + "\n", encoding="ascii")
    if version is not None:
        (dist / "VERSION").write_text(version + "\n", encoding="ascii")
    (dist / ("bdxguard.exe" if WINDOWS else "bdxguard")).write_text(build, encoding="ascii")
    return root


def _place(root, data):
    env = {k: v for k, v in os.environ.items() if k != "CLAUDE_PLUGIN_OPTION_API_KEY"}
    env["CLAUDE_PLUGIN_ROOT"] = str(root)
    env["CLAUDE_PLUGIN_DATA"] = str(data)
    if WINDOWS:
        cmd = ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
               str(root / "scripts" / "place.ps1")]
    else:
        cmd = ["sh", str(root / "scripts" / "place.sh")]
    done = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=120)
    assert done.returncode == 0, done.stderr
    return (data / "current" / "BUILD_ID").read_text(encoding="ascii").strip()


def test_an_older_plugin_folder_does_not_replace_a_newer_build(tmp_path):
    data = tmp_path / "data"
    old = _root(tmp_path, "old", "aaaaaaa", "0.4.9")
    new = _root(tmp_path, "new", "bbbbbbb", "0.4.10")
    assert _place(old, data) == "aaaaaaa"
    assert _place(new, data) == "bbbbbbb"
    assert _place(old, data) == "bbbbbbb"
    assert (data / "current" / "bdxguard.exe").read_text(encoding="ascii") == "bbbbbbb"


def test_a_newer_plugin_folder_replaces_an_older_build(tmp_path):
    data = tmp_path / "data"
    assert _place(_root(tmp_path, "old", "aaaaaaa", "0.4.10"), data) == "aaaaaaa"
    assert _place(_root(tmp_path, "new", "bbbbbbb", "0.5.0"), data) == "bbbbbbb"


def test_the_same_version_with_another_build_replaces(tmp_path):
    data = tmp_path / "data"
    assert _place(_root(tmp_path, "one", "aaaaaaa", "0.4.9"), data) == "aaaaaaa"
    assert _place(_root(tmp_path, "two", "bbbbbbb", "0.4.9"), data) == "bbbbbbb"


def test_a_build_placed_without_a_version_is_replaced(tmp_path):
    """0.4.8 and earlier placed no VERSION file."""
    data = tmp_path / "data"
    assert _place(_root(tmp_path, "old", "aaaaaaa", None), data) == "aaaaaaa"
    assert _place(_root(tmp_path, "new", "bbbbbbb", "0.4.9"), data) == "bbbbbbb"


def test_a_folder_without_a_version_still_replaces(tmp_path):
    """The fix only holds between two versions that both carry it."""
    data = tmp_path / "data"
    assert _place(_root(tmp_path, "new", "bbbbbbb", "0.4.9"), data) == "bbbbbbb"
    assert _place(_root(tmp_path, "old", "aaaaaaa", None), data) == "aaaaaaa"
