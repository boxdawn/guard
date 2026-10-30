# -*- mode: python ; coding: utf-8 -*-
# Build: pyinstaller packaging/bdxguard.spec  (from the repo root, on the OS
# the binary is for -- PyInstaller does not cross-compile).
import os

a = Analysis(
    [os.path.join(SPECPATH, 'guard_entry.py')],
    pathex=[os.path.dirname(SPECPATH)],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='bdxguard',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='bdxguard',
)
