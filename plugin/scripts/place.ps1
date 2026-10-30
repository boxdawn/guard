# SessionStart on Windows: put the guard build at
# $env:CLAUDE_PLUGIN_DATA\current\bdxguard.exe (see place.sh).
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { exit 0 }
# Windows on Arm runs the x64 build under emulation.
if ($env:PROCESSOR_ARCHITECTURE -notin @('AMD64', 'ARM64')) {
    [Console]::Error.WriteLine("boxdawn guard: no build for $env:PROCESSOR_ARCHITECTURE"); exit 1
}
$src = Join-Path $env:CLAUDE_PLUGIN_ROOT 'dist\windows-x64'
$dst = Join-Path $env:CLAUDE_PLUGIN_DATA 'current'
if (-not (Test-Path $src)) { [Console]::Error.WriteLine("boxdawn guard: no build for windows-x64"); exit 1 }
$srcId = Join-Path $src 'BUILD_ID'
$dstId = Join-Path $dst 'BUILD_ID'
if ((Test-Path $dstId) -and ((Get-Content -Raw $srcId) -eq (Get-Content -Raw $dstId))) { exit 0 }
New-Item -ItemType Directory -Force $env:CLAUDE_PLUGIN_DATA | Out-Null
$tmp = Join-Path $env:CLAUDE_PLUGIN_DATA "current.tmp.$PID"
$old = "$dst.old"
if (Test-Path $tmp) { Remove-Item -Recurse -Force $tmp }
Copy-Item -Recurse $src $tmp
if (Test-Path $old) { Remove-Item -Recurse -Force $old }
if (Test-Path $dst) { Move-Item $dst $old }
Move-Item $tmp $dst
if (Test-Path $old) { Remove-Item -Recurse -Force $old }
