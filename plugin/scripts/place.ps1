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
# A session opened before an update runs this script again from the older
# plugin folder. It must not put its older build over a newer one, so a build
# in place with a strictly newer VERSION is left alone.
$keep = $false
$srcVer = Join-Path $src 'VERSION'
$dstVer = Join-Path $dst 'VERSION'
if ((Test-Path $srcVer) -and (Test-Path $dstVer) -and (Test-Path (Join-Path $dst 'bdxguard.exe'))) {
    try {
        $keep = [version]((Get-Content -Raw $dstVer).Trim()) -gt [version]((Get-Content -Raw $srcVer).Trim())
    } catch { $keep = $false }
}
if (-not $keep -and -not ((Test-Path $dstId) -and ((Get-Content -Raw $srcId) -eq (Get-Content -Raw $dstId)))) {
    New-Item -ItemType Directory -Force $env:CLAUDE_PLUGIN_DATA | Out-Null
    $tmp = Join-Path $env:CLAUDE_PLUGIN_DATA "current.tmp.$PID"
    $old = "$dst.old"
    if (Test-Path $tmp) { Remove-Item -Recurse -Force $tmp }
    Copy-Item -Recurse $src $tmp
    if (Test-Path $old) { Remove-Item -Recurse -Force $old }
    if (Test-Path $dst) { Move-Item $dst $old }
    Move-Item $tmp $dst
    if (Test-Path $old) { Remove-Item -Recurse -Force $old }
}
# With an API key in the plugin's settings, fetch the signed rules in the
# background (the session does not wait). Without one this does nothing and
# opens no connection.
if ($env:CLAUDE_PLUGIN_OPTION_API_KEY) {
    Start-Process -FilePath (Join-Path $dst 'bdxguard.exe') -ArgumentList 'fetch-rules' -WindowStyle Hidden
}
