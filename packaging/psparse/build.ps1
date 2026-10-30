# Build bdxpsparse.exe with the C# compiler of .NET Framework 4 against the
# System.Management.Automation.dll of Windows PowerShell 5.1. Both ship with
# Windows. Usage: powershell -NoProfile -File packaging/psparse/build.ps1 <out dir>
param([Parameter(Mandatory)][string]$OutDir)
$ErrorActionPreference = 'Stop'
# pwsh 7 would hand over its own .NET (Core) assembly, which csc of .NET Framework cannot use.
if ($PSVersionTable.PSEdition -ne 'Desktop') { throw 'run this with Windows PowerShell 5.1 (powershell.exe)' }
$csc = Join-Path ([Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()) 'csc.exe'
$sma = [psobject].Assembly.Location
New-Item -ItemType Directory -Force $OutDir | Out-Null
& $csc -nologo -optimize+ "-out:$(Join-Path $OutDir 'bdxpsparse.exe')" "-r:$sma" (Join-Path $PSScriptRoot 'BdxPsParse.cs')
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
