# Build the Windows native shim (libxuidforward.dll) with MSVC.
#
# The shim needs no Endstone headers - it only patches the BDS image and manipulates a
# std::string that belongs to BDS. It is built with the dynamic CRT (/MD) so it shares BDS's
# msvcp140/vcruntime140/UCRT: the same std::string ABI and the same heap.
#
#   powershell -ExecutionPolicy Bypass -File scripts\build-shim.ps1
#
# Output: build\libxuidforward.dll
param(
    [string]$Out = "$PSScriptRoot\..\build"
)
$ErrorActionPreference = "Stop"
$root = Resolve-Path "$PSScriptRoot\.."
New-Item -ItemType Directory -Force $Out | Out-Null

# Locate a Visual Studio with the C++ toolset and its vcvars64.bat.
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) { throw "vswhere.exe not found - install Visual Studio with the C++ workload." }
$vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vsPath) { throw "No Visual Studio with the C++ toolset (MSVC) found." }
$vcvars = Join-Path $vsPath "VC\Auxiliary\Build\vcvars64.bat"
if (-not (Test-Path $vcvars)) { throw "vcvars64.bat not found at $vcvars" }

$src = @(
    "shim\xf_api.cpp",
    "plugin\src\windows\profile.cpp",
    "plugin\src\windows\hook.cpp",
    "plugin\src\windows\inject.cpp",
    "plugin\src\stage.cpp"
) -join " "

$cl = "cl /nologo /std:c++20 /O2 /EHsc /MD /DNDEBUG /DNOMINMAX /DWIN32_LEAN_AND_MEAN " +
      "/FIabi_string.h /I plugin\src\windows /I plugin\src $src " +
      "/LD /Fe:`"$Out\libxuidforward.dll`" /link /DEF:plugin\src\windows\xuidforward.def"

$bat = Join-Path $env:TEMP "xf_build.bat"
@"
@echo off
call "$vcvars" >nul
cd /d "$root"
$cl
"@ | Set-Content $bat -Encoding ascii

Write-Host "=== building libxuidforward.dll ===" -ForegroundColor Cyan
cmd /c "`"$bat`""
if ($LASTEXITCODE -ne 0) { throw "MSVC build failed (exit $LASTEXITCODE)" }

$dll = Join-Path $Out "libxuidforward.dll"
if (-not (Test-Path $dll)) { throw "build produced no DLL" }
Get-Item $dll | Select-Object Name, Length, LastWriteTime | Format-List
Write-Host "exports:" -ForegroundColor Cyan
& dumpbin /exports $dll 2>$null | Select-String "xf_" | ForEach-Object { $_.Line.Trim() }
Write-Host "DLL_BUILD_OK" -ForegroundColor Green
