# Builds the release EXE, the portable ZIP and (if Inno Setup is installed) KeepForge-Setup.exe.
# Usage: powershell -ExecutionPolicy Bypass -File scripts\package.ps1
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"

# Build output goes to CARGO_TARGET_DIR when it is set (for example on another drive), else to .\target.
$target = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { Join-Path $root "target" }

cargo build --release
if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }
$exe = Join-Path $target "release\KeepForge.exe"
if (-not (Test-Path $exe)) { throw "KeepForge.exe was not found in $target\release" }

$version = (Select-String -Path Cargo.toml -Pattern '^version = "(.+)"' | Select-Object -First 1).Matches[0].Groups[1].Value
$dist = Join-Path $root "dist"
New-Item -ItemType Directory -Force $dist | Out-Null

# The build script renders the icon into OUT_DIR; copy the newest one for the installer.
# The installer script looks for both in .\target, wherever the build itself went.
$ico = Get-ChildItem (Join-Path $target "release\build") -Recurse -Filter keepforge.ico | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $ico) { throw "keepforge.ico was not found in the build output" }
$local = Join-Path $root "target"
New-Item -ItemType Directory -Force (Join-Path $local "release") | Out-Null
Copy-Item $ico.FullName (Join-Path $local "keepforge.ico") -Force
$localExe = Join-Path $local "release\KeepForge.exe"
if ((Resolve-Path $exe).Path -ne (Join-Path (Resolve-Path (Join-Path $local "release")).Path "KeepForge.exe")) {
    Copy-Item $exe $localExe -Force
}

# Portable: the EXE, the licence texts and the flag that keeps settings next to the EXE.
$stage = Join-Path $dist "portable"
Remove-Item -Recurse -Force $stage -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $stage | Out-Null
Copy-Item $exe $stage
Copy-Item LICENSE (Join-Path $stage "LICENSE.txt")
Copy-Item NOTICE (Join-Path $stage "NOTICE.txt")
Set-Content -Path (Join-Path $stage "portable.flag") -Encoding ASCII -Value "KeepForge keeps its settings in this folder while this file is here."
$zip = Join-Path $dist "KeepForge-$version-portable-x64.zip"
Remove-Item $zip -ErrorAction SilentlyContinue
Compress-Archive -Path (Join-Path $stage "*") -DestinationPath $zip
Remove-Item -Recurse -Force $stage
Copy-Item $exe (Join-Path $dist "KeepForge.exe") -Force

$iscc = @("$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe", "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe", "$env:ProgramFiles\Inno Setup 6\ISCC.exe") |
    Where-Object { Test-Path $_ } | Select-Object -First 1
if ($iscc) {
    & $iscc "/DAppVersion=$version" installer\KeepForge.iss
    if ($LASTEXITCODE -ne 0) { throw "ISCC failed" }
} else {
    Write-Warning "Inno Setup 6 not found: skipping KeepForge-Setup.exe (winget install JRSoftware.InnoSetup)"
}
$size = (Get-Item $exe).Length / 1MB
Write-Host ("KeepForge.exe {0:N2} MB" -f $size)
Get-ChildItem $dist -File | Format-Table Name, @{n="MB";e={"{0:N2}" -f ($_.Length/1MB)}}
