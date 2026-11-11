param([switch]$SkipToolchainCheck)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root
$out = Join-Path $root 'out/watch-windows'
New-Item -ItemType Directory -Force $out | Out-Null
$report = [ordered]@{
    schema = 1
    status = 'started'
    unofficial = $true
    hardwareTested = $false
    freeAppleAccountVerified = $false
    hermesVerified = $false
    startedUtc = [DateTime]::UtcNow.ToString('o')
    upstream = 'https://github.com/nab138/iloader/tree/v2.4.1'
    isideloadBase = '0.5.2'
    idevice = '0.1.68'
    architecture = 'x86_64-pc-windows-msvc'
}
function Invoke-Checked([string]$Tool, [string[]]$Arguments, [string]$Log) {
    & $Tool @Arguments 2>&1 | Tee-Object -FilePath (Join-Path $out $Log)
    if ($LASTEXITCODE -ne 0) {
        throw "$Tool failed; see $Log (exit $LASTEXITCODE)"
    }
}
function Hash-File([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}
try {
    $report.sourceCommit = (& git rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0) { throw 'Cannot identify source commit' }
    $dirty = (& git status --porcelain | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $dirty.Length -gt 0) { throw 'Refusing a dirty source build' }
    $report.runUrl = if ($env:GITHUB_RUN_ID) { "https://github.com/$env:GITHUB_REPOSITORY/actions/runs/$env:GITHUB_RUN_ID" } else { $null }
    $report.runnerImage = $env:ImageVersion
    $report.rustVersion = (& rustc --version | Out-String).Trim()
    $report.cargoVersion = (& cargo --version | Out-String).Trim()
    $report.bunVersion = (& bun --version | Out-String).Trim()
    if (-not $SkipToolchainCheck -and $report.bunVersion -ne '1.4.2') {
        throw 'Expected Bun 1.4.2; do not silently update the lockfile'
    }
    Invoke-Checked 'python' @('scripts/verify-source.py') 'source-check.log'
    Invoke-Checked 'bun' @('install', '--frozen-lockfile', '--ignore-scripts') 'frontend-install.log'
    Invoke-Checked 'bun' @('run', 'build') 'frontend-build.log'
    # Use the application lockfile for library selection, including the local 0.5.2 patch.
    Invoke-Checked 'cargo' @('test', '--locked', '--manifest-path', 'src-tauri/Cargo.toml', '-p', 'isideload', '--lib') 'library-tests.log'
    Invoke-Checked 'cargo' @('test', '--locked', '--manifest-path', 'src-tauri/Cargo.toml', '--lib') 'host-tests.log'
    Invoke-Checked 'bun' @('run', 'tauri', 'build', '--no-bundle', '--', '--locked') 'windows-build.log'
    $exe = Join-Path $root 'src-tauri/target/release/iloader.exe'
    if (-not (Test-Path $exe -PathType Leaf)) { throw 'Build returned success but executable is missing' }
    $name = 'iloader-2.4.1-watch-experimental.exe'
    Copy-Item -LiteralPath $exe -Destination (Join-Path $out $name)
    $report.status = 'compiled-and-unit-tested'
    $report.executable = $name
    $report.executableSha256 = Hash-File (Join-Path $out $name)
    $report.sourceCargoLockSha256 = Hash-File 'src-tauri/Cargo.lock'
    $report.bunLockSha256 = Hash-File 'bun.lock'
    Copy-Item 'src-tauri/Cargo.lock' (Join-Path $out 'Cargo.lock')
    Copy-Item 'bun.lock' (Join-Path $out 'bun.lock')
    Copy-Item 'WATCH-PORT.md' (Join-Path $out 'READ-ME-FIRST.md')
    Copy-Item 'LICENSE' (Join-Path $out 'LICENSE')
    Copy-Item 'LICENSE-BRANDING' (Join-Path $out 'LICENSE-BRANDING')
} catch {
    $report.status = 'failed'
    # This is only a build error; no Apple or GitHub credentials are read or logged.
    $report.failure = $_.Exception.Message
    throw
} finally {
    $report.completedUtc = [DateTime]::UtcNow.ToString('o')
    $report | ConvertTo-Json -Depth 6 | Set-Content -Encoding utf8 (Join-Path $out 'BUILD.json')
    $lines = Get-ChildItem $out -File | Where-Object Name -ne 'SHA256SUMS.txt' | Sort-Object Name | ForEach-Object { "$(Hash-File $_.FullName)  $($_.Name)" }
    $lines | Set-Content -Encoding ascii (Join-Path $out 'SHA256SUMS.txt')
}
