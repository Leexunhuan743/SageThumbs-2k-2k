<#
  Fast, dependency-free tests for check-release-size.ps1.
  Uses sparse temporary files, so the byte-boundary cases do not consume the
  nominal 10+ MiB on disk.
#>

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$checker = Join-Path $PSScriptRoot 'check-release-size.ps1'
$productionPolicy = Join-Path $root 'packaging\size-budget.json'
$scratch = Join-Path ([IO.Path]::GetTempPath()) ("st2k-size-guard-" + [guid]::NewGuid().ToString('N'))
$script:passed = 0

function Set-SparseLength([string]$path, [int64]$length) {
    $parent = Split-Path $path -Parent
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    $stream = [IO.File]::Open($path, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $stream.SetLength($length) } finally { $stream.Dispose() }
}

function Write-TestPolicy(
    [string]$path,
    [int64]$referenceInstaller = 1000,
    [int64]$installerAllowance = 100,
    [int64]$maxInstaller = 1100,
    [int64]$referenceRust = 2000,
    [int64]$rustAllowance = 200,
    [int64]$maxRust = 2200,
    [int64]$referenceMagick = 3000,
    [int64]$magickAllowance = 300,
    [int64]$maxMagick = 3300
) {
    @{
        schemaVersion = 2
        referenceVersion = 'test'
        referenceInstallerBytes = $referenceInstaller
        referenceInstallerSha256 = ('a' * 64)
        installerGrowthAllowanceBytes = $installerAllowance
        maxInstallerBytes = $maxInstaller
        referenceRustPayloadBytes = $referenceRust
        rustPayloadGrowthAllowanceBytes = $rustAllowance
        maxRustPayloadBytes = $maxRust
        referenceMagickPayloadBytes = $referenceMagick
        magickPayloadGrowthAllowanceBytes = $magickAllowance
        maxMagickPayloadBytes = $maxMagick
        rationale = 'test policy'
    } | ConvertTo-Json | Set-Content -LiteralPath $path -Encoding UTF8
}

function Set-StageTotal([string]$stage, [int64]$total) {
    if ($total -lt 2) { throw 'test stage total must be at least 2 bytes' }
    Set-SparseLength (Join-Path $stage 'sagethumbs2k.dll') 1
    Set-SparseLength (Join-Path $stage 'SageThumbs2K.exe') 1
    Set-SparseLength (Join-Path $stage 'st2k.exe') ($total - 2)
}

function Set-MagickTotal([string]$stage, [int64]$total) {
    Set-SparseLength (Join-Path $stage 'magick\payload.bin') $total
}

function Assert-Passes([string]$name, [scriptblock]$body) {
    try {
        & $body *> $null
        Write-Host "  PASS  $name" -ForegroundColor Green
        $script:passed++
    } catch {
        throw "expected PASS for '$name', got: $($_.Exception.Message)"
    }
}

function Assert-Fails([string]$name, [scriptblock]$body) {
    $failed = $false
    try { & $body *> $null } catch { $failed = $true }
    if (-not $failed) { throw "expected FAILURE for '$name'" }
    Write-Host "  PASS  $name (failed closed)" -ForegroundColor Green
    $script:passed++
}

New-Item -ItemType Directory -Path $scratch -Force | Out-Null
try {
    $policy = Join-Path $scratch 'policy.json'
    $installer = Join-Path $scratch 'setup.exe'
    $stage = Join-Path $scratch 'stage'
    Write-TestPolicy $policy

    Set-SparseLength $installer 1100
    Set-StageTotal $stage 2200
    Set-MagickTotal $stage 3300
    Assert-Passes 'exact installer, Rust, and ImageMagick ceilings' {
        & $checker -InstallerPath $installer -PolicyPath $policy -StagePath $stage
    }

    Set-SparseLength $installer 1101
    Assert-Fails 'installer ceiling plus one byte' {
        & $checker -InstallerPath $installer -PolicyPath $policy -StagePath $stage
    }

    Set-SparseLength $installer 1000
    Set-StageTotal $stage 2201
    Assert-Fails 'Rust payload ceiling plus one byte' {
        & $checker -InstallerPath $installer -PolicyPath $policy -StagePath $stage
    }

    Set-StageTotal $stage 2200
    Set-MagickTotal $stage 3301
    Assert-Fails 'ImageMagick payload ceiling plus one byte' {
        & $checker -InstallerPath $installer -PolicyPath $policy -StagePath $stage
    }

    # Measured 1.3.6-rc1 size-policy reference. Unlike the tagged 1.3.2-1.3.5
    # packages, it includes the clean-machine AVIF/JXL writers and dependencies.
    # This is a policy reference, not a required digest/byte count for every rebuild.
    $p = Get-Content $productionPolicy | ConvertFrom-Json
    Set-SparseLength $installer 13118612
    Set-SparseLength (Join-Path $stage 'sagethumbs2k.dll') 6564352
    Set-SparseLength (Join-Path $stage 'SageThumbs2K.exe') 8899072
    Set-SparseLength (Join-Path $stage 'st2k.exe') 6752768
    Set-MagickTotal $stage 29827612
    Assert-Passes 'measured feature-complete rc1 policy reference' {
        & $checker -InstallerPath $installer -PolicyPath $productionPolicy -StagePath $stage
    }

    # The pre-patch EXR lookup tables duplicated static data in all three Rust
    # artifacts. Keep that raw-payload regression rejected even if compression
    # happens to hide it in the installer. The distribution below is the
    # originally-observed duplicated-table shape; scale it to JUST over the
    # CURRENT ceiling so the probe stays a regression as the baseline moves
    # (it used to be hard-coded and went green when maxRustPayloadBytes was
    # re-baselined).
    $k = [double]($p.maxRustPayloadBytes + 1) / (6785024 + 9118720 + 6974464)
    $dll = [int](6785024 * $k)
    $exe = [int](9118720 * $k)
    Set-SparseLength (Join-Path $stage 'sagethumbs2k.dll') $dll
    Set-SparseLength (Join-Path $stage 'SageThumbs2K.exe') $exe
    Set-SparseLength (Join-Path $stage 'st2k.exe') ($p.maxRustPayloadBytes + 1 - $dll - $exe)
    Assert-Fails 'known duplicated-table Rust payload' {
        & $checker -InstallerPath $installer -PolicyPath $productionPolicy -StagePath $stage
    }

    Set-StageTotal $stage 22216192
    # Ceiling-plus-one probes must track the LIVE policy file — these used to be
    # hard-coded and silently drifted when maxRustPayloadBytes was re-baselined
    # (the "production Rust ceiling plus one byte" case went green instead of
    # failing closed). Read the ceilings from size-budget.json itself.
    Set-SparseLength $installer ($p.maxInstallerBytes + 1)
    Assert-Fails 'production installer ceiling plus one byte' {
        & $checker -InstallerPath $installer -PolicyPath $productionPolicy -StagePath $stage
    }

    Set-SparseLength $installer 13118612
    Set-StageTotal $stage ($p.maxRustPayloadBytes + 1)
    Assert-Fails 'production Rust ceiling plus one byte' {
        & $checker -InstallerPath $installer -PolicyPath $productionPolicy -StagePath $stage
    }

    Set-StageTotal $stage 22216192
    Set-MagickTotal $stage ($p.maxMagickPayloadBytes + 1)
    Assert-Fails 'production ImageMagick ceiling plus one byte' {
        & $checker -InstallerPath $installer -PolicyPath $productionPolicy -StagePath $stage
    }

    Assert-Fails 'missing installer' {
        & $checker -InstallerPath (Join-Path $scratch 'missing.exe') -PolicyPath $policy
    }

    Set-SparseLength $installer 1000
    Set-StageTotal $stage 2000
    Remove-Item -LiteralPath (Join-Path $stage 'st2k.exe') -Force
    Assert-Fails 'missing staged Rust artifact' {
        & $checker -InstallerPath $installer -PolicyPath $policy -StagePath $stage
    }

    $malformed = Join-Path $scratch 'malformed.json'
    Set-Content -LiteralPath $malformed -Value '{ not-json' -Encoding UTF8
    Assert-Fails 'malformed policy JSON' {
        & $checker -InstallerPath $installer -PolicyPath $malformed
    }

    Write-TestPolicy $policy -maxInstaller 1099
    Assert-Fails 'inconsistent policy arithmetic' {
        & $checker -InstallerPath $installer -PolicyPath $policy
    }

    Write-Host "[size-test] ALL GREEN ($script:passed cases)" -ForegroundColor Green
} finally {
    if (Test-Path -LiteralPath $scratch) {
        Remove-Item -LiteralPath $scratch -Recurse -Force
    }
}
