[CmdletBinding()]
param(
    [Parameter()]
    [string]$Platforms = 'all',

    [Parameter()]
    [string]$Version = $env:VERSION,

    [Parameter()]
    [switch]$Vendor,

    [Parameter()]
    [switch]$Race,

    [Parameter()]
    [switch]$Help
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Save the caller's Go environment so it can be restored on exit. PowerShell
# scripts that assign $env:... leak those changes back into the calling
# session, which would otherwise leave GOOS/GOARCH pointed at the last target
# and break every subsequent `go` command in the session.
$script:OriginalGoEnv = @{
    GOOS        = $env:GOOS
    GOARCH      = $env:GOARCH
    CGO_ENABLED = $env:CGO_ENABLED
    GOTOOLCHAIN = $env:GOTOOLCHAIN
    GOPROXY     = $env:GOPROXY
    GOFLAGS     = $env:GOFLAGS
}

# Never auto-download a Go toolchain: always use the one that is installed.
# (Module fetching is decided later, based on whether vendor/ exists.)
$env:GOTOOLCHAIN = 'local'

function Show-Usage {
    Write-Host 'Usage: ./build-all.ps1 [-Platforms os/arch,...] [-Version version] [-Vendor]'
    Write-Host ''
    Write-Host '  -Platforms  Comma-separated list of targets (default: all).'
    Write-Host '              Example: -Platforms linux/amd64,darwin/arm64'
    Write-Host ''
    Write-Host '  -Version    Overrides the version string (default: 5.1.0).'
    Write-Host ''
    Write-Host '  -Vendor     Run "go mod vendor" first to create the local vendor/'
    Write-Host '              directory (requires network), then build fully offline.'
    Write-Host '  -Race       Run unit tests with the Go race detector (requires CGO)'
}

if (-not $Version) {
    $Version = '5.1.0'
}

if ($Help) {
    Show-Usage
    exit 0
}

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Push-Location $scriptRoot

try {
    # Optional: (re)create the vendored dependency tree on demand. This needs
    # network access once; afterwards builds run fully offline from vendor/.
    if ($Vendor) {
        Write-Host 'Vendoring dependencies (go mod vendor)...'
        & go mod vendor
        if ($LASTEXITCODE -ne 0) {
            throw 'go mod vendor failed'
        }
    }

    # Use the vendored tree when it exists; otherwise resolve modules normally.
    $useVendor = Test-Path 'vendor/modules.txt'
    if ($useVendor) {
        $env:GOFLAGS = '-mod=vendor'
        $env:GOPROXY = 'off'
        Write-Host '[INFO]  Using vendored dependencies (offline).'
    }
    else {
        Write-Host '[INFO]  vendor/ not found - fetching modules on demand (network).'
        Write-Host '        Tip: run with -Vendor once to snapshot dependencies locally.'
    }

    # Commit stamp is optional: fall back to 'unknown' when git is missing or
    # the source tree is a plain tarball (no .git) so builds work fully offline.
    $gitCommit = 'unknown'
    if (Get-Command git -ErrorAction SilentlyContinue) {
        try {
            $commitOut = git rev-parse --short HEAD 2>$null
            if ($LASTEXITCODE -eq 0 -and $commitOut) {
                $gitCommit = $commitOut.Trim()
            }
        }
        catch {
            $gitCommit = 'unknown'
        }
    }
    $allPlatforms = @(
        'linux/amd64',
        'linux/arm64',
        'linux/386',
        'windows/amd64',
        'windows/386',
        'darwin/amd64',
        'darwin/arm64',
        'freebsd/amd64'
    )

    if ($Platforms -eq 'all') {
        $selectedPlatforms = $allPlatforms
    }
    else {
        $selectedPlatforms = @($Platforms -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
    }

    foreach ($platform in $selectedPlatforms) {
        if ($allPlatforms -notcontains $platform) {
            Write-Error "Unknown platform: $platform"
            exit 1
        }
    }

    Write-Host 'Cipherforge build'
    Write-Host "Version : $Version"
    Write-Host "Commit  : $gitCommit"
    Write-Host "Targets : $($selectedPlatforms.Count)"

    # ---- Unit tests ----
    Write-Host ''
    Write-Host 'Running unit tests...'

    # The race detector is opt-in (-Race) because it roughly doubles test time.
    $cgoEnabled = (go env CGO_ENABLED) -eq '1'
    if ($Race -and $cgoEnabled) {
        Write-Host '[INFO]  Race detector enabled (CGO is available)'
        $testResult = & go test -race ./... 2>&1
    } else {
        if ($Race) {
            Write-Host '[WARN]  -Race requested but CGO not available - running tests without the race detector'
        } else {
            Write-Host '[INFO]  Running tests without the race detector (pass -Race to enable)'
        }
        $testResult = & go test ./... 2>&1
    }

    if ($LASTEXITCODE -ne 0) {
        Write-Host ($testResult -join "`n")
        Write-Error "Unit tests failed (exit code $LASTEXITCODE) - build aborted."
        exit 1
    }

    if (($testResult -join "`n") -match 'panic:') {
        Write-Host ($testResult -join "`n")
        Write-Error 'Test panic detected - build aborted.'
        exit 1
    }

    Write-Host '[OK]    All unit tests passed.'
    Write-Host ''

    # ---- Compilation ----
    $distDir = 'dist'
    if (Test-Path $distDir) {
        Remove-Item $distDir -Recurse -Force
    }

    # Build each target in a separate background process so GOOS/GOARCH are
    # isolated per target and the cross-compilations run in parallel. Each job
    # reports exactly one line: "OK <os>/<arch>" or "FAIL <os>/<arch> :: ...".
    $buildScript = {
        param($os, $arch, $outFile, $ldf, $useVend, $root)
        Push-Location $root
        try {
            $env:CGO_ENABLED = '0'   # fully static binary: no libc/CGo runtime dependency
            $env:GOOS = $os
            $env:GOARCH = $arch
            $goArgs = @('-trimpath', '-buildvcs=false')
            if ($useVend) { $goArgs += '-mod=vendor' }
            $goArgs += '-ldflags', $ldf, '-o', $outFile, './cmd/cfo/'
            $buildOut = & go build @goArgs 2>&1
            $code = $LASTEXITCODE
            if ($code -ne 0) {
                Write-Output "FAIL $os/$arch :: $($buildOut -join ' ')"
            }
            else {
                Write-Output "OK $os/$arch"
            }
        }
        finally {
            Pop-Location
        }
    }

    $jobs = @()
    foreach ($platform in $selectedPlatforms) {
        $parts = $platform -split '/'
        $targetOs = $parts[0]
        $targetArch = $parts[1]
        $targetDir = Join-Path (Join-Path $distDir "originals/$targetOs") $targetArch
        New-Item -ItemType Directory -Path $targetDir -Force | Out-Null

        $outputFile = if ($targetOs -eq 'windows') {
            Join-Path $targetDir 'cfo.exe'
        }
        else {
            Join-Path $targetDir 'cfo'
        }

        $ldflags = "-s -w -X main.GitCommit=$gitCommit -X main.Version=$Version"
        Write-Host "Building $platform -> $outputFile"
        $jobs += Start-Job -ArgumentList $targetOs, $targetArch, $outputFile, $ldflags, $useVendor, $scriptRoot -ScriptBlock $buildScript
    }

    $failed = @()
    foreach ($job in $jobs) {
        $null = Wait-Job $job
        $result = (Receive-Job $job | Out-String).Trim()
        if ($result -like 'OK *') {
            Write-Host "Built  $($result.Substring(3))"
        }
        else {
            Write-Host "FAILED: $result"
            $failed += $result
        }
        Remove-Job $job
    }
    if ($failed.Count -gt 0) {
        throw "Build failed:`n$($failed -join "`n")"
    }
}
finally {
    Pop-Location

    # Restore the caller's Go environment so this script leaves no side effects.
    foreach ($name in @('GOOS', 'GOARCH', 'CGO_ENABLED', 'GOTOOLCHAIN', 'GOPROXY', 'GOFLAGS')) {
        $original = $script:OriginalGoEnv[$name]
        if ($null -eq $original) {
            Remove-Item "Env:$name" -ErrorAction SilentlyContinue
        }
        else {
            Set-Item "Env:$name" -Value $original
        }
    }
}
