[CmdletBinding()]
param(
    [Parameter()]
    [string]$Platforms = 'all',

    [Parameter()]
    [string]$Version = $env:VERSION,

    [Parameter()]
    [switch]$Vendor,

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
    Write-Host '  -Version    Overrides the version string (default: 5.0.2).'
    Write-Host ''
    Write-Host '  -Vendor     Run "go mod vendor" first to create the local vendor/'
    Write-Host '              directory (requires network), then build fully offline.'
}

if (-not $Version) {
    $Version = '5.0.2'
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

    $cgoEnabled = (go env CGO_ENABLED) -eq '1'
    if ($cgoEnabled) {
        Write-Host '[INFO]  Race detector enabled (CGO is available)'
        $testResult = & go test -race -v ./... 2>&1
    } else {
        Write-Host '[WARN]  Race detector disabled - CGO not available (install gcc/mingw-w64 to enable)'
        $testResult = & go test -v ./... 2>&1
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
        $env:CGO_ENABLED = '0'   # fully static binary: no libc/CGo runtime dependency
        $env:GOOS = $targetOs
        $env:GOARCH = $targetArch
        Write-Host "Building $platform -> $outputFile"
        $buildArgs = @('-trimpath', '-buildvcs=false')
        if ($useVendor) { $buildArgs += '-mod=vendor' }
        $buildArgs += '-ldflags', $ldflags, '-o', $outputFile, './cmd/cfo/'
        & go build @buildArgs
        if ($LASTEXITCODE -ne 0) {
            throw "Build failed for $platform"
        }
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
