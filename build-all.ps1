[CmdletBinding()]
param(
    [Parameter()]
    [string]$Platforms = 'all',

    [Parameter()]
    [string]$Version = $env:VERSION,

    [Parameter()]
    [switch]$Help
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Show-Usage {
    Write-Host 'Usage: ./build-all.ps1 [-Platforms os/arch,...] [-Version version]'
    Write-Host ''
    Write-Host '  -Platforms  Comma-separated list of targets (default: all).'
    Write-Host '              Example: -Platforms linux/amd64,darwin/arm64'
    Write-Host ''
    Write-Host '  -Version    Overrides the version string (default: 4.0.0).'
}

if (-not $Version) {
    $Version = '4.0.0'
}

if ($Help) {
    Show-Usage
    exit 0
}

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Push-Location $scriptRoot

try {
    $gitCommit = (git rev-parse --short HEAD).Trim()
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
        Write-Error "Unit tests failed (exit code $LASTEXITCODE) - build aborted."
        Write-Host ($testResult -join "`n")
        exit 1
    }

    if (($testResult -join "`n") -match 'panic:') {
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
        $env:GOOS = $targetOs
        $env:GOARCH = $targetArch
        Write-Host "Building $platform -> $outputFile"
        & go build -ldflags=$ldflags -o $outputFile ./cmd/cfo/
        if ($LASTEXITCODE -ne 0) {
            throw "Build failed for $platform"
        }
    }
}
finally {
    Pop-Location
}
