#!/bin/bash
#
# Script til at tvær-kompilere Go-programmet (cipherforge.go) til
# en omfattende liste af platforme.
#

# Stop scriptet øjeblikkeligt, hvis en kommando fejler
set -e

GIT_COMMIT=$(git rev-parse --short HEAD)
VERSION="1.00"

# Navnet på kildekoden
SOURCE_FILE="cipherforge.go"

# --- Definér Kompileringsmatrix ---
PLATFORMS=(
    "linux/amd64"    # Linux Server/Desktop (Standard)
    "linux/arm64"    # Linux ARM (Modern Servers, Raspberry Pi 64-bit)
    "linux/386"      # Linux 32-bit (Older systems)
    "windows/amd64"  # Windows 64-bit (Standard)
    "windows/386"    # Windows 32-bit
    "darwin/amd64"   # macOS Intel (Older Macs)
    "darwin/arm64"   # macOS Apple Silicon (M-series)
    "freebsd/amd64"  # FreeBSD
)

# Opret output mapper
mkdir -p bin
# 1. Opret mappe til originale filer
mkdir -p bin/unpacked
DIST_DIR=dist
mkdir -p ${DIST_DIR}

echo "Building version ${VERSION}, commit: ${GIT_COMMIT}"

echo "Starter tvær-kompilering af ${SOURCE_FILE}..."
echo "Total targets: ${#PLATFORMS[@]}"
echo "------------------------------------------------------"

# --- Kompileringsloop ---
for PLATFORM in "${PLATFORMS[@]}"; do
    # Split GOOS/GOARCH fra platformsvariablen
    TARGET_OS=$(echo $PLATFORM | cut -d '/' -f 1)
    TARGET_ARCH=$(echo $PLATFORM | cut -d '/' -f 2)

    # Bestem output filnavn og tilføj .exe for Windows
    if [ "${TARGET_OS}" = "windows" ]; then
        OUTPUT_NAME="cipherforge_${TARGET_OS}_${TARGET_ARCH}.exe"
    else
        OUTPUT_NAME="cipherforge_${TARGET_OS}_${TARGET_ARCH}"
    fi

    echo "Bygger: ${TARGET_OS}/${TARGET_ARCH} -> ${OUTPUT_NAME}"

    # Define the full path to the variable to inject
    LDFLAGS="-s -w -X github.com/vilshansen/cipherforge-go/constants.GitCommit=${GIT_COMMIT} -X github.com/vilshansen/cipherforge-go/constants.Version=${VERSION}"

    # Tvær-kompileringskommandoen gemmer originalen i 'bin/unpacked'
    # 1. Gem den originale, ukomprimerede fil her.
    GOOS=${TARGET_OS} GOARCH=${TARGET_ARCH} go build \
        -ldflags="${LDFLAGS}" \
        -o bin/unpacked/${OUTPUT_NAME} \
        ${SOURCE_FILE}

    # Kopier den ukomprimerede fil til 'bin/' før UPX, så UPX kan arbejde på den.
    cp bin/unpacked/${OUTPUT_NAME} bin/
done

cp -R bin ${DIST_DIR}/
tar -czvf ${DIST_DIR}/cipherforge_source.tar.gz --exclude=bin --exclude=.git .

echo "------------------------------------------------------"
echo "Kompilering fuldført for alle platforme!"
echo "Starter komprimering af understøttede filer i bin/*..."
echo "------------------------------------------------------"

# --- Komprimering ---
# 2. Ignorer FreeBSD og Darwin (macOS) eksplicit under UPX.
# UPX komprimerer filstørrelsen for Linux og Windows.
find bin/ -maxdepth 1 \
    -type f \
    ! -name "*darwin*" \
    ! -name "*freebsd*" \
    ! -path "*/unpacked/*" \
    -exec upx -9 "{}" \;

echo "------------------------------------------------------"
echo "Kompilering og komprimering fuldført!"
echo "Følgende komprimerede filer er klar til distribution (i bin/):"
ls -l bin/cipherforge_*

echo ""
echo "Originale (ukomprimerede) filer er gemt i bin/unpacked/."
ls -l bin/unpacked/cipherforge_*
