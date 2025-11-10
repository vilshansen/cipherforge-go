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

DIST_DIR=dist

echo "Building version ${VERSION}, commit: ${GIT_COMMIT}"

echo "Starter tvær-kompilering af ${SOURCE_FILE}..."
echo "Total targets: ${#PLATFORMS[@]}"
echo "------------------------------------------------------"

rm -rf ${DIST_DIR}

# --- Kompileringsloop ---
for PLATFORM in "${PLATFORMS[@]}"; do
    # Split GOOS/GOARCH fra platformsvariablen
    TARGET_OS=$(echo $PLATFORM | cut -d '/' -f 1)
    TARGET_ARCH=$(echo $PLATFORM | cut -d '/' -f 2)

    mkdir -p ${DIST_DIR}/originals/${TARGET_OS}/${TARGET_ARCH}
    
    # Bestem output filnavn og tilføj .exe for Windows
    if [ "${TARGET_OS}" = "windows" ]; then
        DIST_OUTPUT_FILE=${DIST_DIR}/originals/${TARGET_OS}/${TARGET_ARCH}/"cfo.exe"
    else
        DIST_OUTPUT_FILE=${DIST_DIR}/originals/${TARGET_OS}/${TARGET_ARCH}/"cfo"
    fi

    echo "Bygger: ${TARGET_OS}/${TARGET_ARCH} -> ${DIST_OUTPUT_FILE}"

    # Define the full path to the variable to inject
    LDFLAGS="-s -w -X github.com/vilshansen/cipherforge-go/constants.GitCommit=${GIT_COMMIT} -X github.com/vilshansen/cipherforge-go/constants.Version=${VERSION}"

    # Tvær-kompileringskommandoen gemmer originalen i 'bin/originals'
    # 1. Gem den originale, ukomprimerede fil her.
    GOOS=${TARGET_OS} GOARCH=${TARGET_ARCH} go build \
        -ldflags="${LDFLAGS}" \
        -o ${DIST_OUTPUT_FILE} \
        ${SOURCE_FILE}

    # Kopier den ukomprimerede fil til 'bin/' før UPX, så UPX kan arbejde på den.
    mkdir -p ${DIST_DIR}/compressed/${TARGET_OS}/${TARGET_ARCH}
    cp ${DIST_OUTPUT_FILE} ${DIST_DIR}/compressed/${TARGET_OS}/${TARGET_ARCH}
done

tar -czf ${DIST_DIR}/cipherforge_source.tar.gz --exclude=dist --exclude=.git .

echo "------------------------------------------------------"
echo "Kompilering fuldført for alle platforme!"
echo "Starter komprimering af understøttede filer i dist/compressed/*..."
echo "------------------------------------------------------"

# --- Komprimering ---
# 2. Ignorer FreeBSD og Darwin (macOS) eksplicit under UPX.
# UPX komprimerer filstørrelsen for Linux og Windows.
find ${DIST_DIR}/compressed/ \
    -type f \
    ! -path "*darwin*" \
    ! -path "*freebsd*" \
    -exec upx -9 "{}" \;

echo "------------------------------------------------------"
echo "Kompilering og komprimering fuldført!"
echo "Følgende filer er klar til distribution (originale filer ligger i mappen originals):"
find ${DIST_DIR} -type f
