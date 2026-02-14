#!/bin/bash

set -e

GIT_COMMIT=$(git rev-parse --short HEAD)
VERSION="1.00"

SOURCE_FILE="cipherforge.go"

PLATFORMS=(
    "linux/amd64"    # Linux Server/Desktop (Standard)
)

DIST_DIR=dist

echo "Building version ${VERSION}, commit: ${GIT_COMMIT}"

echo "Starting cross-compilation of ${SOURCE_FILE}..."
echo "Total targets: ${#PLATFORMS[@]}"
echo "------------------------------------------------------"

rm -rf ${DIST_DIR}

for PLATFORM in "${PLATFORMS[@]}"; do
    TARGET_OS=$(echo $PLATFORM | cut -d '/' -f 1)
    TARGET_ARCH=$(echo $PLATFORM | cut -d '/' -f 2)

    mkdir -p ${DIST_DIR}/originals/${TARGET_OS}/${TARGET_ARCH}
    
    if [ "${TARGET_OS}" = "windows" ]; then
        DIST_OUTPUT_FILE=${DIST_DIR}/originals/${TARGET_OS}/${TARGET_ARCH}/"cfo.exe"
    else
        DIST_OUTPUT_FILE=${DIST_DIR}/originals/${TARGET_OS}/${TARGET_ARCH}/"cfo"
    fi

    echo "Building: ${TARGET_OS}/${TARGET_ARCH} -> ${DIST_OUTPUT_FILE}"

    LDFLAGS="-s -w -X github.com/vilshansen/cipherforge-go/constants.GitCommit=${GIT_COMMIT} -X github.com/vilshansen/cipherforge-go/constants.Version=${VERSION}"

    GOOS=${TARGET_OS} GOARCH=${TARGET_ARCH} go build \
        -ldflags="${LDFLAGS}" \
        -o ${DIST_OUTPUT_FILE} \
        ${SOURCE_FILE}

    mkdir -p ${DIST_DIR}/compressed/${TARGET_OS}/${TARGET_ARCH}
    cp ${DIST_OUTPUT_FILE} ${DIST_DIR}/compressed/${TARGET_OS}/${TARGET_ARCH}
done

tar -czf ${DIST_DIR}/cipherforge_source.tar.gz --exclude=dist --exclude=.git .

echo "------------------------------------------------------"
echo "Compilation for all platforms completed!"
echo "Starting compression of all supported files in dist/compressed/*..."
echo "------------------------------------------------------"

# Ignore FreeBSD and Darwin (macOS) explicitly.
find ${DIST_DIR}/compressed/ \
    -type f \
    ! -path "*darwin*" \
    ! -path "*freebsd*" \
    -exec upx -9 "{}" \;

echo "------------------------------------------------------"
echo "Compilation and compression completed!"
echo "Following files are ready for distribution (original, uncompressed files found in the originals folder):"
find ${DIST_DIR} -type f
