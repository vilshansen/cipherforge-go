#!/bin/bash

set -euo pipefail

GIT_COMMIT=$(git rev-parse --short HEAD)
VERSION="${VERSION:-3.1.0}"

SOURCE_FILE="cmd/cfo/main.go"

ALL_PLATFORMS=(
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

# -------------------------------------------------------
# Helpers
# -------------------------------------------------------

SEP="======================================================"
DASH="------------------------------------------------------"

info()    { echo "[INFO]  $*"; }
ok()      { echo "[OK]    $*"; }
warn()    { echo "[WARN]  $*"; }
fail()    { echo "[ERROR] $*" >&2; }

section() { echo ""; echo "${SEP}"; echo "  $*"; echo "${SEP}"; }
divider() { echo "${DASH}"; }

usage() {
    echo "Usage: $0 [--platforms os/arch,...]"
    echo ""
    echo "  --platforms  Comma-separated list of targets (default: all)."
    echo "               Example: --platforms linux/amd64,darwin/arm64"
    echo ""
    echo "  VERSION env var overrides the version string (default: ${VERSION})."
    exit 0
}

# -------------------------------------------------------
# Platform selection
# -------------------------------------------------------

PLATFORMS=("${ALL_PLATFORMS[@]}")

while [[ $# -gt 0 ]]; do
    case "$1" in
        --platforms)
            if [[ -z "$2" || "$2" == -* ]]; then
                fail "--platforms requires a comma-separated list"
                exit 1
            fi
            IFS=',' read -ra PLATFORMS <<< "$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            fail "Unknown argument: $1"
            usage
            exit 1
            ;;
    esac
done

# Validate platform list against known platforms
for p in "${PLATFORMS[@]}"; do
    found=false
    for ap in "${ALL_PLATFORMS[@]}"; do
        [[ "$p" == "$ap" ]] && found=true && break
    done
    if ! $found; then
        fail "Unknown platform: $p"
        info "Known: ${ALL_PLATFORMS[*]}"
        exit 1
    fi
done

# -------------------------------------------------------
# Prerequisite checks
# -------------------------------------------------------

section "Prerequisites"

for cmd in go git; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        fail "$cmd is required but not found in PATH"
        exit 1
    fi
done
ok "go $(go version | cut -d' ' -f3)"
ok "git $(git version | cut -d' ' -f3)"

if command -v upx >/dev/null 2>&1; then
    ok "upx $(upx --version 2>/dev/null | head -1 || echo 'found')"
else
    warn "upx not found — compression step will be skipped"
fi

# -------------------------------------------------------
# Header
# -------------------------------------------------------

section "Cipherforge Build"
info "Version  : ${VERSION}"
info "Commit   : ${GIT_COMMIT}"
info "Targets  : ${#PLATFORMS[@]}"

# -------------------------------------------------------
# Unit tests
# -------------------------------------------------------

section "Unit Tests"

go test -race -v ./... 2>&1 | tee test_output.log
test_rc=$?

if [ $test_rc -ne 0 ]; then
    fail "Unit tests failed (exit code $test_rc) — build aborted."
    rm -f test_output.log
    exit 1
fi

if grep -q "panic:" test_output.log; then
    fail "Test panic detected — build aborted."
    rm -f test_output.log
    exit 1
fi

ok "All unit tests passed."
rm -f test_output.log

# -------------------------------------------------------
# Integration tests
# -------------------------------------------------------

section "Integration Tests"

if [ -f "test/test.sh" ]; then
    ( cd test
      chmod +x test.sh
      ./test.sh
    ) || {
        fail "Integration tests failed — build aborted."
        exit 1
    }
    ok "All integration tests passed."
else
    warn "test/test.sh not found — skipping integration tests."
fi

# -------------------------------------------------------
# Compilation
# -------------------------------------------------------

section "Compilation"

# Safety check: DIST_DIR must be a non-empty subdirectory of the project root,
# not something that could cause catastrophic deletion.
if [ -z "${DIST_DIR}" ] || [ "${DIST_DIR}" = "/" ] || [ "${DIST_DIR}" = "." ] || [ "${DIST_DIR}" = ".." ]; then
    fail "DIST_DIR sanity check failed: '${DIST_DIR}'"
    exit 1
fi
rm -rf "${DIST_DIR}"

PASS=0
FAIL=0

for PLATFORM in "${PLATFORMS[@]}"; do
    TARGET_OS="${PLATFORM%%/*}"
    TARGET_ARCH="${PLATFORM##*/}"

    mkdir -p "${DIST_DIR}/originals/${TARGET_OS}/${TARGET_ARCH}"

    if [ "${TARGET_OS}" = "windows" ]; then
        DIST_OUTPUT_FILE="${DIST_DIR}/originals/${TARGET_OS}/${TARGET_ARCH}/cfo.exe"
    else
        DIST_OUTPUT_FILE="${DIST_DIR}/originals/${TARGET_OS}/${TARGET_ARCH}/cfo"
    fi

    LDFLAGS="-s -w -X main.GitCommit=${GIT_COMMIT} -X main.Version=${VERSION}"

    if GOOS=${TARGET_OS} GOARCH=${TARGET_ARCH} go build \
            -ldflags="${LDFLAGS}" \
            -o "${DIST_OUTPUT_FILE}" \
            "${SOURCE_FILE}" 2>&1; then
        ok "Built  ${TARGET_OS}/${TARGET_ARCH} -> ${DIST_OUTPUT_FILE}"
        mkdir -p "${DIST_DIR}/compressed/${TARGET_OS}/${TARGET_ARCH}"
        cp "${DIST_OUTPUT_FILE}" "${DIST_DIR}/compressed/${TARGET_OS}/${TARGET_ARCH}"
        PASS=$((PASS + 1))
    else
        fail "Failed ${TARGET_OS}/${TARGET_ARCH}"
        FAIL=$((FAIL + 1))
    fi
done

divider
info "Compiled: ${PASS} succeeded, ${FAIL} failed."

if [ "${FAIL}" -gt 0 ]; then
    fail "One or more targets failed to compile — aborting."
    exit 1
fi

# -------------------------------------------------------
# Checksums
# -------------------------------------------------------

section "Checksums"

( cd "${DIST_DIR}/originals"
  find . -type f | sort | while read -r f; do
      sha256sum "${f}" >> ../checksums.txt
  done
)

while read -r hash path; do
    ok "${path}"
done < "${DIST_DIR}/checksums.txt"

info "SHA256 checksums written to ${DIST_DIR}/checksums.txt"

# -------------------------------------------------------
# Source archive
# -------------------------------------------------------

section "Source Archive"

tar -czf "${DIST_DIR}/cipherforge_source.tar.gz" --exclude=dist --exclude=.git .
ok "Source archive -> ${DIST_DIR}/cipherforge_source.tar.gz"

# -------------------------------------------------------
# Compression (UPX)
# -------------------------------------------------------

section "UPX Compression"

find "${DIST_DIR}/compressed/" \
    -type f \
    | while read -r f; do
        if upx -9 "${f}" > /dev/null 2>&1; then
            ok "Compressed ${f}"
        else
            warn "UPX skipped  ${f}"
        fi
    done

# -------------------------------------------------------
# Summary
# -------------------------------------------------------

section "Output Files"

find "${DIST_DIR}" -type f | sort | while read -r f; do
    SIZE=$(du -sh "${f}" 2>/dev/null | cut -f1)
    printf "  %-55s %s\n" "${f}" "${SIZE}"
done

echo ""
ok "Build complete — version ${VERSION} (${GIT_COMMIT})."
echo ""
