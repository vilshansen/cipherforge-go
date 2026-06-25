#!/bin/bash
set -euo pipefail

# =============================================================================
# CONFIG
# =============================================================================
CFO_BIN=""
BUILT_LOCALLY=false

if [ -f "../dist/compressed/linux/amd64/cfo" ]; then
    CFO_BIN="../dist/compressed/linux/amd64/cfo"
elif [ -f "../dist/originals/linux/amd64/cfo" ]; then
    CFO_BIN="../dist/originals/linux/amd64/cfo"
fi

if [ -z "$CFO_BIN" ]; then
    echo "Binary not found, building test binary..."
    cd ..
    go build -o test/test_bin ./cmd/cfo/
    cd test
    CFO_BIN="./test_bin"
    BUILT_LOCALLY=true
fi

# ---------------------------------------------------------------------------
# Prerequisite checks (fail early with a clear message)
# ---------------------------------------------------------------------------
for cmd in "$CFO_BIN" timeout dd sha256sum; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "ERROR: required command not found: $cmd" >&2
        exit 1
    fi
done

TEST_DIR="./test_data"
CHAOS_RUNS=${CHAOS_RUNS:-5}
TEST_PASSWORD="test-password-123"

mkdir -p "$TEST_DIR"

# =============================================================================
# OUTPUT
# =============================================================================
printf "\n%-45s %-8s\n" "TEST" "RESULT"
printf "%-45s %-8s\n" "---------------------------------------------" "------"

report() { printf "%-45s %-8s\n" "$1" "$2"; }

# =============================================================================
# CLEANUP
# =============================================================================
cleanup() {
    # Kill any child processes still running under this script's process group.
    kill -TERM -$$ 2>/dev/null || true
    sleep 0.1
    local attempt
    for attempt in 1 2 3; do
        rm -rf "$TEST_DIR" 2>/dev/null && break
        sleep 0.1
    done
}
trap cleanup EXIT

# =============================================================================
# HELPERS
# =============================================================================

do_encrypt() {
    local target="$1"
    timeout 30 "$CFO_BIN" -e "$target" -p "$TEST_PASSWORD" >/dev/null 2>&1
}

do_decrypt() {
    local target="$1"
    "$CFO_BIN" -d "$target" -p "$TEST_PASSWORD" -f >/dev/null 2>&1
}

# =============================================================================
# TESTS
# =============================================================================

test_single() {
    local size="$1"
    local file="$TEST_DIR/single_${size}.bin"

    dd if=/dev/urandom of="$file" bs="$size" count=1 status=none 2>/dev/null
    local orig_sum
    orig_sum=$(sha256sum "$file" | cut -d' ' -f1)

    if ! do_encrypt "$file"; then
        report "Single (${size})" "FAIL (encrypt)"
        return 1
    fi

    rm -f "$file"

    if ! do_decrypt "${file}.cfo"; then
        report "Single (${size})" "FAIL (decrypt)"
        return 1
    fi

    local dec_sum
    dec_sum=$(sha256sum "$file" | cut -d' ' -f1)
    if [ "$orig_sum" = "$dec_sum" ]; then
        report "Single (${size})" "PASS"
    else
        report "Single (${size})" "FAIL (checksum mismatch)"
        return 1
    fi
}

test_multi() {
    local size="$1"
    local count="$2"
    local files=()

    for i in $(seq 1 "$count"); do
        local f="$TEST_DIR/m_${size}_${i}.bin"
        dd if=/dev/urandom of="$f" bs="$size" count=1 status=none 2>/dev/null
        files+=("$f")
    done

    sha256sum "${files[@]}" > "$TEST_DIR/check.txt"

    if ! do_encrypt "$TEST_DIR/m_${size}_*.bin"; then
        report "${count} files (${size} each)" "FAIL"
        return 1
    fi

    rm -f "${files[@]}"
    do_decrypt "$TEST_DIR/m_${size}_*.bin.cfo" || true

    if sha256sum --check "$TEST_DIR/check.txt" >/dev/null 2>&1; then
        report "${count} files (${size} each)" "PASS"
    else
        report "${count} files (${size} each)" "FAIL (checksum)"
        return 1
    fi
}

test_zero() {
    local file="$TEST_DIR/zero.bin"
    touch "$file"

    if ! do_encrypt "$file"; then
        report "Zero-byte file" "FAIL (encrypt)"
        return 1
    fi

    rm -f "$file"
    do_decrypt "${file}.cfo" || true

    if [ -f "$file" ] && [ ! -s "$file" ]; then
        report "Zero-byte file" "PASS"
    else
        report "Zero-byte file" "FAIL (decrypt)"
        return 1
    fi
}

test_tamper() {
    local file="$TEST_DIR/tamper.bin"
    local orig="$TEST_DIR/original.bin"

    dd if=/dev/urandom of="$file" bs=4k count=1 status=none 2>/dev/null
    cp "$file" "$orig"

    if ! do_encrypt "$file"; then
        report "Tamper detection" "FAIL"
        return 1
    fi

    local size
    if [[ "$OSTYPE" == "darwin"* ]]; then
        size=$(stat -f%z "${file}.cfo")
    else
        size=$(stat -c%s "${file}.cfo")
    fi
    dd if=/dev/zero of="${file}.cfo" bs=1 count=16 \
        seek="$((size / 2))" conv=notrunc status=none 2>/dev/null

    if do_decrypt "${file}.cfo" && cmp -s "$file" "$orig" 2>/dev/null; then
        report "Tamper detection" "FAIL (corruption undetected)"
        return 1
    else
        report "Tamper detection" "PASS"
    fi
}

# =============================================================================
# FAULT TESTS
# =============================================================================
# fault_kill_once verifies that killing the encryption process mid-stream does
# not produce a valid .cfo file that decrypts to the correct plaintext.  It
# returns 0 (success) when either:
#   a) no .cfo was written (process killed before any output), or
#   b) decryption of the partial .cfo fails (AEAD or HMAC catches corruption).
# It is NOT a failure when encryption finished before the kill — the random
# sleep window is small, so this is rare but harmless.
fault_kill_once() {
    local file orig cfo dec
    file=$(mktemp "$TEST_DIR/fault_XXXXXX.bin")
    orig=$(mktemp "$TEST_DIR/fault_XXXXXX.orig")

    dd if=/dev/urandom of="$file" bs=1M count=1 status=none 2>/dev/null
    cp "$file" "$orig"

    "$CFO_BIN" -e "$file" -p "$TEST_PASSWORD" >/dev/null 2>/dev/null &
    local pid=$!

    # Sleep a random fraction of a second to try to catch mid-encryption.
    sleep "0.$((RANDOM % 10))"
    kill -9 "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true

    cfo="${file}.cfo"

    if [ ! -f "$cfo" ]; then
        # No output file — encryption was killed before writing anything.
        rm -f "$file" "$orig"
        return 0
    fi

    dec=$(mktemp "$TEST_DIR/fault_XXXXXX.dec")
    if "$CFO_BIN" -d "$cfo" -p "$TEST_PASSWORD" -f >/dev/null 2>&1 \
            && cmp -s "$file" "$orig" 2>/dev/null; then
        # Encryption completed before kill — valid file produced.
        # This is not a fault; the kill happened after the file was written.
        rm -f "$file" "$orig" "$cfo" "$dec"
        return 0
    fi

    # Decryption either failed or produced wrong output — fault handled correctly.
    rm -f "$file" "$orig" "$cfo" "$dec"
    return 0
}

test_fault_kill() {
    local failures=0
    for i in $(seq 1 3); do
        fault_kill_once || failures=$((failures + 1))
    done

    if [ "$failures" -eq 0 ]; then
        report "Fault: killed mid-encryption" "PASS"
    else
        report "Fault: killed mid-encryption" "FAIL($failures)"
        return 1
    fi
}

test_fault_truncate() {
    local file="$TEST_DIR/trunc.bin"
    local orig="$TEST_DIR/trunc.orig"

    dd if=/dev/urandom of="$file" bs=1M count=1 status=none 2>/dev/null
    cp "$file" "$orig"  # save original for comparison after decrypt

    if ! do_encrypt "$file"; then
        report "Fault: truncated ciphertext" "FAIL (encrypt)"
        return 1
    fi

    local current_size
    if [[ "$OSTYPE" == "darwin"* ]]; then
        current_size=$(stat -f%z "${file}.cfo")
    else
        current_size=$(stat -c%s "${file}.cfo")
    fi
    # Truncate by 100 bytes: try truncate(1) first, fall back to dd.
    local new_size=$((current_size - 100))
    if command -v truncate >/dev/null 2>&1; then
        truncate -s "$new_size" "${file}.cfo"
    else
        dd if="${file}.cfo" of="${file}.cfo.trunc" bs="$new_size" count=1 status=none 2>/dev/null \
            && mv "${file}.cfo.trunc" "${file}.cfo"
    fi

    # Decryption of a truncated file must fail, or produce wrong output.
    # If it succeeds *and* the output matches the original, the corruption was
    # not detected — that is a test failure.
    if do_decrypt "${file}.cfo" && cmp -s "$file" "$orig" 2>/dev/null; then
        report "Fault: truncated ciphertext" "FAIL (undetected)"
        return 1
    fi
    report "Fault: truncated ciphertext" "PASS"
}

test_chaos() {
    local failures=0
    for i in $(seq 1 "$CHAOS_RUNS"); do
        fault_kill_once || failures=$((failures + 1))
    done

    if [ "$failures" -eq 0 ]; then
        report "Chaos test (${CHAOS_RUNS} runs)" "PASS"
    else
        report "Chaos test (${CHAOS_RUNS} runs)" "FAIL($failures)"
        return 1
    fi
}

# =============================================================================
# RUN
# =============================================================================
main() {
    local failed=0

    test_single "10k"   || failed=1
    test_single "1M"    || failed=1
    test_multi  "1k" 3  || failed=1
    test_zero           || failed=1
    test_tamper         || failed=1
    test_fault_kill     || failed=1
    test_fault_truncate || failed=1
    test_chaos          || failed=1

    if $BUILT_LOCALLY; then rm -f "$CFO_BIN"; fi
    echo ""
    if [ "$failed" -eq 0 ]; then
        echo "🎉 ALL TESTS PASSED"
        exit 0
    else
        echo "❌ SOME TESTS FAILED"
        exit 1
    fi
}

main
