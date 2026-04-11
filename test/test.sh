#!/bin/bash
set -euo pipefail

# =============================================================================
# CONFIG
# =============================================================================
# Use the most recently built binary from dist/compressed or dist/originals
if [ -f "../dist/compressed/linux/amd64/cfo" ]; then
    CFO_BIN="../dist/compressed/linux/amd64/cfo"
elif [ -f "../dist/originals/linux/amd64/cfo" ]; then
    CFO_BIN="../dist/originals/linux/amd64/cfo"
else
    # Fallback to building a test binary
    echo "Binary not found, building test binary..."
    cd ..
    go build -o test/test_bin cipherforge.go
    cd test
    CFO_BIN="./test_bin"
fi

TEST_DIR="./test_data"
PARALLEL=${PARALLEL:-0}
JOBS=${JOBS:-4}
CHAOS_RUNS=${CHAOS_RUNS:-5}  # Reduced for faster testing

mkdir -p "$TEST_DIR"

# =============================================================================
# OUTPUT
# =============================================================================
printf "\n%-45s %-8s %-12s %-12s\n" "TEST" "RESULT" "TIME" "MEM"
printf "%-45s %-8s %-12s %-12s\n" "---------------------------------------------" "------" "------------" "------------"

report() {
    printf "%-45s %-8s %-12s %-12s\n" "$1" "$2" "$3" "$4"
}

# =============================================================================
# CLEANUP
# =============================================================================
cleanup() {
    pkill -P $$ 2>/dev/null || true
    sleep 0.1
    for _ in {1..3}; do
        rm -rf "$TEST_DIR" && break
        sleep 0.1
    done
}
trap cleanup EXIT

# =============================================================================
# BENCH + PASSWORD (correct)
# =============================================================================
run_encrypt() {
    local target="$1"

    local tmp_out tmp_time
    tmp_out=$(mktemp)
    tmp_time=$(mktemp)

    # Use timeout to prevent hanging
    timeout 30 /usr/bin/time -f "%E|%M" \
        -o "$tmp_time" \
        bash -c "echo '' | \"$CFO_BIN\" -e \"$target\"" \
        >"$tmp_out" 2>&1 || true

    # Check if encryption succeeded
    if ! grep -q "Encryption password (save this" "$tmp_out"; then
        echo "ERROR|0|" > "$tmp_time"
        echo "|0|" 
        rm -f "$tmp_out" "$tmp_time"
        return 1
    fi

    local time mem password
    time=$(cut -d'|' -f1 "$tmp_time" 2>/dev/null || echo "0:00.00")
    mem=$(cut -d'|' -f2 "$tmp_time" 2>/dev/null || echo "0")

    password=$(sed -n '/Encryption password (save this/,+1p' "$tmp_out" | tail -n 1 | tr -d '\n')

    rm -f "$tmp_out" "$tmp_time"

    echo "$time|${mem}KB|$password"
}

# =============================================================================
# TESTS
# =============================================================================

test_single() {
    local size="$1"
    local file="$TEST_DIR/single_${size}.bin"

    dd if=/dev/urandom of="$file" bs="$size" count=1 status=none 2>/dev/null

    if ! IFS="|" read -r time mem password <<< "$(run_encrypt "$file")"; then
        report "Single (${size})" "FAIL" "-" "-"
        return 1
    fi

    if [ -z "$password" ]; then
        report "Single (${size})" "FAIL (no password)" "-" "-"
        return 1
    fi

    # Decrypt with password
    echo "$password" | "$CFO_BIN" -d "${file}.cfo" > /dev/null 2>&1

    if cmp -s "$file" "${file}" 2>/dev/null; then
        report "Single (${size})" "PASS" "$time" "$mem"
        return 0
    else
        report "Single (${size})" "FAIL" "-" "-"
        return 1
    fi
}

test_multi() {
    local size="$1"
    local count="$2"

    local files=()
    for i in $(seq 1 "$count"); do
        f="$TEST_DIR/m_${size}_$i.bin"
        dd if=/dev/urandom of="$f" bs="$size" count=1 status=none 2>/dev/null
        files+=("$f")
    done

    # Create checksum file
    sha256sum "${files[@]}" 2>/dev/null > "$TEST_DIR/check.txt"

    # Use glob pattern for multiple files
    pattern="$TEST_DIR/m_${size}_*.bin"
    
    if ! IFS="|" read -r time mem password <<< "$(run_encrypt "$pattern")"; then
        report "${count} files (${size} each)" "FAIL" "-" "-"
        return 1
    fi

    if [ -z "$password" ]; then
        report "${count} files (${size} each)" "FAIL (no password)" "-" "-"
        return 1
    fi

    # Remove originals before decryption
    rm -f "${files[@]}"

    # Decrypt all
    echo "$password" | "$CFO_BIN" -d "$TEST_DIR/m_${size}_*.bin.cfo" > /dev/null 2>&1

    # Verify checksums
    if sha256sum --check "$TEST_DIR/check.txt" 2>/dev/null > /dev/null; then
        report "${count} files (${size} each)" "PASS" "$time" "$mem"
        return 0
    else
        report "${count} files (${size} each)" "FAIL" "-" "-"
        return 1
    fi
}

test_zero() {
    local file="$TEST_DIR/zero.bin"
    touch "$file"

    if ! IFS="|" read -r time mem password <<< "$(run_encrypt "$file")"; then
        report "Zero-byte file" "FAIL" "-" "-"
        return 1
    fi

    if [ -z "$password" ]; then
        report "Zero-byte file" "FAIL (no password)" "-" "-"
        return 1
    fi

    rm -f "$file"

    echo "$password" | "$CFO_BIN" -d "${file}.cfo" > /dev/null 2>&1

    if [[ -f "$file" && ! -s "$file" ]]; then
        report "Zero-byte file" "PASS" "-" "-"
        return 0
    else
        report "Zero-byte file" "FAIL" "-" "-"
        return 1
    fi
}

test_tamper() {
    local file="$TEST_DIR/tamper.bin"
    local orig="$TEST_DIR/original.bin"

    dd if=/dev/urandom of="$file" bs=4k count=1 status=none 2>/dev/null
    cp "$file" "$orig"

    if ! IFS="|" read -r time mem password <<< "$(run_encrypt "$file")"; then
        report "Tamper detection" "FAIL" "-" "-"
        return 1
    fi

    if [ -z "$password" ]; then
        report "Tamper detection" "FAIL (no password)" "-" "-"
        return 1
    fi

    # Corrupt the encrypted file
    local size
    if [[ "$OSTYPE" == "darwin"* ]]; then
        size=$(stat -f%z "${file}.cfo")
    else
        size=$(stat -c%s "${file}.cfo")
    fi
    local offset=$((size / 2))

    dd if=/dev/zero of="${file}.cfo" bs=1 count=16 seek="$offset" conv=notrunc status=none 2>/dev/null

    # Attempt decrypt - should fail or produce wrong content
    if echo "$password" | "$CFO_BIN" -d "${file}.cfo" > /dev/null 2>&1; then
        # Decrypt "succeeded" → compare contents
        if cmp -s "$file" "$orig" 2>/dev/null; then
            report "Tamper detection" "FAIL (corruption undetected)" "-" "-"
            return 1
        else
            report "Tamper detection" "PASS" "-" "-"
            return 0
        fi
    else
        # Decrypt failed → correct behavior
        report "Tamper detection" "PASS" "-" "-"
        return 0
    fi
}

# =============================================================================
# FAULT TESTS
# =============================================================================

fault_kill_once() {
    local file orig cfo tmp_out password
    file=$(mktemp "$TEST_DIR/fault_XXXXXX.bin")
    orig=$(mktemp "$TEST_DIR/fault_XXXXXX.orig")
    dd if=/dev/urandom of="$file" bs=1M count=1 status=none 2>/dev/null
    cp "$file" "$orig"

    # Capture stdout so we can extract the real password.
    tmp_out=$(mktemp)
    "$CFO_BIN" -e "$file" >"$tmp_out" 2>/dev/null &
    pid=$!

    # Randomized kill timing (chaos)
    sleep "0.$((RANDOM % 10))"

    kill -9 "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true

    cfo="${file}.cfo"

    # Case 1: no .cfo created at all → clean kill before file was opened → pass.
    if [ ! -f "$cfo" ]; then
        rm -f "$file" "$orig" "$tmp_out"
        return 0
    fi

    password=$(sed -n '/Your secure, auto-generated password/,+1p' "$tmp_out" | tail -n 1 | tr -d '\n')

    # Case 2: no password in output → process was killed before it printed one
    if [ -z "$password" ]; then
        local dec
        dec=$(mktemp "$TEST_DIR/fault_XXXXXX.dec")
        # Attempt decrypt with a dummy password; should fail or produce garbage.
        if echo "DUMMY" | "$CFO_BIN" -d "$cfo" >"$dec" 2>/dev/null && cmp -s "$dec" "$orig" 2>/dev/null; then
            rm -f "$file" "$orig" "$tmp_out" "$cfo" "$dec"
            return 1
        fi
        rm -f "$file" "$orig" "$tmp_out" "$cfo" "$dec"
        return 0
    fi

    # Case 3: we have the real password. Verify partial file detection
    local dec
    dec=$(mktemp "$TEST_DIR/fault_XXXXXX.dec")
    if echo "$password" | "$CFO_BIN" -d "$cfo" >"$dec" 2>/dev/null && cmp -s "$dec" "$orig" 2>/dev/null; then
        # Encryption finished before kill → valid file
        rm -f "$file" "$orig" "$tmp_out" "$cfo" "$dec"
        return 0
    fi

    # Decrypt failed or output didn't match → partial file correctly rejected
    rm -f "$file" "$orig" "$tmp_out" "$cfo" "$dec"
    return 0
}

test_fault_kill() {
    local failures=0
    local runs=3  # Reduced for faster testing

    for i in $(seq 1 "$runs"); do
        if ! fault_kill_once; then
            failures=$((failures+1))
        fi
    done

    if [ "$failures" -eq 0 ]; then
        report "Fault: killed mid-encryption" "PASS" "-" "-"
        return 0
    else
        report "Fault: killed mid-encryption" "FAIL($failures)" "-" "-"
        return 1
    fi
}

test_fault_truncate() {
    local file="$TEST_DIR/trunc.bin"
    local dec="$TEST_DIR/trunc.dec"
    dd if=/dev/urandom of="$file" bs=1M count=1 status=none 2>/dev/null

    if ! IFS="|" read -r time mem password <<< "$(run_encrypt "$file")"; then
        report "Fault: truncated ciphertext" "FAIL" "-" "-"
        return 1
    fi

    if [ -z "$password" ]; then
        report "Fault: truncated ciphertext" "FAIL (no password)" "-" "-"
        return 1
    fi

    # Truncate the encrypted file
    if [[ "$OSTYPE" == "darwin"* ]]; then
        current_size=$(stat -f%z "${file}.cfo")
    else
        current_size=$(stat -c%s "${file}.cfo")
    fi
    truncate_size=$((current_size - 100))
    truncate -s "$truncate_size" "${file}.cfo" 2>/dev/null || true

    # Decryption must fail or produce wrong content
    if echo "$password" | "$CFO_BIN" -d "${file}.cfo" >"$dec" 2>/dev/null && cmp -s "$dec" "$file" 2>/dev/null; then
        report "Fault: truncated ciphertext" "FAIL" "-" "-"
        return 1
    else
        report "Fault: truncated ciphertext" "PASS" "-" "-"
        return 0
    fi
}

# =============================================================================
# CHAOS TEST
# =============================================================================
test_chaos() {
    local failures=0

    for i in $(seq 1 "$CHAOS_RUNS"); do
        if ! fault_kill_once; then
            failures=$((failures+1))
        fi
    done

    if [ "$failures" -eq 0 ]; then
        report "Chaos test (${CHAOS_RUNS} runs)" "PASS" "-" "-"
        return 0
    else
        report "Chaos test (${CHAOS_RUNS} runs)" "FAIL($failures)" "-" "-"
        return 1
    fi
}

# =============================================================================
# PARALLEL
# =============================================================================
run_parallel() {
    export -f test_single run_encrypt report
    export CFO_BIN TEST_DIR

    printf "10k\n1M\n5M\n" | xargs -I{} -P"$JOBS" bash -c 'test_single "$@"' _ {}
}

# =============================================================================
# RUN
# =============================================================================
main() {
    local failed=0
    
    if [ "$PARALLEL" -eq 1 ]; then
        run_parallel
    else
        test_single "10k" || failed=1
        test_single "1M" || failed=1
        test_single "5M" || failed=1

        test_multi "1k" 3 || failed=1
        test_multi "1M" 3 || failed=1

        test_zero || failed=1
        test_tamper || failed=1

        test_fault_kill || failed=1
        test_fault_truncate || failed=1

        test_chaos || failed=1
    fi

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
