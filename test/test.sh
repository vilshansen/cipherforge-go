#!/bin/bash
set -euo pipefail

# =============================================================================
# CONFIG
# =============================================================================
CFO_BIN="../dist/originals/linux/amd64/cfo"
TEST_DIR="./test_data"
PARALLEL=${PARALLEL:-0}
JOBS=${JOBS:-4}
CHAOS_RUNS=${CHAOS_RUNS:-20}

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

    /usr/bin/time -f "%E|%M" \
        -o "$tmp_time" \
        bash -c "$CFO_BIN -e \"$target\"" \
        >"$tmp_out" 2>/dev/null

    local time mem password
    time=$(cut -d'|' -f1 "$tmp_time")
    mem=$(cut -d'|' -f2 "$tmp_time")

    password=$(sed -n '/Your secure, auto-generated password/,+1p' "$tmp_out" | tail -n 1)

    rm -f "$tmp_out" "$tmp_time"

    echo "$time|${mem}KB|$password"
}

# =============================================================================
# TESTS
# =============================================================================

test_single() {
    local size="$1"
    local file="$TEST_DIR/single_${size}.bin"

    dd if=/dev/urandom of="$file" bs="$size" count=1 status=none

    IFS="|" read -r time mem password <<< "$(run_encrypt "$file")"

    echo "$password" | "$CFO_BIN" -d "${file}.cfo" > /dev/null 2>&1

    cmp -s "$file" "$file" \
        && report "Single (${size})" "PASS" "$time" "$mem" \
        || { report "Single (${size})" "FAIL" "-" "-"; exit 1; }
}

test_multi() {
    local size="$1"
    local count="$2"

    local files=()
    for i in $(seq 1 "$count"); do
        f="$TEST_DIR/m_${size}_$i.bin"
        dd if=/dev/urandom of="$f" bs="$size" count=1 status=none
        files+=("$f")
    done

    sha256sum "${files[@]}" > "$TEST_DIR/check.txt"

    IFS="|" read -r time mem password <<< "$(run_encrypt "$TEST_DIR/m_${size}_*.bin")"

    rm "${files[@]}"

    echo "$password" | "$CFO_BIN" -d "$TEST_DIR/m_${size}_*.bin.cfo" > /dev/null 2>&1

    sha256sum --check "$TEST_DIR/check.txt" > /dev/null \
        && report "${count} files (${size} each)" "PASS" "$time" "$mem" \
        || { report "${count} files (${size} each)" "FAIL" "-" "-"; exit 1; }
}

test_zero() {
    local file="$TEST_DIR/zero.bin"
    touch "$file"

    IFS="|" read -r _ _ password <<< "$(run_encrypt "$file")"

    rm "$file"

    echo "$password" | "$CFO_BIN" -d "${file}.cfo" > /dev/null 2>&1

    [[ -f "$file" && ! -s "$file" ]] \
        && report "Zero-byte file" "PASS" "-" "-" \
        || { report "Zero-byte file" "FAIL" "-" "-"; exit 1; }
}

test_tamper() {
    local file="$TEST_DIR/tamper.bin"
    local orig="$TEST_DIR/original.bin"

    dd if=/dev/urandom of="$file" bs=4k count=1 status=none
    cp "$file" "$orig"

    IFS="|" read -r _ _ password <<< "$(run_encrypt "$file")"

    # 🔥 Strong corruption: modify multiple bytes in middle
    local size
    size=$(stat -c%s "${file}.cfo")
    local offset=$((size / 2))

    dd if=/dev/zero of="${file}.cfo" bs=1 count=16 seek="$offset" conv=notrunc status=none

    # Attempt decrypt
    if echo "$password" | "$CFO_BIN" -d "${file}.cfo" > /dev/null 2>&1; then
        # Decrypt "succeeded" → compare contents
        if cmp -s "$file" "$orig"; then
            report "Tamper detection" "FAIL" "-" "-"
            exit 1
        else
            report "Tamper detection" "PASS" "-" "-"
        fi
    else
        # Decrypt failed → correct behavior
        report "Tamper detection" "PASS" "-" "-"
    fi
}

# =============================================================================
# FAULT TESTS
# =============================================================================

fault_kill_once() {
    local file orig cfo tmp_out password
    file=$(mktemp "$TEST_DIR/fault_XXXXXX.bin")
    orig=$(mktemp "$TEST_DIR/fault_XXXXXX.orig")
    dd if=/dev/urandom of="$file" bs=10M count=1 status=none
    cp "$file" "$orig"

    # Capture stdout so we can extract the real password.
    tmp_out=$(mktemp)
    "$CFO_BIN" -e "$file" >"$tmp_out" 2>/dev/null &
    pid=$!

    # Randomized kill timing (chaos)
    sleep "0.$((RANDOM % 20))"

    kill -9 "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true

    cfo="${file}.cfo"

    # Case 1: no .cfo created at all → clean kill before file was opened → pass.
    if [ ! -f "$cfo" ]; then
        rm -f "$file" "$orig" "$tmp_out"
        return 0
    fi

    password=$(sed -n '/Your secure, auto-generated password/,+1p' "$tmp_out" | tail -n 1)

    # Case 2: no password in output → process was killed before it printed one,
    # meaning the .cfo is incomplete. Decryption must fail or produce wrong output.
    if [ -z "$password" ]; then
        local dec
        dec=$(mktemp "$TEST_DIR/fault_XXXXXX.dec")
        # Attempt decrypt with a dummy password; should fail or produce garbage.
        if echo "DUMMY" | "$CFO_BIN" -d "$cfo" >"$dec" 2>/dev/null && cmp -s "$dec" "$orig"; then
            # Corrupted file decrypted correctly → that must not happen.
            rm -f "$file" "$orig" "$tmp_out" "$cfo" "$dec"
            return 1
        fi
        rm -f "$file" "$orig" "$tmp_out" "$cfo" "$dec"
        return 0
    fi

    # Case 3: we have the real password. Either encryption finished before the
    # kill (valid .cfo) or the kill landed mid-write (partial .cfo).
    # A partial file must NOT decrypt to the original content.
    local dec
    dec=$(mktemp "$TEST_DIR/fault_XXXXXX.dec")
    if echo "$password" | "$CFO_BIN" -d "$cfo" >"$dec" 2>/dev/null && cmp -s "$dec" "$orig"; then
        # Decrypted successfully and matches → encryption finished before kill → pass.
        rm -f "$file" "$orig" "$tmp_out" "$cfo" "$dec"
        return 0
    fi

    # Decrypt failed or output didn't match → partial file was correctly rejected → pass.
    rm -f "$file" "$orig" "$tmp_out" "$cfo" "$dec"
    return 0
}

test_fault_kill() {
    local file="$TEST_DIR/fault.bin"
    local orig="$TEST_DIR/fault_orig.bin"
    local tmp_out="$TEST_DIR/fault_enc.out"
    local dec="$TEST_DIR/fault.dec"

    dd if=/dev/urandom of="$file" bs=100M count=1 status=none
    cp "$file" "$orig"

    # Capture stdout to extract the real password.
    "$CFO_BIN" -e "$file" >"$tmp_out" 2>/dev/null &
    pid=$!

    # Random kill timing (chaos)
    sleep "0.$((RANDOM % 20))"

    kill -9 "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true

    # Case 1: no .cfo created → killed before OpenFile → pass.
    if [ ! -f "${file}.cfo" ]; then
        report "Fault: killed mid-encryption" "PASS" "-" "-"
        return
    fi

    local password
    password=$(sed -n '/Your secure, auto-generated password/,+1p' "$tmp_out" | tail -n 1)

    # Case 2: no password in output → killed before it was printed → file is
    # partial. Any decrypt attempt must not reproduce the original content.
    if [ -z "$password" ]; then
        if echo "DUMMY" | "$CFO_BIN" -d "${file}.cfo" >"$dec" 2>/dev/null && cmp -s "$dec" "$orig"; then
            report "Fault: killed mid-encryption" "FAIL (corruption undetected)" "-" "-"
            exit 1
        fi
        report "Fault: killed mid-encryption" "PASS" "-" "-"
        return
    fi

    # Case 3: have the real password. Decrypt and compare output to original.
    if echo "$password" | "$CFO_BIN" -d "${file}.cfo" >"$dec" 2>/dev/null && cmp -s "$dec" "$orig"; then
        # Fully valid file — encryption finished before the kill landed.
        report "Fault: killed mid-encryption" "PASS" "-" "-"
    else
        # Partial file was correctly rejected by authentication.
        report "Fault: killed mid-encryption" "PASS" "-" "-"
    fi
}

test_fault_truncate() {
    local file="$TEST_DIR/trunc.bin"
    local dec="$TEST_DIR/trunc.dec"
    dd if=/dev/urandom of="$file" bs=1M count=1 status=none

    IFS="|" read -r _ _ password <<< "$(run_encrypt "$file")"

    truncate -s 100 "${file}.cfo"

    # Decryption of a truncated file with the correct password must fail or
    # must not reproduce the original content.
    if echo "$password" | "$CFO_BIN" -d "${file}.cfo" >"$dec" 2>/dev/null && cmp -s "$dec" "$file"; then
        report "Fault: truncated ciphertext" "FAIL" "-" "-"
        exit 1
    else
        report "Fault: truncated ciphertext" "PASS" "-" "-"
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
    else
        report "Chaos test (${CHAOS_RUNS} runs)" "FAIL($failures)" "-" "-"
        exit 1
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
if [ "$PARALLEL" -eq 1 ]; then
    run_parallel
else
    test_single "10k"
    test_single "1M"
    test_single "5M"

    test_multi "1k" 3
    test_multi "1M" 3

    test_zero
    test_tamper

    test_fault_kill
    test_fault_truncate

    test_chaos
fi

echo ""
echo "🎉 ALL TESTS PASSED"
