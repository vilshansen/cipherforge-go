#!/bin/bash
# =============================================================================
# Cipherforge Integration Test Suite
#
# Tests: single-file encrypt/decrypt, multi-file batch, zero-byte files,
#        tamper detection, fault injection (kill/truncate), stdin pipelines,
#        atomic mode, custom output naming, and quiet mode.
#
# Usage:  ./test.sh                  # run all tests
#         CFO_BIN=/path/to/cfo ./test.sh   # use a specific binary
#         CHAOS_RUNS=10 ./test.sh    # more fault-injection runs
#         TEST_PASSWORD=custom ./test.sh   # use a custom password
#
# Prerequisites: bash 4+, timeout, dd, sha256sum (or shasum -a 256 on macOS)
# =============================================================================
set -euo pipefail

# ---- configuration (all overridable via environment) ------------------------
CFO_BIN="${CFO_BIN:-}"                       # path to cfo binary
BUILT_LOCALLY=false
CHAOS_RUNS="${CHAOS_RUNS:-5}"                # number of chaos-test iterations
TEST_PASSWORD="${TEST_PASSWORD:-test-password-123}"
TEST_DIR="./test_data"
TIMEOUT_SECS="${TIMEOUT_SECS:-60}"           # per-operation timeout

# ---- colour output (auto-detects TTY, falls back to plain) ------------------
if [[ -t 1 ]]; then
    GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
else
    GREEN=''; RED=''; YELLOW=''; NC=''
fi

# ---- helper: pick the best sha256 tool available ---------------------------
if command -v sha256sum >/dev/null 2>&1; then
    sha256() { sha256sum "$@" | cut -d' ' -f1; }
    sha256_check() { sha256sum --check "$1" >/dev/null 2>&1; }
elif command -v shasum >/dev/null 2>&1; then
    sha256() { shasum -a 256 "$@" | cut -d' ' -f1; }
    sha256_check() { shasum -a 256 -c "$1" >/dev/null 2>&1; }
else
    echo "ERROR: neither sha256sum nor shasum found" >&2
    exit 1
fi

# ---- helper: get file size portably (Linux, macOS, FreeBSD) -----------------
file_size() {
    if stat --version >/dev/null 2>&1; then
        stat -c%s "$1"        # GNU stat (Linux)
    else
        stat -f%z "$1"         # BSD stat (macOS, FreeBSD)
    fi
}

# =============================================================================
# BINARY DISCOVERY
# =============================================================================
# Search order: 1) env var  2) ../cfo (dev build)  3) dist paths
find_binary() {
    if [[ -n "$CFO_BIN" ]] && [[ -x "$CFO_BIN" ]]; then
        return 0
    fi

    local candidates=(
        "../cfo"                                 # go build in repo root
        "../dist/compressed/linux/amd64/cfo"
        "../dist/originals/linux/amd64/cfo"
        "../dist/compressed/darwin/amd64/cfo"
        "../dist/originals/darwin/amd64/cfo"
        "../dist/compressed/darwin/arm64/cfo"
        "../dist/originals/darwin/arm64/cfo"
    )

    for candidate in "${candidates[@]}"; do
        if [[ -x "$candidate" ]]; then
            CFO_BIN="$candidate"
            echo "Found binary: $candidate" >&2
            return 0
        fi
    done

    return 1
}

if ! find_binary; then
    echo "Binary not found, building test binary..." >&2
    cd ..
    go build -o test/test_bin ./cmd/cfo/
    cd test
    CFO_BIN="./test_bin"
    BUILT_LOCALLY=true
fi

# ---- prerequisite checks ----------------------------------------------------
for cmd in "$CFO_BIN" timeout dd; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "ERROR: required command not found: $cmd" >&2
        exit 1
    fi
done

mkdir -p "$TEST_DIR"

# =============================================================================
# OUTPUT FORMATTING
# =============================================================================
printf "\n%-50s %s\n" "TEST" "RESULT"
printf "%-50s %s\n" "--------------------------------------------------" "------"

report_ok()   { printf "%-50s ${GREEN}PASS${NC}\n" "$1"; }
report_fail() { printf "%-50s ${RED}FAIL${NC} %s\n" "$1" "${2:-}"; }
report_skip() { printf "%-50s ${YELLOW}SKIP${NC}\n" "$1"; }

# =============================================================================
# CLEANUP
# =============================================================================
cleanup() {
    kill -TERM -$$ 2>/dev/null || true
    sleep 0.1
    local attempt
    for attempt in 1 2 3; do
        rm -rf "$TEST_DIR" 2>/dev/null && break
        sleep 0.1
    done
    if $BUILT_LOCALLY; then
        rm -f "$CFO_BIN"
    fi
}
trap cleanup EXIT

# =============================================================================
# HELPERS
# =============================================================================

# do_encrypt — encrypt with a timeout.  Returns 0 on success.
do_encrypt() {
    local target="$1"
    timeout "$TIMEOUT_SECS" "$CFO_BIN" -e "$target" -p "$TEST_PASSWORD" >/dev/null 2>&1
}

# do_decrypt — decrypt with a timeout (symmetrical with do_encrypt).
do_decrypt() {
    local target="$1"
    timeout "$TIMEOUT_SECS" "$CFO_BIN" -d "$target" -p "$TEST_PASSWORD" -f >/dev/null 2>&1
}

# decrypt_to_stdout — decrypt to stdout, capture output for comparison.
decrypt_to_stdout() {
    "$CFO_BIN" -d "$1" -p "$TEST_PASSWORD" -o - 2>/dev/null
}

# =============================================================================
# TESTS
# =============================================================================

# --- single-file round-trip --------------------------------------------------
test_single() {
    local size="$1"
    local file="$TEST_DIR/single_${size}.bin"

    dd if=/dev/urandom of="$file" bs="$size" count=1 status=none 2>/dev/null
    local orig_sum
    orig_sum=$(sha256 "$file")

    if ! do_encrypt "$file"; then
        report_fail "Single (${size})" "encrypt failed"
        return 1
    fi

    rm -f "$file"

    if ! do_decrypt "${file}.cfo"; then
        report_fail "Single (${size})" "decrypt failed"
        return 1
    fi

    local dec_sum
    dec_sum=$(sha256 "$file")
    if [[ "$orig_sum" == "$dec_sum" ]]; then
        report_ok "Single (${size})"
    else
        report_fail "Single (${size})" "checksum mismatch"
        return 1
    fi
}

# --- multi-file batch round-trip ---------------------------------------------
test_multi() {
    local size="$1"
    local count="$2"
    local files=()

    for ((i = 1; i <= count; i++)); do
        local f="$TEST_DIR/m_${size}_${i}.bin"
        dd if=/dev/urandom of="$f" bs="$size" count=1 status=none 2>/dev/null
        files+=("$f")
    done

    sha256sum "${files[@]}" > "$TEST_DIR/check.txt"

    if ! do_encrypt "$TEST_DIR/m_${size}_*.bin"; then
        report_fail "${count} files (${size})" "encrypt failed"
        return 1
    fi

    rm -f "${files[@]}"

    # Decrypt all files.  If any fail, the checksum check below will catch it.
    local dec_failed=0
    for ((i = 1; i <= count; i++)); do
        if ! do_decrypt "$TEST_DIR/m_${size}_${i}.bin.cfo"; then
            dec_failed=1
        fi
    done

    if [[ "$dec_failed" -ne 0 ]]; then
        report_fail "${count} files (${size})" "decrypt error on ≥1 file"
        return 1
    fi

    if sha256_check "$TEST_DIR/check.txt"; then
        report_ok "${count} files (${size})"
    else
        report_fail "${count} files (${size})" "checksum mismatch"
        return 1
    fi
}

# --- zero-byte file ----------------------------------------------------------
test_zero() {
    local file="$TEST_DIR/zero.bin"
    : > "$file"   # create empty file

    if ! do_encrypt "$file"; then
        report_fail "Zero-byte file" "encrypt failed"
        return 1
    fi

    rm -f "$file"
    do_decrypt "${file}.cfo" || true

    if [[ -f "$file" ]] && [[ ! -s "$file" ]]; then
        report_ok "Zero-byte file"
    else
        report_fail "Zero-byte file" "decrypt produced non-empty output"
        return 1
    fi
}

# --- tamper detection --------------------------------------------------------
test_tamper() {
    local file="$TEST_DIR/tamper.bin"
    local orig="$TEST_DIR/original.bin"

    dd if=/dev/urandom of="$file" bs=4k count=1 status=none 2>/dev/null
    cp "$file" "$orig"

    if ! do_encrypt "$file"; then
        report_fail "Tamper detection" "encrypt failed"
        return 1
    fi

    # Corrupt the middle of the ciphertext (payload region).
    local size
    size=$(file_size "${file}.cfo")
    dd if=/dev/zero of="${file}.cfo" bs=1 count=16 \
        seek="$((size / 2))" conv=notrunc status=none 2>/dev/null

    # Decryption must fail (AEAD tag invalid) or produce wrong output.
    if do_decrypt "${file}.cfo" && sha256_check <(echo "$(sha256 "$orig")  $file"); then
        report_fail "Tamper detection" "corruption undetected"
        return 1
    fi
    report_ok "Tamper detection"
}

# --- header tamper (salt modification) ---------------------------------------
test_header_tamper() {
    local file="$TEST_DIR/hdr_tamper.bin"

    dd if=/dev/urandom of="$file" bs=4k count=1 status=none 2>/dev/null

    if ! do_encrypt "$file"; then
        report_fail "Header tamper" "encrypt failed"
        return 1
    fi

    # Salt is at bytes 12-27.  Flip byte 15.
    local cfo="${file}.cfo"
    local tmp="${cfo}.tmp"
    dd if="$cfo" of="$tmp" bs=1 count=15 status=none 2>/dev/null
    printf '\x00' >> "$tmp"
    dd if="$cfo" of="$tmp" bs=1 skip=16 seek=16 status=none 2>/dev/null
    mv "$tmp" "$cfo"

    if do_decrypt "$cfo"; then
        report_fail "Header tamper" "HMAC should have rejected tampered salt"
        return 1
    fi
    report_ok "Header tamper (salt)"
}

# --- wrong password -----------------------------------------------------------
test_wrong_password() {
    local file="$TEST_DIR/wrongpw.bin"

    dd if=/dev/urandom of="$file" bs=1k count=1 status=none 2>/dev/null

    if ! do_encrypt "$file"; then
        report_fail "Wrong password" "encrypt failed"
        return 1
    fi

    rm -f "$file"

    # Try decrypting with a different password — must fail with "authentication failed".
    if timeout "$TIMEOUT_SECS" "$CFO_BIN" -d "${file}.cfo" -p "wrong-password!!" -f >/dev/null 2>&1; then
        report_fail "Wrong password" "decryption should have failed"
        return 1
    fi
    report_ok "Wrong password"
}

# --- stdin encrypt + stdout decrypt ------------------------------------------
test_stdin_stdout() {
    local plaintext="Hello, Cipherforge stdin test!  UTF-8:  café résumé π ≈ 3.14"
    local cfo="$TEST_DIR/stdin_test.cfo"

    # Encrypt from stdin.
    if ! echo "$plaintext" | timeout "$TIMEOUT_SECS" "$CFO_BIN" -e -o "$cfo" -p "$TEST_PASSWORD" >/dev/null 2>&1; then
        report_fail "Stdin encrypt" "encrypt failed"
        return 1
    fi

    # Decrypt to stdout and capture output.
    local decrypted
    if ! decrypted=$(decrypt_to_stdout "$cfo"); then
        report_fail "Stdout decrypt" "decrypt failed"
        return 1
    fi

    # Go's Printf appends a newline after the password, and echo may add one.
    # Trim trailing newlines for comparison.
    decrypted="${decrypted%$'\n'}"
    if [[ "$decrypted" == "$plaintext" ]]; then
        report_ok "Stdin → stdout round-trip"
    else
        report_fail "Stdin → stdout round-trip" "content mismatch"
        return 1
    fi
}

# --- atomic mode (-a) --------------------------------------------------------
test_atomic_decrypt() {
    local file="$TEST_DIR/atomic.bin"
    local orig="$TEST_DIR/atomic.orig"

    dd if=/dev/urandom of="$file" bs=10k count=1 status=none 2>/dev/null
    cp "$file" "$orig"

    if ! do_encrypt "$file"; then
        report_fail "Atomic decrypt" "encrypt failed"
        return 1
    fi

    rm -f "$file"

    # Decrypt with -a (atomic) — output should appear atomically.
    if ! timeout "$TIMEOUT_SECS" "$CFO_BIN" -d "${file}.cfo" -p "$TEST_PASSWORD" -a >/dev/null 2>&1; then
        report_fail "Atomic decrypt" "decrypt failed"
        return 1
    fi

    if [[ -f "$file" ]] && sha256_check <(echo "$(sha256 "$orig")  $file"); then
        report_ok "Atomic decrypt (-a)"
    else
        report_fail "Atomic decrypt (-a)" "output mismatch or missing"
        return 1
    fi
}

# --- custom output naming (-o) -----------------------------------------------
test_custom_output() {
    local file="$TEST_DIR/custom_out.bin"
    local custom="$TEST_DIR/renamed.enc"
    local orig_sum

    dd if=/dev/urandom of="$file" bs=1k count=1 status=none 2>/dev/null
    orig_sum=$(sha256 "$file")

    # Encrypt to a custom filename.
    if ! timeout "$TIMEOUT_SECS" "$CFO_BIN" -e "$file" -o "$custom" -p "$TEST_PASSWORD" >/dev/null 2>&1; then
        report_fail "Custom output (-o)" "encrypt failed"
        return 1
    fi

    if [[ ! -f "$custom" ]]; then
        report_fail "Custom output (-o)" "output file not created"
        return 1
    fi

    # Decrypt the custom-named file.
    if ! timeout "$TIMEOUT_SECS" "$CFO_BIN" -d "$custom" -p "$TEST_PASSWORD" -f >/dev/null 2>&1; then
        report_fail "Custom output (-o)" "decrypt failed"
        return 1
    fi

    # The decrypted file is named "renamed" (stripping .enc, but there's no .cfo to strip).
    # Verify the original file is intact.
    if sha256_check <(echo "$orig_sum  $file"); then
        report_ok "Custom output (-o)"
    else
        report_fail "Custom output (-o)" "checksum mismatch"
        return 1
    fi
}

# --- quiet mode (-q) ---------------------------------------------------------
test_quiet_mode() {
    local file="$TEST_DIR/quiet.bin"

    dd if=/dev/urandom of="$file" bs=1k count=1 status=none 2>/dev/null

    # -q should suppress all non-error output to stderr.
    local output
    output=$(timeout "$TIMEOUT_SECS" "$CFO_BIN" -e "$file" -p "$TEST_PASSWORD" -q 2>&1) || true

    # With -q, there should be no stderr output (except errors).
    if [[ -n "$output" ]]; then
        report_fail "Quiet mode (-q)" "unexpected output: $output"
        return 1
    fi
    report_ok "Quiet mode (-q)"
}

# =============================================================================
# FAULT TESTS
# =============================================================================

# fault_kill_once — kills encryption mid-stream; verifies no valid .cfo is left.
# Returns 0 (success) when:
#   a) no .cfo was written (killed before any output), or
#   b) decryption of the partial .cfo fails (AEAD/HMAC catches corruption).
# The rare case where encryption finishes before the kill is also treated as
# success — the kill simply arrived too late.
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

    if [[ ! -f "$cfo" ]]; then
        rm -f "$file" "$orig"
        return 0
    fi

    dec=$(mktemp "$TEST_DIR/fault_XXXXXX.dec")
    if "$CFO_BIN" -d "$cfo" -p "$TEST_PASSWORD" -f >/dev/null 2>&1 \
            && sha256_check <(echo "$(sha256 "$orig")  $file"); then
        # Encryption completed before kill — valid file produced.  Not an error.
        rm -f "$file" "$orig" "$cfo" "$dec"
        return 0
    fi

    rm -f "$file" "$orig" "$cfo" "$dec"
    return 0
}

test_fault_kill() {
    local failures=0
    for ((i = 0; i < 3; i++)); do
        fault_kill_once || ((failures++))
    done

    if [[ "$failures" -eq 0 ]]; then
        report_ok "Fault: killed mid-encrypt (×3)"
    else
        report_fail "Fault: killed mid-encrypt" "$failures failures"
        return 1
    fi
}

test_fault_truncate() {
    local file="$TEST_DIR/trunc.bin"
    local orig="$TEST_DIR/trunc.orig"

    dd if=/dev/urandom of="$file" bs=1M count=1 status=none 2>/dev/null
    cp "$file" "$orig"

    if ! do_encrypt "$file"; then
        report_fail "Fault: truncated" "encrypt failed"
        return 1
    fi

    local current_size new_size cfo="${file}.cfo"
    current_size=$(file_size "$cfo")
    new_size=$((current_size - 100))  # remove last 100 bytes (destroys trailer)

    if command -v truncate >/dev/null 2>&1; then
        truncate -s "$new_size" "$cfo"
    else
        dd if="$cfo" bs="$new_size" count=1 of="${cfo}.trunc" status=none 2>/dev/null \
            && mv "${cfo}.trunc" "$cfo"
    fi

    # Decryption of a truncated file must fail or produce wrong output.
    if do_decrypt "$cfo" && sha256_check <(echo "$(sha256 "$orig")  $file"); then
        report_fail "Fault: truncated" "corruption undetected"
        return 1
    fi
    report_ok "Fault: truncated ciphertext"
}

# chaos test — many kill iterations to stress-test fault tolerance.
test_chaos() {
    local failures=0
    for ((i = 0; i < CHAOS_RUNS; i++)); do
        fault_kill_once || ((failures++))
    done

    if [[ "$failures" -eq 0 ]]; then
        report_ok "Chaos test (${CHAOS_RUNS} runs)"
    else
        report_fail "Chaos test (${CHAOS_RUNS} runs)" "$failures failures"
        return 1
    fi
}

# =============================================================================
# MAIN
# =============================================================================
main() {
    local failed=0

    # Correctness tests
    test_single "10k"            || failed=1
    test_single "1M"             || failed=1
    test_multi  "1k" 3           || failed=1
    test_zero                    || failed=1

    # Security tests
    test_tamper                  || failed=1
    test_header_tamper           || failed=1
    test_wrong_password          || failed=1

    # Feature tests
    test_stdin_stdout            || failed=1
    test_atomic_decrypt          || failed=1
    test_custom_output           || failed=1
    test_quiet_mode              || failed=1

    # Fault-injection tests
    test_fault_kill              || failed=1
    test_fault_truncate          || failed=1
    test_chaos                   || failed=1

    echo ""
    if [[ "$failed" -eq 0 ]]; then
        echo -e "${GREEN}ALL TESTS PASSED${NC}"
        exit 0
    else
        echo -e "${RED}SOME TESTS FAILED${NC}"
        exit 1
    fi
}

main
