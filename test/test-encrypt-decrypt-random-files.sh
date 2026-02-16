#!/bin/bash
set -e

# Define the binary path once for easy updates
CFO_BIN="../dist/originals/linux/amd64/cfo"

# -----------------------------------------------------------------------------
# Function: run_test
# Arguments: test_name, file_count, block_size, count, dd_extra
# This handles the full lifecycle: Generate -> Hash -> Encrypt -> Decrypt -> Verify
# -----------------------------------------------------------------------------
run_test() {
    local name=$1
    local f_count=$2
    local bs=$3
    local count=$4
    local dd_extra=$5
    
    echo "=========================================================="
    echo " RUNNING TEST: $name"
    echo "=========================================================="
    
    # Cleanup previous artifacts
    rm -f test-$name-*.bin* checksums-$name.txt

    # 1. Generate Test Files
    # Using /dev/urandom ensures the encryption engine handles high-entropy data
    for i in $(seq -f "%03g" 1 "$f_count"); do
        dd if=/dev/urandom of=test-$name-$i.bin bs=$bs count=$count $dd_extra status=none
    done

    # 2. Record Truth (Original Hashes)
    sha256sum test-$name-*.bin > checksums-$name.txt

    # 3. Encrypt & Capture Password
    # tee /dev/tty allows us to see progress in real-time while capturing stdout
    echo "Encrypting..."
    ENC_LOG=$($CFO_BIN -e "test-$name-*.bin" | tee /dev/tty)
    
    # Extract the line after the password prompt using sed
    PASSWORD=$(echo "$ENC_LOG" | sed -n '/Your secure, auto-generated password/,+1p' | tail -n 1)

    if [ -z "$PASSWORD" ]; then
        echo "Error: Password extraction failed for $name."
        exit 1
    fi

    # Wipe originals to ensure the decrypter actually restores data from the .cfo
    rm test-$name-*.bin

    # 4. Decrypt (Automated Input)
    # The password is piped into Stdin. If x/term is updated to handle non-TTY, 
    # this will work without an 'expect' wrapper.
    echo "Decrypting..."
    echo "$PASSWORD" | $CFO_BIN -d "test-$name-*.bin.cfo"

    # 5. Automated Verification
    # sha256sum --check returns 0 if matches, non-zero if tampering/corruption exists
    echo "Verifying..."
    if sha256sum --check checksums-$name.txt; then
        echo "RESULT: $name PASSED"
        # Cleanup artifacts only on success to allow debugging on failure
        rm test-$name-*.bin test-$name-*.bin.cfo checksums-$name.txt
    else
        echo "RESULT: $name FAILED"
        exit 1
    fi
    echo ""
}

# --- TIER 1: Small Burst (1 KB) ---
# Tests logic for data smaller than the 1MiB internal segment buffer.
run_test "small" 10 "1k" 1 ""

# --- TIER 2: Standard Load (100 MB) ---
# Tests batch processing and smooth progress bar increments.
run_test "standard" 3 "1M" 100 ""

# --- TIER 3: Stress Test (Unaligned) ---
# Specifically tests the 'remainder' logic when files aren't exact multiples of 1MiB.
echo "Creating unaligned stress files..."
# 1 Byte file
dd if=/dev/urandom of=test-stress-001.bin bs=1 count=1 status=none
# 1MiB + 1 Byte (forces a two-segment read where the second is tiny)
dd if=/dev/urandom of=test-stress-002.bin bs=1 count=1 seek=$((1024*1024)) status=none

# Manually running the logic for the stress files
sha256sum test-stress-*.bin > checksums-stress.txt
ENC_LOG=$($CFO_BIN -e "test-stress-*.bin" | tee /dev/tty)
PASSWORD=$(echo "$ENC_LOG" | sed -n '/Your secure, auto-generated password/,+1p' | tail -n 1)
rm test-stress-*.bin
echo "$PASSWORD" | $CFO_BIN -d "test-stress-*.bin.cfo"
sha256sum --check checksums-stress.txt && rm test-stress-*.bin* checksums-stress.txt

# --- TIER 4: Heavy Loader (1 GB) ---
# Tests memory management and segment counter at scale.
# Optional: Comment this out if running on low-disk-space environments.
run_test "heavy" 1 "1M" 1024 ""

echo "=========================================================="
echo " ALL TESTS COMPLETED SUCCESSFULLY"
echo "=========================================================="
