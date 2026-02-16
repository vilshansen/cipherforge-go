#!/bin/bash
set -e # Exit on any error

# Configuration
BINARY="../dist/originals/linux/amd64/cfo"
TEST_DIR="./test_data"
PASS_FILE="$TEST_DIR/session_pass.txt"
mkdir -p $TEST_DIR

echo "--- 🛠️ Cipherforge Master Test Suite ---"

# Function to run a full cycle test
run_test() {
    local label=$1
    local size=$2
    local filename="$TEST_DIR/test_$label.bin"
    local enc_file="$filename.cfo"
    local dec_file="$filename"

    echo "Testing $label ($size)..."
    
    # Create dummy data
    dd if=/dev/urandom of="$filename" bs=$size count=1 status=none

    # Encrypt
    # Capture the auto-generated password
    output=$($BINARY -e "$filename")
    password=$(echo "$output" | sed -n '2p')
    
    # Decrypt using the captured password
    echo "$password" | $BINARY -d "$enc_file" > /dev/null

    # Validate integrity
    if cmp -s "$filename" "$dec_file"; then
        echo "✅ $label: Integrity Verified"
    else
        echo "❌ $label: Integrity FAILED"
        exit 1
    fi
}

# 2. Run Test Cases
echo "[2/4] Running Functional Tests..."

# Case A: Small file (less than 1 segment)
run_test "Small" "10k"

# Case B: Exact segment size (1MB)
run_test "Exact_1MB" "1M"

# Case C: Unaligned large file (e.g., 5.7MB)
run_test "Large_Unaligned" "5800k"

# 3. Security Test: Tamper Resistance
echo "[3/4] Running Security Test: Tamper Resistance..."
# Modify a single byte in the middle of a ciphertext segment
# to trigger a Poly1305 authentication failure.
echo "Corrupting ciphertext..."
dd if=/dev/zero of="$TEST_DIR/test_Small.bin.cfo" bs=1 count=1 seek=100 conv=notrunc status=none

echo "Attempting decryption of corrupted file (Expect failure)..."
if echo "dummy_pass" | $BINARY -d "$TEST_DIR/test_Small.bin.cfo" 2>&1 | grep -q "tampering detected or wrong password"; then
    echo "✅ Tamper Detection: Verified"
else
    echo "❌ Tamper Detection: FAILED (System decrypted tampered data!)"
    exit 1
fi

# 4. Cleanup
echo "[4/4] Cleanup..."
rm -rf $TEST_DIR
echo "--- 🎉 All Tests Passed Successfully ---"
