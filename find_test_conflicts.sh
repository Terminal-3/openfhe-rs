#!/bin/bash

# Output file for failing combinations
OUTPUT_FILE="test_conflicts.log"

# Clear the output file
echo "Test Conflicts Log" > "$OUTPUT_FILE"
echo "Started at: $(date)" >> "$OUTPUT_FILE"
echo "----------------------------------------" >> "$OUTPUT_FILE"

# List of tests to check
TESTS=(
    "test_crypto_context_roundtrip_decrypt"
    "test_concurrent_roundtrip_decrypt"
    "test_crypto_context_creation"
    "test_crypto_context_key_gen"
    "test_crypto_context_multiparty_key_gen"
    "test_crypto_context_make_packed_plaintext"
    "test_crypto_context_encrypt"
    "test_crypto_context_encrypt_multiple"
    "test_crypto_context_multiparty_decrypt_operations"
    "test_crypto_context_cross_context_operations"
    "test_concurrent_crypto_context_operations"
    "test_stress_crypto_context_creation"
    "test_massive_concurrent_crypto_context_load"
    "test_crypto_context_edge_cases"
)

# Function to run tests and check for failures
run_tests() {
    local test_args="$1"
    echo "Testing combination: $test_args"
    output=$(cargo test -- $test_args 2>&1)
    if echo "$output" | grep -q "test result: FAILED"; then
        echo "FAILURE FOUND!"
        echo "Failed combination: $test_args"
        echo "Output:"
        echo "$output"
        echo "----------------------------------------"
        
        # Write to log file
        echo "FAILURE FOUND at $(date)" >> "$OUTPUT_FILE"
        echo "Failed combination: $test_args" >> "$OUTPUT_FILE"
        return 1
    fi
    return 0
}

# Test all pairs
echo "Testing all pairs..."
echo "Testing pairs at $(date)" >> "$OUTPUT_FILE"
found_failure=0

for ((i=0; i<${#TESTS[@]}; i++)); do
    for ((j=i+1; j<${#TESTS[@]}; j++)); do
        test_pair="${TESTS[$i]} ${TESTS[$j]}"
        if ! run_tests "$test_pair"; then
            found_failure=1
        fi
    done
done

# Only test triples if no pairs failed
if [ $found_failure -eq 0 ]; then
    echo "No failing pairs found. Testing triples..."
    echo "No failing pairs found. Testing triples at $(date)" >> "$OUTPUT_FILE"
    for ((i=0; i<${#TESTS[@]}; i++)); do
        for ((j=i+1; j<${#TESTS[@]}; j++)); do
            for ((k=j+1; k<${#TESTS[@]}; k++)); do
                test_triple="${TESTS[$i]} ${TESTS[$j]} ${TESTS[$k]}"
                run_tests "$test_triple"
            done
        done
    done
else
    echo "Found failing pairs. Skipping triples testing."
    echo "Found failing pairs. Skipping triples testing." >> "$OUTPUT_FILE"
fi

echo "Test combination search complete."
echo "Test combination search completed at $(date)" >> "$OUTPUT_FILE"
echo "----------------------------------------" >> "$OUTPUT_FILE" 