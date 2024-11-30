#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

# Counter for tests
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Function to run a test
run_test() {
    local test_name="$1"
    local command="$2"
    local expected_exit="$3"
    local expected_output="$4"
    
    echo -n "Running test: $test_name... "
    TESTS_RUN=$((TESTS_RUN + 1))
    
    # Run the command and capture output and exit code
    output=$(eval "$command" 2>&1)
    exit_code=$?
    
    # Check exit code
    if [ "$exit_code" != "$expected_exit" ]; then
        echo -e "${RED}FAILED${NC}"
        echo "Expected exit code $expected_exit, got $exit_code"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return
    fi
    
    # Check output if expected_output is provided
    if [ -n "$expected_output" ]; then
        if ! echo "$output" | grep -q "$expected_output"; then
            echo -e "${RED}FAILED${NC}"
            echo "Expected output containing: $expected_output"
            echo "Got: $output"
            TESTS_FAILED=$((TESTS_FAILED + 1))
            return
        fi
    fi
    
    echo -e "${GREEN}PASSED${NC}"
    TESTS_PASSED=$((TESTS_PASSED + 1))
}

# Make sure we're in the right directory
cd "$(dirname "$0")/.." || exit 1

# Test help output
run_test "Help Output" \
    "./RT-MASK.sh --help" \
    0 \
    "Usage: RT-MASK.sh"

# Test invalid option
run_test "Invalid Option" \
    "./RT-MASK.sh --invalid-option" \
    0 \
    "Unknown option: --invalid-option"

# Test single IP conversion
run_test "Single IP Conversion" \
    "./RT-MASK.sh -i 192.168.1.1" \
    0 \
    "::ffff:C0A8:0101"

# Test domain resolution
run_test "Domain Resolution" \
    "./RT-MASK.sh -d google.com --format json" \
    0 \
    '"ipv4":'

# Test CIDR range
run_test "CIDR Range" \
    "./RT-MASK.sh -c 192.168.1.0/30 --format json" \
    0 \
    '"ipv4":'

# Test file input with example file
run_test "File Input" \
    "./RT-MASK.sh -f example/sample_networks.txt --format json" \
    0 \
    '"ipv4":'

# Test WHOIS lookup
run_test "WHOIS Lookup" \
    "./RT-MASK.sh -i 8.8.8.8 --whois --format json" \
    0 \
    '"whois":'

# Test geolocation
run_test "Geolocation" \
    "./RT-MASK.sh -i 8.8.8.8 --geo --format json" \
    0 \
    '"geo":'

# Print summary
echo "===================="
echo "Test Summary:"
echo "------------------"
echo "Tests Run: $TESTS_RUN"
echo -e "Tests Passed: ${GREEN}$TESTS_PASSED${NC}"
echo -e "Tests Failed: ${RED}$TESTS_FAILED${NC}"
echo "===================="

# Exit with failure if any tests failed
[ "$TESTS_FAILED" -eq 0 ] || exit 1
