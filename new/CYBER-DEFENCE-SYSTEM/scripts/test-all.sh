#!/bin/bash
# Run all tests

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PASSED=0
FAILED=0

run_test() {
    local test_name=$1
    local test_cmd=$2
    
    echo "▶️  Testing: $test_name"
    if eval "$test_cmd" > /dev/null 2>&1; then
        echo "✅ PASS: $test_name"
        ((PASSED++))
    else
        echo "❌ FAIL: $test_name"
        ((FAILED++))
    fi
}

# Unit tests
echo "=== Unit Tests ==="

# Android
if [ -d "$SCRIPT_DIR/../mobile/android" ]; then
    run_test "Android Unit Tests" "cd $SCRIPT_DIR/../mobile/android && ./gradlew test"
fi

# Python/ML
if command -v python3 &>/dev/null; then
    run_test "ML Inference Tests" "python3 $SCRIPT_DIR/../ml/runner.py --test"
fi

# Integration tests
echo ""
echo "=== Integration Tests ==="

# Test file entropy calculation
run_test "Entropy Calculation" "python3 -c 'import sys; sys.path.insert(0, \"$SCRIPT_DIR/../ml\"); from runner import calculate_entropy; assert calculate_entropy(b\"test\") > 0'"

# Desktop Electron
if command -v npm &>/dev/null && [ -d "$SCRIPT_DIR/../desktop" ]; then
    run_test "Electron Preload Security" "test -f $SCRIPT_DIR/../desktop/electron/preload.js && grep -q 'contextBridge' $SCRIPT_DIR/../desktop/electron/preload.js"
fi

# Summary
echo ""
echo "=== Test Summary ==="
echo "✅ Passed: $PASSED"
echo "❌ Failed: $FAILED"

if [ $FAILED -gt 0 ]; then
    exit 1
fi
