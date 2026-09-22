#!/bin/bash
set -e

echo "╔═══════════════════════════════════════════════════════╗"
echo "║   🧪 CYBERSHIELD ANTIVIRUS - TEST SUITE             ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo ""

# Run Rust tests
echo "🧪 Running unit tests..."
cargo test --workspace

echo ""
echo "🧪 Running integration tests..."
cargo test --test integration_test

echo ""
echo "✅ All tests passed!"
