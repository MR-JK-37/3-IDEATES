#!/bin/bash

echo "╔═══════════════════════════════════════════════════════╗"
echo "║   🛡️  CYBERSHIELD ANTIVIRUS - DEMO                   ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo ""

# Set environment
export RUST_LOG=info
export HASH_DB_PATH=./signatures/hashes/malware_hashes.db

# Run service
echo "Starting CyberShield Antivirus..."
echo ""
./target/release/av-service
