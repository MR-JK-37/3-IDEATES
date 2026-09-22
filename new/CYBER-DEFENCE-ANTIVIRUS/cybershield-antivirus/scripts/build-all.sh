#!/bin/bash
set -e

echo "╔═══════════════════════════════════════════════════════╗"
echo "║   🛡️  CYBERSHIELD ANTIVIRUS - COMPLETE BUILD        ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo ""

# Check prerequisites
echo "📋 Checking prerequisites..."
command -v cargo >/dev/null 2>&1 || { echo "❌ Rust not installed"; exit 1; }
echo "✅ Rust found: $(rustc --version)"

# Build Rust workspace
echo ""
echo "🔨 Building Rust workspace..."
cargo build --workspace --release

if [ $? -eq 0 ]; then
    echo "✅ Rust build successful"
else
    echo "❌ Rust build failed"
    exit 1
fi

# Create directories
echo ""
echo "📁 Creating directories..."
mkdir -p signatures/hashes
mkdir -p tests/malware-samples

# Create EICAR test file
echo ""
echo "🧪 Creating EICAR test file..."
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > tests/malware-samples/eicar.com
echo "✅ EICAR test file created"

echo ""
echo "╔═══════════════════════════════════════════════════════╗"
echo "║   ✅ BUILD COMPLETE                                   ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo ""
echo "📦 Binaries:"
echo "   • av-service: target/release/av-service"
echo ""
echo "🚀 Run with: ./scripts/run-demo.sh"
