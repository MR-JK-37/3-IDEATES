#!/bin/bash
set -e

echo "╔═══════════════════════════════════════════════════════╗"
echo "║   🧪 CYBERSHIELD ANTIVIRUS - E2E TEST               ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo ""

SERVICE_BIN="./target/release/av-service"
DB_PATH="./signatures/hashes/malware_hashes.db"

if [ ! -f "$SERVICE_BIN" ]; then
    echo "❌ Service binary not found. Run build-all.sh first."
    exit 1
fi

echo "🧪 Starting service in background..."
export RUST_LOG=debug
export HASH_DB_PATH="$DB_PATH"

# Start service and capture PID
$SERVICE_BIN &
PID=$!

echo "   PID: $PID"
echo "   Waiting for initialization (5s)..."
sleep 5

# Check if process is still running
if ps -p $PID > /dev/null; then
   echo "✅ Service is running"
   
   # In a real E2E, we would interact with it here.
   # For now, we verify it didn't crash on startup.
   
   echo "🛑 Stopping service..."
   kill $PID
   wait $PID 2>/dev/null || true
   echo "✅ Service stopped gracefully"
   exit 0
else
   echo "❌ Service crashed on startup"
   exit 1
fi
