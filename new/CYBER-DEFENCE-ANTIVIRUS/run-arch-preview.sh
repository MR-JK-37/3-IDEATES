#!/bin/bash
# CyberShield Arch Linux - Full Working Preview
# Runs av-service + creates EICAR test + optionally opens UI

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PREVIEW_DIR="/tmp/cybershield-preview"
mkdir -p "$PREVIEW_DIR"
mkdir -p "$PREVIEW_DIR/quarantine"

export HASH_DB_PATH="$PREVIEW_DIR/hash_db.sqlite"
export QUARANTINE_DIR="$PREVIEW_DIR/quarantine"
export AV_SOCKET_PATH="$PREVIEW_DIR/av_event.sock"

echo "=== CyberShield Arch Preview ==="
echo "Data dir: $PREVIEW_DIR"
echo ""

# Build av-service if needed
if [ ! -f av-service/target/release/av-service ]; then
    echo "[1/4] Building av-service..."
    (cd av-service && cargo build --release 2>/dev/null) || {
        echo "Build failed. Install: pacman -S rust clamav yara"
        exit 1
    }
else
    echo "[1/4] av-service binary found"
fi

# Create EICAR test file
echo "[2/4] Creating EICAR test file..."
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > "$PREVIEW_DIR/eicar.txt"
echo "      $PREVIEW_DIR/eicar.txt"

# Start av-service
echo "[3/4] Starting av-service..."
pkill -f "av-service" 2>/dev/null || true
sleep 1
./av-service/target/release/av-service &
AV_PID=$!
sleep 2

if ! kill -0 $AV_PID 2>/dev/null; then
    echo "av-service failed to start"
    exit 1
fi
echo "      PID: $AV_PID"

# Trigger scan
echo "[4/4] Triggering scan..."
curl -s -X POST http://127.0.0.1:3001/api/v1/scan \
  -H "Content-Type: application/json" \
  -d "{\"path\":\"$PREVIEW_DIR/eicar.txt\"}" || true

sleep 2
echo ""
echo "=== Scan Results ==="
curl -s http://127.0.0.1:3001/api/v1/threats | head -20
echo ""
echo ""
echo "=== Service Status ==="
curl -s http://127.0.0.1:3001/api/v1/status
echo ""
echo ""
echo "av-service running. To stop: kill $AV_PID"
echo "To run UI: cd av-ui-desktop && npm run tauri dev"
echo ""
