#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:3001}"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  CyberShield - Real Scanning Validation"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

echo ""
echo "[TEST 1] Backend health..."
curl -fsS "${BASE_URL}/api/v1/status" >/dev/null
echo "  ✅ API reachable at ${BASE_URL}"

echo ""
echo "[TEST 2] EICAR detection (path-multiengine)..."
EICAR='X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
echo "$EICAR" > /tmp/eicar_test.com
EICAR_RESULT=$(curl -fsS -X POST "${BASE_URL}/api/v1/scan/path-multiengine" \
  -H "Content-Type: application/json" \
  -d "{\"path\":\"/tmp/eicar_test.com\"}")
echo "  result: ${EICAR_RESULT}"
if echo "${EICAR_RESULT}" | grep -Eq '"malicious":[1-9]'; then
  echo "  ✅ EICAR flagged by at least one engine"
else
  echo "  ⚠️ EICAR not flagged. Ensure ClamAV/YARA signatures are installed and updated."
fi

echo ""
echo "[TEST 3] Clean file check..."
echo "Hello CyberShield" > /tmp/clean_test.txt
CLEAN_RESULT=$(curl -fsS -X POST "${BASE_URL}/api/v1/scan/path-multiengine" \
  -H "Content-Type: application/json" \
  -d "{\"path\":\"/tmp/clean_test.txt\"}")
echo "  result: ${CLEAN_RESULT}"
if echo "${CLEAN_RESULT}" | grep -Eq '"malicious":0'; then
  echo "  ✅ Clean file stayed clean"
else
  echo "  ⚠️ Potential false positive; inspect engine output."
fi

echo ""
echo "[TEST 4] Network telemetry endpoint..."
NET_JSON=$(curl -fsS "${BASE_URL}/api/v1/network-logs")
COUNT=$(echo "${NET_JSON}" | tr -cd '{' | wc -c | tr -d ' ')
echo "  ✅ Network rows returned: ${COUNT}"

echo ""
echo "[TEST 5] Process telemetry endpoint..."
PROC_JSON=$(curl -fsS "${BASE_URL}/api/v1/process-logs")
PCOUNT=$(echo "${PROC_JSON}" | tr -cd '{' | wc -c | tr -d ' ')
echo "  ✅ Process rows returned: ${PCOUNT}"

if command -v bpftool >/dev/null 2>&1; then
  echo ""
  echo "[TEST 6] eBPF programs loaded..."
  BPF_COUNT=$(sudo bpftool prog list 2>/dev/null | grep -Ec "hook_execve|hook_openat|hook_connect|xdp_packet_filter" || true)
  if [[ "${BPF_COUNT}" -gt 0 ]]; then
    echo "  ✅ eBPF programs active: ${BPF_COUNT}"
  else
    echo "  ⚠️ No CyberShield eBPF programs found; fallback monitors may be active."
  fi
fi

rm -f /tmp/eicar_test.com /tmp/clean_test.txt
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Validation complete"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
