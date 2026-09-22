#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:-}"
OUTPUT_DIR="/output"
REPORT="${OUTPUT_DIR}/report.json"
SYSCALLS="${OUTPUT_DIR}/syscalls.txt"
START_MS=$(date +%s%3N)

mkdir -p "${OUTPUT_DIR}"

if [[ -z "${TARGET}" || ! -f "${TARGET}" ]]; then
  cat > "${REPORT}" <<EOF
{
  "file_path": "${TARGET}",
  "execution_time_ms": 0,
  "verdict": "Unknown",
  "suspicious_syscalls": [],
  "network_connections": [],
  "file_modifications": [],
  "process_creations": [],
  "api_calls": [],
  "risk_score": 0.0
}
EOF
  exit 0
fi

chmod +x "${TARGET}" 2>/dev/null || true

set +e
timeout 20s strace -f -o "${SYSCALLS}" "${TARGET}" >/dev/null 2>&1
TRACE_STATUS=$?
set -e

SUSPICIOUS=()
if grep -q "connect(" "${SYSCALLS}" 2>/dev/null; then SUSPICIOUS+=("connect"); fi
if grep -q "execve(" "${SYSCALLS}" 2>/dev/null; then SUSPICIOUS+=("execve"); fi
if grep -q "ptrace(" "${SYSCALLS}" 2>/dev/null; then SUSPICIOUS+=("ptrace"); fi
if grep -q "chmod(" "${SYSCALLS}" 2>/dev/null; then SUSPICIOUS+=("chmod"); fi

RISK="0.1"
VERDICT="Clean"
if [[ ${#SUSPICIOUS[@]} -ge 2 ]]; then
  RISK="0.65"
  VERDICT="Suspicious"
fi
if [[ ${#SUSPICIOUS[@]} -ge 4 ]]; then
  RISK="0.9"
  VERDICT="Malicious"
fi

END_MS=$(date +%s%3N)
ELAPSED=$((END_MS - START_MS))

json_list() {
  local first=1
  printf "["
  for item in "$@"; do
    if [[ ${first} -eq 0 ]]; then printf ","; fi
    first=0
    printf "\"%s\"" "${item}"
  done
  printf "]"
}

cat > "${REPORT}" <<EOF
{
  "file_path": "${TARGET}",
  "execution_time_ms": ${ELAPSED},
  "verdict": "${VERDICT}",
  "suspicious_syscalls": $(json_list "${SUSPICIOUS[@]}"),
  "network_connections": [],
  "file_modifications": [],
  "process_creations": [],
  "api_calls": [
    {
      "function": "strace",
      "module": "linux-kernel",
      "parameters": ["timeout=20s"],
      "result": "exit_code=${TRACE_STATUS}"
    }
  ],
  "risk_score": ${RISK}
}
EOF
