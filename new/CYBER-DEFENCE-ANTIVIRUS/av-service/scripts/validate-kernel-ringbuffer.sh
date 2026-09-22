#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${SERVICE_DIR}/.." && pwd)"

KERNEL_SRC="${KERNEL_SRC:-${REPO_ROOT}/av-kernel-linux/src/monitor.bpf.c}"
BPF_OBJ="${BPF_OBJ:-/tmp/monitor.bpf.o}"
SERVICE_BIN="${SERVICE_BIN:-${SERVICE_DIR}/target/debug/av-service}"
AUDIT_LOG="${AUDIT_LOG:-/tmp/cybershield-policy-audit.jsonl}"
SERVICE_LOG="${SERVICE_LOG:-/tmp/av-kernel-ringbuffer-validate.log}"
STARTUP_TIMEOUT_SECS="${STARTUP_TIMEOUT_SECS:-20}"
EVENT_SETTLE_SECS="${EVENT_SETTLE_SECS:-6}"
ENFORCEMENT_TTL_SECS="${ENFORCEMENT_TTL_SECS:-7}"
BUILD_SERVICE="${BUILD_SERVICE:-1}"
PROBE_SRC="${PROBE_SRC:-/tmp/cybershield_enforcement_probe.c}"
PROBE_BIN="${PROBE_BIN:-/tmp/cybershield_enforcement_probe}"
PROBE_QUAR_BIN="${PROBE_QUAR_BIN:-/tmp/cybershield_enforcement_probe_quarantine}"
BLOCK_RESULT="${BLOCK_RESULT:-/tmp/cybershield_block_result.txt}"
QUAR_RESULT="${QUAR_RESULT:-/tmp/cybershield_quarantine_result.txt}"

SUDO_PID=""

log() {
  printf '[validate-kernel-ringbuffer] %s\n' "$*"
}

die() {
  printf '[validate-kernel-ringbuffer] ERROR: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  if [[ -n "${SUDO_PID}" ]] && kill -0 "${SUDO_PID}" 2>/dev/null; then
    log "stopping av-service (pid=${SUDO_PID})"
    kill "${SUDO_PID}" 2>/dev/null || true
    sleep 1
  fi
}
trap cleanup EXIT

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

wait_for_log() {
  local pattern="$1"
  local timeout="$2"
  local waited=0
  while (( waited < timeout )); do
    if [[ -f "${SERVICE_LOG}" ]] && grep -q "${pattern}" "${SERVICE_LOG}"; then
      return 0
    fi
    sleep 1
    waited=$((waited + 1))
  done
  return 1
}

line_of_log() {
  local pattern="$1"
  grep -n "${pattern}" "${SERVICE_LOG}" | head -n1 | cut -d: -f1
}

assert_log_order() {
  local first_pattern="$1"
  local second_pattern="$2"
  local first_line
  local second_line
  first_line="$(line_of_log "${first_pattern}")"
  second_line="$(line_of_log "${second_pattern}")"
  [[ -n "${first_line}" ]] || die "missing log pattern: ${first_pattern}"
  [[ -n "${second_line}" ]] || die "missing log pattern: ${second_pattern}"
  if (( first_line >= second_line )); then
    die "log ordering violation: '${first_pattern}' (line ${first_line}) must be before '${second_pattern}' (line ${second_line})"
  fi
}

compile_enforcement_probe() {
  cat > "${PROBE_SRC}" <<'EOF'
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

static void write_kv(FILE *f, const char *key, long v) {
  fprintf(f, "%s=%ld\n", key, v);
  fflush(f);
}

static int open_test(FILE *f, const char *prefix, const char *path, int flags) {
  errno = 0;
  int fd = open(path, flags, 0644);
  int saved = errno;
  if (fd >= 0) close(fd);
  char key_rc[64];
  char key_errno[64];
  snprintf(key_rc, sizeof(key_rc), "%s_rc", prefix);
  snprintf(key_errno, sizeof(key_errno), "%s_errno", prefix);
  write_kv(f, key_rc, fd >= 0 ? 0 : -1);
  write_kv(f, key_errno, saved);
  return (fd >= 0) ? 0 : -1;
}

static int exec_test(FILE *f, const char *prefix, const char *path) {
  char key_before[64];
  char key_errno[64];
  snprintf(key_before, sizeof(key_before), "%s_before", prefix);
  snprintf(key_errno, sizeof(key_errno), "%s_errno", prefix);
  write_kv(f, key_before, 1);
  char *const argv[] = {(char *)path, NULL};
  execve(path, argv, environ);
  write_kv(f, key_errno, errno);
  return -1;
}

int main(int argc, char **argv) {
  if (argc < 5) {
    fprintf(stderr, "usage: %s <mode:block_ttl|quarantine> <trigger_path> <result_path> <ttl_secs>\n", argv[0]);
    return 2;
  }
  const char *mode = argv[1];
  const char *trigger_path = argv[2];
  const char *result_path = argv[3];
  int ttl_secs = atoi(argv[4]);

  FILE *f = fopen(result_path, "w");
  if (!f) {
    perror("fopen");
    return 3;
  }
  write_kv(f, "pid", (long)getpid());

  if (strcmp(mode, "block_ttl") == 0) {
    open_test(f, "trigger_open", trigger_path, O_RDONLY | O_CREAT);
    sleep(2);
    open_test(f, "open_during_ttl", "/etc/hosts", O_RDONLY);
    exec_test(f, "exec_during_ttl", "/bin/true");
    sleep(ttl_secs + 2);
    open_test(f, "open_after_ttl", "/etc/hosts", O_RDONLY);
    write_kv(f, "exec_after_ttl_before", 1);
    char *const argv_final[] = {(char *)"/bin/true", NULL};
    execve("/bin/true", argv_final, environ);
    write_kv(f, "exec_after_ttl_errno", errno);
    fclose(f);
    return 50;
  }

  if (strcmp(mode, "quarantine") == 0) {
    sleep(2);
    open_test(f, "open_quarantine", "/etc/hosts", O_RDONLY);
    exec_test(f, "exec_quarantine", "/bin/true");
    fclose(f);
    return 0;
  }

  fclose(f);
  return 4;
}
EOF

  cc -O2 "${PROBE_SRC}" -o "${PROBE_BIN}"
  cp -f "${PROBE_BIN}" "${PROBE_QUAR_BIN}"
  chmod +x "${PROBE_BIN}" "${PROBE_QUAR_BIN}"
}

read_kv() {
  local file="$1"
  local key="$2"
  grep "^${key}=" "${file}" | tail -n1 | cut -d= -f2
}

need_cmd sudo
need_cmd clang
need_cmd cargo
need_cmd timeout
need_cmd grep
need_cmd cc

[[ -f "${KERNEL_SRC}" ]] || die "kernel source not found: ${KERNEL_SRC}"
[[ -d "${SERVICE_DIR}" ]] || die "service dir not found: ${SERVICE_DIR}"

log "building eBPF object: ${BPF_OBJ}"
clang -g -O2 -target bpf -D__KERNEL__ -D__BPF_TRACING__ \
  -I/usr/include/linux \
  -c "${KERNEL_SRC}" -o "${BPF_OBJ}"

if [[ "${BUILD_SERVICE}" == "1" ]]; then
  log "building av-service binary"
  (cd "${SERVICE_DIR}" && cargo build --locked)
fi

[[ -x "${SERVICE_BIN}" ]] || die "service binary not found/executable: ${SERVICE_BIN}"

log "preparing kernel/runtime prerequisites"
sudo sysctl -w kernel.unprivileged_bpf_disabled=0 >/dev/null || \
  die "failed to set kernel.unprivileged_bpf_disabled=0"

rm -f "${AUDIT_LOG}" "${SERVICE_LOG}"
rm -f "${BLOCK_RESULT}" "${QUAR_RESULT}" "${PROBE_SRC}" "${PROBE_BIN}" "${PROBE_QUAR_BIN}"
compile_enforcement_probe

log "starting av-service in kernel-only mode"
sudo --preserve-env=PATH env \
  AV_KERNEL_MONITOR_MODE=kernel \
  AV_EBPF_OBJECT_PATH="${BPF_OBJ}" \
  AV_KERNEL_EVENT_STARTUP_TIMEOUT_SECS="${STARTUP_TIMEOUT_SECS}" \
  AV_KERNEL_ENFORCEMENT_TTL_SECS="${ENFORCEMENT_TTL_SECS}" \
  AV_POLICY_AUDIT_LOG="${AUDIT_LOG}" \
  bash -lc "ulimit -l unlimited; exec '${SERVICE_BIN}'" \
  >"${SERVICE_LOG}" 2>&1 &
SUDO_PID=$!

if ! wait_for_log "REST API listening on port" "${STARTUP_TIMEOUT_SECS}"; then
  tail -n 120 "${SERVICE_LOG}" || true
  die "service did not reach API startup within timeout"
fi

if grep -q "linux ringbuffer consumer stopped" "${SERVICE_LOG}"; then
  tail -n 120 "${SERVICE_LOG}" || true
  die "ringbuffer consumer failed during startup"
fi

log "triggering kernel activity (file, exec, network)"
echo "kernel-ringbuffer-validation" >> /tmp/cybershield_ringbuffer_test.txt
cat /etc/hosts >/dev/null
/bin/echo "exec-kernel-test" >/dev/null
timeout 3 bash -c 'cat </dev/null >/dev/tcp/1.1.1.1/80' >/dev/null 2>&1 || true

sleep "${EVENT_SETTLE_SECS}"

if grep -q "linux ringbuffer consumer stopped" "${SERVICE_LOG}"; then
  tail -n 120 "${SERVICE_LOG}" || true
  die "ringbuffer consumer failed after event trigger"
fi

log "running block + TTL enforcement probe"
BLOCK_TRIGGER="/tmp/cybershield_eicar_trigger.txt"
echo "EICAR test trigger" > "${BLOCK_TRIGGER}"
"${PROBE_BIN}" block_ttl "${BLOCK_TRIGGER}" "${BLOCK_RESULT}" "${ENFORCEMENT_TTL_SECS}" || true
[[ -s "${BLOCK_RESULT}" ]] || die "block probe did not produce result file"

BLOCK_PID="$(read_kv "${BLOCK_RESULT}" "pid")"
[[ -n "${BLOCK_PID}" ]] || die "missing block probe pid"

[[ "$(read_kv "${BLOCK_RESULT}" "open_during_ttl_errno")" == "13" ]] || \
  die "block probe expected open_during_ttl errno=13 (EACCES)"
[[ "$(read_kv "${BLOCK_RESULT}" "exec_during_ttl_before")" == "1" ]] || \
  die "block probe did not reach exec_during_ttl"
[[ "$(read_kv "${BLOCK_RESULT}" "exec_during_ttl_errno")" == "13" ]] || \
  die "block probe expected exec_during_ttl errno=13 (EACCES)"
[[ "$(read_kv "${BLOCK_RESULT}" "open_after_ttl_rc")" == "0" ]] || \
  die "block probe expected open_after_ttl to succeed after TTL expiry"
[[ "$(read_kv "${BLOCK_RESULT}" "exec_after_ttl_before")" == "1" ]] || \
  die "block probe did not reach exec_after_ttl stage"
if grep -q "^exec_after_ttl_errno=" "${BLOCK_RESULT}"; then
  die "block probe expected exec_after_ttl success (process replacement), but exec_after_ttl_errno was recorded"
fi

log "running quarantine enforcement probe"
"${PROBE_QUAR_BIN}" quarantine "/tmp/unused" "${QUAR_RESULT}" "${ENFORCEMENT_TTL_SECS}" || true
[[ -s "${QUAR_RESULT}" ]] || die "quarantine probe did not produce result file"

QUAR_PID="$(read_kv "${QUAR_RESULT}" "pid")"
[[ -n "${QUAR_PID}" ]] || die "missing quarantine probe pid"
[[ "$(read_kv "${QUAR_RESULT}" "open_quarantine_errno")" == "13" ]] || \
  die "quarantine probe expected open_quarantine errno=13 (EACCES)"
[[ "$(read_kv "${QUAR_RESULT}" "exec_quarantine_before")" == "1" ]] || \
  die "quarantine probe did not reach exec_quarantine"
[[ "$(read_kv "${QUAR_RESULT}" "exec_quarantine_errno")" == "13" ]] || \
  die "quarantine probe expected exec_quarantine errno=13 (EACCES)"

log "asserting strict kernel mode behavior"
grep -q "procfs fallback disabled because AV_KERNEL_MONITOR_MODE=kernel" "${SERVICE_LOG}" || \
  die "procfs fallback was not disabled in kernel mode"
grep -q "userspace fallback watcher disabled because AV_KERNEL_MONITOR_MODE=kernel" "${SERVICE_LOG}" || \
  die "userspace fallback watcher was not disabled in kernel mode"

log "asserting policy audit output from kernel events"
[[ -f "${AUDIT_LOG}" ]] || die "audit log not created: ${AUDIT_LOG}"
[[ -s "${AUDIT_LOG}" ]] || die "audit log is empty: ${AUDIT_LOG}"

grep -q '"source":"kernel_socket"' "${AUDIT_LOG}" || \
  die "no kernel_socket source records found in audit log"
grep -q '"decision":"' "${AUDIT_LOG}" || \
  die "no policy decisions found in audit log"
if grep -q '"source":"procfs_fallback"' "${AUDIT_LOG}"; then
  die "found procfs_fallback records while running kernel-only mode"
fi

log "asserting audit -> enforcement ordering and decision coverage"
grep -q "\"pid\":${BLOCK_PID}.*\"decision\":\"block\"" "${AUDIT_LOG}" || \
  die "missing block decision audit record for pid ${BLOCK_PID}"
grep -q "\"pid\":${QUAR_PID}.*\"decision\":\"quarantine\"" "${AUDIT_LOG}" || \
  die "missing quarantine decision audit record for pid ${QUAR_PID}"

assert_log_order \
  "policy audit appended: pid=${BLOCK_PID} decision=Block" \
  "programmed inline kernel enforcement for pid ${BLOCK_PID} decision Block"
assert_log_order \
  "policy audit appended: pid=${QUAR_PID} decision=Quarantine" \
  "programmed inline kernel enforcement for pid ${QUAR_PID} decision Quarantine"
grep -q "kernel policy quarantine action:" "${SERVICE_LOG}" || \
  die "missing quarantine action log entry"

KERNEL_LINES="$(grep -c '"source":"kernel_socket"' "${AUDIT_LOG}" || true)"
DECISION_LINES="$(grep -c '"decision":"' "${AUDIT_LOG}" || true)"
FILE_KIND_LINES="$(grep -c '"kind":"file_access"' "${AUDIT_LOG}" || true)"
EXEC_KIND_LINES="$(grep -c '"kind":"process_exec"' "${AUDIT_LOG}" || true)"
NET_KIND_LINES="$(grep -c '"kind":"network_connect"' "${AUDIT_LOG}" || true)"

log "validation passed"
log "kernel_socket records: ${KERNEL_LINES}"
log "policy decision records: ${DECISION_LINES}"
log "kind=file_access records: ${FILE_KIND_LINES}"
log "kind=process_exec records: ${EXEC_KIND_LINES}"
log "kind=network_connect records: ${NET_KIND_LINES}"
log "block probe pid: ${BLOCK_PID}"
log "quarantine probe pid: ${QUAR_PID}"
log "service log: ${SERVICE_LOG}"
log "audit log: ${AUDIT_LOG}"
