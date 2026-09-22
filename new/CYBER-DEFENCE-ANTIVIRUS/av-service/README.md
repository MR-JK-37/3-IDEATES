# av-service (PoC)

Overview
- Minimal Rust PoC that listens on a Unix datagram socket for events (file paths) and runs a simple scanner stub.

Quick start (test VM, root):

```bash
# Build the Rust PoC
cd av-service
cargo build --release

# Create a socket and send a test path (run service in one terminal)
sudo target/release/av-service

# In another terminal, send a path via socat or unix_dgram test program
echo "/tmp/eicar.com" | socat - UNIX-DATAGRAM:/var/run/av_event.sock
```

Notes
- This PoC is intentionally minimal. Replace IPC with a secure netlink or ioctl channel and implement authenticated communication for production.
- Integrate `libbpf` ringbuffer consumer to read events from the `av-ebpf` program.

Kernel monitor mode (Linux)
- `AV_KERNEL_MONITOR_MODE=auto` (default): use kernel ringbuffer events and also run procfs fallback monitors.
- `AV_KERNEL_MONITOR_MODE=kernel`: require real kernel ringbuffer events; procfs fallback is disabled and service exits if no kernel events arrive within startup timeout.
- `AV_KERNEL_MONITOR_MODE=procfs`: force userspace fallback monitors only.
- Optional timeout for kernel-only mode: `AV_KERNEL_EVENT_STARTUP_TIMEOUT_SECS=20`.

Kernel policy/audit pipeline
- Kernel and fallback events are normalized into a shared schema before handling.
- Each event gets a policy decision (`allow|monitor|quarantine|block`) and a reason/confidence.
- Audit records are appended as JSONL to `AV_POLICY_AUDIT_LOG` (default: `/tmp/cybershield-policy-audit.jsonl`).

Schema version contract
- Service schema constant: `KERNEL_EVENT_SCHEMA_VERSION=2`.
- Wire events must include `schema_version`.
- Compatibility checks:
  - Runtime expectation gate: `AV_KERNEL_SCHEMA_VERSION_EXPECTED` (service exits if it does not match supported schema).
  - Ringbuffer/wire-frame validation: incompatible `schema_version` is rejected.
- Strict behavior:
  - `AV_KERNEL_STRICT_SCHEMA=true` (default).
  - In `AV_KERNEL_MONITOR_MODE=kernel`, invalid/mismatched/non-JSON frames cause fail-closed exit.

Kernel ringbuffer validation (privileged host/VM)
- End-to-end validator script: `scripts/validate-kernel-ringbuffer.sh`
- What it verifies:
  - kernel-only mode disables fallback paths
  - ringbuffer events are ingested
  - `KernelEventSource` resolves to `kernel_socket`
  - policy audit JSONL is emitted
  - inline `block`/`quarantine` enforcement returns `EACCES`
  - audit record is written before enforcement handoff
  - enforcement TTL expiry restores access/exec behavior
- Usage:
```bash
cd av-service
chmod +x scripts/validate-kernel-ringbuffer.sh
./scripts/validate-kernel-ringbuffer.sh
```

Cross-platform IPC schema contract
- Shared IPC schema constant: `KERNEL_IPC_SCHEMA_VERSION=1` (`src/kernel_ipc/mod.rs`).
- Strict IPC contract toggle: `AV_KERNEL_IPC_STRICT_SCHEMA=true` (default).
- Optional expected IPC schema gate: `AV_KERNEL_IPC_SCHEMA_VERSION_EXPECTED=<u16>`.
- Linux/Windows/macOS IPC handlers now validate this contract and report schema mismatch instead of silently continuing.

AI Risk Model (Trainable)
- Runtime model file: `config/ml/risk_model.json`
- Engine: `src/engines/ml.rs`
- Training script: `scripts/train_risk_model.py`
- Dataset builder: `scripts/build_feature_dataset.py`
- Evaluation script: `scripts/evaluate_risk_model.py`

Train/update weights:
```bash
cd av-service
python3 scripts/train_risk_model.py \
  --input /path/to/features.csv \
  --output config/ml/risk_model.json
```

Runtime override:
```bash
AV_RISK_MODEL_PATH=/absolute/path/to/risk_model.json cargo run
```

Recommended training workflow
```bash
cd av-service

# 1) Build features from your own benign/malicious samples
python3 scripts/build_feature_dataset.py \
  --benign-dir /path/to/benign_samples \
  --malicious-dir /path/to/malicious_samples \
  --output data/training/features.csv

# 2) Train weights
python3 scripts/train_risk_model.py \
  --input data/training/features.csv \
  --output config/ml/risk_model.json

# 3) Evaluate quality (precision/recall/confusion matrix)
python3 scripts/evaluate_risk_model.py \
  --model config/ml/risk_model.json \
  --input data/training/features.csv
```
