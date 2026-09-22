# CyberShield Ultimate - Complete System Documentation

## Table of Contents
1. [Overview](#overview)
2. [Component Documentation](#component-documentation)
3. [Integration Guide](#integration-guide)
4. [Deployment Guide](#deployment-guide)

---

## Overview

CyberShield Ultimate is a **production-grade, cross-platform antivirus system** with:
- Kernel-level protection (eBPF, Endpoint Security, Minifilter)
- AI-powered threat analysis using Llama 3.2
- Behavioral sandboxing via libvirt/Hyper-V
- Real-time desktop dashboard
- Enterprise-grade security architecture

**7 Core Components:**
1. av-service (Rust) - Central scanning engine
2. av-sandbox (Rust) - Behavior analysis sandbox
3. av-ai (Rust) - LLM threat explainer
4. av-ui-desktop (React + Tauri) - Cross-platform UI
5. av-kernel-linux (eBPF) - Kernel interception
6. av-kernel-macos (Swift) - System Extension
7. av-kernel-windows (C++) - Minifilter driver

---

## Component Documentation

### av-service
**Location:** `/av-service/`
**Language:** Rust
**Purpose:** Central scanning engine with threat database

**Key Files:**
- `Cargo.toml` - Dependencies
- `src/main.rs` - Service entry point
- `src/scanner.rs` - Scanning logic
- `src/rules.rs` - Yara rule engine
- `Dockerfile` - Container image

**API Endpoints:**
```
POST /api/v1/scan              # Scan file
GET  /api/v1/status            # Service status
POST /api/v1/quarantine        # Quarantine file
GET  /api/v1/quarantine        # List quarantined
DELETE /api/v1/quarantine/:id  # Remove from quarantine
```

### av-sandbox
**Location:** `/av-sandbox/`
**Language:** Rust
**Purpose:** Zero-day detection via isolated VM execution

**Key Files:**
- `src/main.rs` - Service initialization
- `src/vm/manager.rs` - VM lifecycle (create, execute, destroy)
- `src/analyzer.rs` - Behavioral threat scoring
- `Cargo.toml` - libvirt + tokio dependencies

**Key Features:**
- Multi-hypervisor support (KVM, Hyper-V, VirtualBox)
- Syscall/network/file monitoring
- Automated behavior analysis
- Threat scoring (0.0-1.0)
- Offline fallback mode

### av-ai
**Location:** `/av-ai/`
**Language:** Rust
**Purpose:** LLM-powered threat explanation

**Key Files:**
- `src/main.rs` - Service startup
- `src/llm.rs` - Ollama HTTP client
- `src/explainer.rs` - ThreatExplainer wrapper

**Key Features:**
- Ollama backend (localhost:11434)
- Llama 3.2 3B model inference
- Threat explanation generation
- Danger level assessment (Low/Medium/High/Critical)
- Actionable recommendations

### av-ui-desktop
**Location:** `/av-ui-desktop/`
**Language:** React + Tauri
**Purpose:** Cross-platform desktop application

**Key Files:**
- `src/App.tsx` - Main component with routing
- `src/components/Dashboard.tsx` - Statistics & charts
- `src/components/ThreatLog.tsx` - Threat history
- `src/components/Settings.tsx` - Configuration
- `src-tauri/src/main.rs` - Rust backend (command handlers)
- `tauri.conf.json` - Tauri configuration
- `vite.config.ts` - Vite build configuration

**Tauri Commands:**
- get_protection_status() - System protection status
- get_recent_threats() - Threat history
- get_system_stats() - CPU/memory/threat metrics
- invoke_scan(path) - Trigger file scan
- get_threat_explanation(threat) - AI explanation
- quarantine_file(path) - Move to quarantine
- restore_quarantined_file() - Restore file

### av-kernel-macos
**Location:** `/av-kernel-macos/`
**Language:** Swift
**Purpose:** macOS kernel-level file monitoring

**Key Files:**
- `FileMonitor.swift` - Endpoint Security event handling
- `XPCConnection.swift` - IPC to av-service
- `main.swift` - Entry point
- `Info.plist` - System extension configuration
- `build.sh` - Xcode build script

**Features:**
- Real-time file access interception
- Process execution monitoring
- XPC synchronous RPC
- System file exclusion
- ES decision support (allow/deny/quarantine)

### av-kernel-linux
**Location:** `/av-kernel-linux/`
**Language:** C (eBPF)
**Purpose:** Linux kernel-level syscall monitoring

**Key Files:**
- `ebpf.bpf.c` - eBPF bytecode
- `ebpf.skel.h` - BPF skeleton
- `src/main.rs` - Ring buffer consumer
- `build.sh` - Compilation script

**Features:**
- Syscall tracing (open, execute, write, rename)
- Ring buffer zero-copy delivery
- libbpf loader
- Capability: CAP_BPF, CAP_PERFMON

### av-kernel-windows
**Location:** `/av-kernel-windows/`
**Language:** C++
**Purpose:** Windows minifilter driver

**Key Files:**
- `filter.c` - Minifilter implementation
- `filter.inf` - Installation manifest
- `filter.rc` - Resource file

**Features:**
- File I/O interception (create, read, write)
- Registry monitoring
- Process tracking
- Filter communication port (userspace bridge)

---

## Integration Guide

### Data Flow: File Scan (Real-Time)
```
User opens file: /home/john/Downloads/file.exe
    ↓
Kernel (eBPF/ES/Minifilter)
    ↓
av-kernel (intercepts syscall)
    ↓
av-service (REST POST /api/v1/scan)
    ↓
Threat Detection Engine:
  1. Hash lookup in database
  2. Yara rule matching
  3. Heuristic scoring
    ↓
Decision: ALLOW | DENY | QUARANTINE | SANDBOX
    ↓
Response → Kernel → OS → User

If SANDBOX:
  av-service → av-sandbox (execute in VM)
  av-sandbox → monitors behavior
  av-sandbox → av-ai (if suspicious behavior)
  av-ai → LLM (generate explanation)
  Decision stored in database
    ↓
av-ui-desktop: User sees threat alert
```

### Data Flow: Threat Explanation
```
User clicks threat in Dashboard
    ↓
av-ui-desktop (React component)
    ↓
Tauri invoke: get_threat_explanation(threat_name)
    ↓
av-ui-desktop backend (Rust)
    ↓
av-ai:3003 REST call
    ↓
av-ai (LLMEngine)
    ↓
Ollama HTTP API
    ↓
Llama 3.2 3B model (local inference)
    ↓
Generated explanation + danger level + recommendations
    ↓
av-ui-desktop: Display modal with details
```

### IPC Communication Protocols

**macOS (XPC):**
```swift
let connection = NSXPCConnection(machServiceName: "com.cybershield.av-service")
connection.remoteObjectProxy.scanFile(path: "/path", callback: { result in ... })
```

**Linux (REST over HTTP):**
```bash
curl -X POST http://localhost:3001/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"path": "/path/to/file"}'
```

**Windows (Named Pipes / REST):**
```cpp
HANDLE pipe = CreateNamedPipe(L"\\\\.\\pipe\\cybershield-av", ...);
// or HTTP REST to av-service
```

---

## Deployment Guide

### Docker Compose (Development)
```bash
docker-compose up -d
docker-compose ps
docker-compose logs -f av-service
```

**Services Exposed:**
- av-service: http://localhost:3001
- av-sandbox: http://localhost:3002
- av-ai: http://localhost:3003
- Ollama: http://localhost:11434
- Prometheus: http://localhost:9090
- Grafana: http://localhost:3000

### Kubernetes (Enterprise)
```bash
helm install cybershield cybershield/chart \
  --namespace cybershield \
  --set av-service.replicas=3
```

### Bare Metal (On-Premises)
```bash
# Build from source
cargo build --release

# Create systemd services
sudo systemctl enable cybershield-av-service
sudo systemctl start cybershield-av-service

# Verify
systemctl status cybershield-av-service
```

---

## Build Instructions

### av-service
```bash
cd av-service
cargo build --release
# Binary: target/release/av-service
```

### av-sandbox
```bash
cd av-sandbox
cargo build --release
# Binary: target/release/av-sandbox
```

### av-ai
```bash
cd av-ai
cargo build --release
# Binary: target/release/av-ai
```

### av-ui-desktop
```bash
cd av-ui-desktop
npm install
npm run tauri build
# App: src-tauri/target/release/cybershield-ui
```

### av-kernel-macos
```bash
cd av-kernel-macos
bash build.sh
# System extension: build/CyberShield.systemextension
```

### av-kernel-linux
```bash
cd av-kernel-linux
bash build.sh
# eBPF object: av_kern.o
```

### av-kernel-windows
```cmd
cd av-kernel-windows
msbuild minifilter.sln /p:Configuration=Release
# Driver: filter.sys
```

---

## Configuration Reference

### Environment Variables

**av-service:**
```bash
AV_SERVICE_PORT=3001
AV_DB_PATH=/var/lib/cybershield/db
AV_YARA_RULES=/etc/cybershield/yara
AV_SANDBOX_URL=http://localhost:3002
AV_AI_URL=http://localhost:3003
LOG_LEVEL=info
```

**av-sandbox:**
```bash
AV_SANDBOX_PORT=3002
AV_HYPERVISOR=qemu:///system
AV_VM_MEMORY=2048
AV_VM_TIMEOUT=60
```

**av-ai:**
```bash
AV_AI_PORT=3003
OLLAMA_URL=http://localhost:11434
LLM_MODEL=llama3.2-3b
RUST_LOG=info
```

---

## Monitoring & Logging

### Health Checks
```bash
curl http://localhost:3001/health  # av-service
curl http://localhost:3002/health  # av-sandbox
curl http://localhost:3003/health  # av-ai
```

### Log Viewing
```bash
# Docker
docker-compose logs -f av-service

# Systemd
journalctl -u cybershield-av-service -f

# Debug mode
RUST_LOG=debug av-service
```

### Prometheus Metrics
Available at `http://localhost:9090/metrics`

---

## Security Best Practices

1. **Keep definitions updated:** Daily threat definition updates
2. **Encrypt data at rest:** AES-256-GCM for databases
3. **HTTPS for APIs:** Certificate pinning recommended
4. **Restrict access:** Firewall rules by default
5. **Audit logging:** All actions logged and centralized
6. **Regular backups:** Daily backup of threat database

---

## Performance Targets

| Metric | Target |
|--------|--------|
| File scan latency | <100ms (p95) |
| Threat detection rate | >99% |
| False positive rate | <0.1% |
| Memory per instance | <512MB |
| CPU overhead | <2% (at 100K syscalls/sec) |

---

## Troubleshooting

See INSTALLATION.md for comprehensive troubleshooting guide.

Common issues:
- Service won't start → Check logs: `docker-compose logs av-service`
- High memory → Monitor: `docker stats av-service`
- Ollama timeout → Verify model: `docker exec cybershield-ollama ollama list`
- Can't connect → Check firewall: `sudo ufw status`

---

## Support & References

- **Documentation:** https://docs.cybershield.io
- **GitHub Issues:** https://github.com/cybershield/ultimate-antivirus/issues
- **Discord:** https://discord.gg/cybershield
- **Email:** support@cybershield.io
