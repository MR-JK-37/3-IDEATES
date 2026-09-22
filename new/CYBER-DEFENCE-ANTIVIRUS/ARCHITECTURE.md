# CyberShield Ultimate - System Architecture & Integration Guide

## System Overview

CyberShield Ultimate is a **production-grade, cross-platform antivirus system** with kernel-level protection across Windows, macOS, and Linux. The system consists of 7 core components working together in a coordinated architecture.

```
┌─────────────────────────────────────────────────────────────────┐
│                      Desktop UI (Tauri + React)                  │
│  Dashboard | Threat Log | Settings | Quarantine Management      │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                    REST API / WebSocket
                           │
      ┌────────────────────┼────────────────────┐
      │                    │                    │
      ▼                    ▼                    ▼
┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│  av-service  │  │  av-sandbox  │  │   av-ai      │
│  (Core Scan) │  │  (Behavior)  │  │  (LLM)       │
└──────┬───────┘  └──────────────┘  └──────────────┘
       │
    ┌──┼──┐
    │  │  │
    ▼  ▼  ▼
  Linux macOS Windows
  (eBPF) (ES)  (Minifilter)
  Kernel-Level Interception
```

## Component Breakdown

### 1. **av-service** (Rust)
**Purpose:** Core scanning engine with unified API for all platforms

**Location:** `/av-service/`

**Key Features:**
- File hash database (MD5/SHA256)
- Yara rule matching
- Behavioral heuristics
- Decision logic (Allow/Deny/Quarantine/Sandbox)

**Key Files:**
- `src/main.rs` - Service entry point with REST API
- `src/scanner.rs` - Scanning logic
- `src/rules.rs` - Yara rule engine
- `src/database.rs` - Threat database

**Integration Points:**
- **Receives from:** macOS ES, Linux eBPF, Windows minifilter (file events)
- **Sends to:** av-sandbox (suspicious files), av-ai (threat analysis), av-ui-desktop (alerts)

**API Endpoints:**
```
POST /api/v1/scan             # Scan file
GET  /api/v1/status          # Service status
POST /api/v1/quarantine      # Quarantine file
GET  /api/v1/quarantine      # List quarantined
DELETE /api/v1/quarantine/:id # Remove from quarantine
```

---

### 2. **av-kernel-macos** (Swift)
**Purpose:** macOS kernel-level file monitoring via Endpoint Security framework

**Location:** `/av-kernel-macos/`

**Key Features:**
- Real-time file access interception (ES_EVENT_TYPE_AUTH_OPEN)
- Process execution monitoring (ES_EVENT_TYPE_AUTH_EXEC)
- XPC communication with av-service
- System file exclusion

**Key Files:**
- `FileMonitor.swift` - ES event handling
- `XPCConnection.swift` - Sync RPC to Rust service
- `main.swift` - Entry point
- `Info.plist` - System extension configuration
- `build.sh` - Compilation script

**Integration Points:**
- **Sends to:** av-service (file events via XPC)
- **Receives from:** av-service (Allow/Deny/Quarantine decisions)

**Event Flow:**
```
macOS Filesystem Event
    ↓
Endpoint Security Framework
    ↓
FileMonitor.swift (handleEvent)
    ↓
XPCConnection.swift (requestScan)
    ↓
av-service REST API (/api/v1/scan)
    ↓
Decision (Allow/Deny)
    ↓
ES Response (ApprovalExpression)
```

---

### 3. **av-sandbox** (Rust)
**Purpose:** Zero-day detection via isolated VM execution and behavior analysis

**Location:** `/av-sandbox/`

**Key Features:**
- Multi-hypervisor support (KVM/QEMU, Hyper-V, VirtualBox)
- Snapshot-based isolation
- Syscall/network/file monitoring
- Behavioral threat scoring
- Offline analysis fallback

**Key Files:**
- `src/main.rs` - Service initialization
- `src/vm/manager.rs` - VM lifecycle management
- `src/vm/snapshot.rs` - Snapshot metadata
- `src/analyzer.rs` - Behavioral threat assessment

**Key Structs:**
```rust
SandboxReport {
  file_path: String,
  execution_time_ms: u64,
  verdict: SandboxVerdict,  // Clean|Suspicious|Malicious
  suspicious_syscalls: Vec<String>,
  network_connections: Vec<NetworkConnection>,
  file_modifications: Vec<FileModification>,
  process_creations: Vec<ProcessCreation>,
  api_calls: Vec<APICall>,
  risk_score: f32,  // 0.0-1.0
}
```

**Integration Points:**
- **Receives from:** av-service (suspicious files)
- **Sends to:** av-ai (behavior text), av-ui-desktop (reports)

**API Endpoints:**
```
POST /api/v1/sandbox/execute     # Run file in sandbox
GET  /api/v1/sandbox/report/:id  # Fetch report
POST /api/v1/sandbox/analyze     # Offline behavior analysis
```

---

### 4. **av-ai** (Rust)
**Purpose:** AI-powered threat explanation and recommendation generation

**Location:** `/av-ai/`

**Key Features:**
- Ollama HTTP backend for inference
- Llama 3.2 LLM (3B parameter model)
- Threat explanation generation
- Danger level assessment
- Actionable recommendation synthesis

**Key Files:**
- `src/main.rs` - Service startup
- `src/llm.rs` - Ollama HTTP client
- `src/explainer.rs` - ThreatExplainer wrapper

**Key Structs:**
```rust
ThreatExplanation {
  threat_name: String,
  file_path: String,
  explanation: String,  // User-friendly description
  danger_level: DangerLevel,  // Low|Medium|High|Critical
  recommended_actions: Vec<String>,
  timestamp: DateTime<Utc>,
}
```

**Integration Points:**
- **Receives from:** av-service (threat name), av-sandbox (behavior report)
- **Sends to:** av-ui-desktop (explanations)

**Dependencies:**
- **External:** Ollama service running on localhost:11434 (configurable)
- **Model:** llama3.2-3b (must be pulled: `ollama pull llama3.2-3b`)

**API Endpoints:**
```
POST /api/v1/explain          # Explain threat
POST /api/v1/analyze_behavior # Analyze behavior
POST /api/v1/recommend        # Get recommendations
```

---

### 5. **av-kernel-linux** (eBPF)
**Purpose:** Linux kernel-level file interception via eBPF programs

**Location:** `/av-kernel-linux/`

**Key Features:**
- eBPF programs for syscall monitoring (open, execute, write)
- Ring buffer event delivery
- Zero-copy userspace communication
- Performance optimized for high-frequency events

**Key Files:**
- `ebpf.bpf.c` - BPF bytecode
- `ebpf.skel.h` - BPF skeleton (libbpf)
- `src/main.rs` - Event consumer

**Integration Points:**
- **Sends to:** av-service (file events)

---

### 6. **av-kernel-windows** (C++)
**Purpose:** Windows minifilter driver for kernel-level file monitoring

**Location:** `/av-kernel-windows/`

**Key Features:**
- FltRegisterFilter for file I/O interception
- Registry key monitoring
- Process creation tracking
- Filter communication port to userspace

**Key Files:**
- `filter.c` - Minifilter driver code
- `filter.inf` - Installation manifest

**Integration Points:**
- **Sends to:** av-service (file events)

---

### 7. **av-ui-desktop** (React + Tauri)
**Purpose:** Cross-platform desktop application for threat management

**Location:** `/av-ui-desktop/`

**Key Features:**
- Real-time threat dashboard
- Historical threat log with filtering
- Security settings management
- Quarantine file restoration
- AI-powered threat explanations

**Key Files:**
- `src/App.tsx` - Main routing component
- `src/components/Dashboard.tsx` - Statistics & charts
- `src/components/ThreatLog.tsx` - Threat history table
- `src/components/Settings.tsx` - Configuration form
- `src-tauri/src/main.rs` - Tauri command handlers

**Key Tauri Commands:**
```rust
get_protection_status()       // → ProtectionStatus
get_recent_threats()          // → Vec<Threat>
get_system_stats()            // → SystemStats
invoke_scan(path)             // → ScanResult
get_threat_explanation(name)  // → String
quarantine_file(path)         // → Result
restore_quarantined_file()    // → Result
```

**Integration Points:**
- **Receives from:** av-service (threat logs), av-ai (explanations)
- **Sends to:** av-service (scan requests, quarantine actions)

---

## System Integration Flows

### Flow 1: Real-Time File Scan (macOS Example)

```
1. User opens file: /Users/john/Downloads/malware.exe
2. macOS kernel → Endpoint Security
3. ES → av-kernel-macos (FileMonitor)
4. FileMonitor → XPCConnection.requestScan()
5. XPCConnection → av-service:3001/api/v1/scan
6. av-service analyzes:
   - Hash lookup in database
   - Yara rule matching
   - Heuristic scoring
7. av-service → returns ALLOW or DENY
8. FileMonitor → sets ES decision
9. ES → OS kernel → file access granted/denied
10. av-ui-desktop → gets alert (WebSocket)
```

### Flow 2: Zero-Day Detection (Unknown File)

```
1. Unknown file detected by kernel
2. av-service unable to identify
3. av-service → av-sandbox (execute in VM)
4. av-sandbox:
   - Snapshot VM to clean state
   - Copy file to isolated environment
   - Execute file in VM
   - Monitor syscalls, network, file ops
5. av-sandbox → reports suspicious syscalls
6. av-sandbox → av-ai (behavior text)
7. av-ai → LLM (generate explanation)
8. av-ai → returns threat type & danger level
9. Decision: Quarantine / Monitor / Allow
10. av-ui-desktop → displays explanation
```

### Flow 3: Threat Explanation (User Clicks Threat)

```
1. User clicks threat in UI: "Trojan.Win32.Generic"
2. av-ui-desktop → invoke get_threat_explanation()
3. Tauri → av-ai:3002/api/v1/explain
4. av-ai → LLM prompt:
   "Explain Trojan.Win32.Generic to a non-technical user"
5. LLM → generates explanation
6. av-ai → returns with danger level & recommendations
7. av-ui-desktop → displays in modal
```

---

## Data Structures & Schemas

### FileEvent (av-service)
```json
{
  "path": "/home/user/file.exe",
  "operation": "open",
  "process_id": 1234,
  "process_name": "firefox",
  "timestamp": "2024-01-15T10:30:45Z",
  "hash": {
    "md5": "abc123...",
    "sha256": "def456..."
  }
}
```

### ScanDecision (av-service)
```json
{
  "verdict": "DENY|ALLOW|QUARANTINE|SANDBOX",
  "threat_type": "Trojan|PUP|Ransomware|...",
  "confidence": 0.95,
  "reason": "Matched Yara rule: trojan.generic"
}
```

### BehaviorReport (av-sandbox)
```json
{
  "file_path": "/vm/suspicious.exe",
  "execution_time_ms": 5000,
  "verdict": "MALICIOUS",
  "risk_score": 0.87,
  "suspicious_syscalls": [
    "NtQueryDirectoryFile",
    "NtSetInformationFile",
    "NtCreateProcess"
  ],
  "network_connections": [
    {
      "protocol": "TCP",
      "destination": "192.168.1.100",
      "port": 4444
    }
  ]
}
```

### ThreatExplanation (av-ai)
```json
{
  "threat_name": "Trojan.Win32.Generic",
  "explanation": "A trojan horse disguised as legitimate...",
  "danger_level": "CRITICAL",
  "recommended_actions": [
    "Isolate infected machine from network",
    "Run full system scan",
    "Check for persistence mechanisms"
  ]
}
```

---

## Deployment Architecture

### Local Development
```
Docker Compose with all services:
- av-service (port 3001)
- av-sandbox (port 3002)
- av-ai (port 3003)
- Ollama (port 11434)
- av-ui-desktop (localhost with Tauri dev server)
```

### Production (Linux)
```
Kubernetes:
- av-service Deployment (3 replicas)
- av-sandbox Deployment (2 replicas, KVM nodes)
- av-ai Deployment (2 replicas)
- av-kernel-linux DaemonSet (eBPF on every node)
- av-ui-desktop: Distributed web UI via NGINX
```

### Production (Windows Enterprise)
```
Active Directory Group Policy:
- av-kernel-windows: Minifilter driver installed
- av-service: Windows Service (SYSTEM account)
- av-sandbox: Hyper-V VMs for isolation
- av-ui-desktop: .exe installer via SCCM
```

### Production (macOS)
```
- av-kernel-macos: System Extension (notarized app)
- av-service: LaunchDaemon (com.cybershield.avservice)
- av-sandbox: Hypervisor.framework VM
- av-ui-desktop: .dmg package (signed & notarized)
```

---

## Configuration & Environment Variables

### av-service
```bash
AV_SERVICE_PORT=3001              # API port
AV_DB_PATH=/var/lib/cybershield   # Threat database
AV_YARA_RULES=/etc/cybershield    # Yara rules directory
AV_SANDBOX_URL=http://localhost:3002
AV_AI_URL=http://localhost:3003
LOG_LEVEL=info
```

### av-sandbox
```bash
AV_SANDBOX_PORT=3002
AV_HYPERVISOR=qemu:///system      # or hyperv:///system
AV_VM_MEMORY=2048                 # MB
AV_VM_TIMEOUT=60                  # seconds
```

### av-ai
```bash
AV_AI_PORT=3003
OLLAMA_URL=http://localhost:11434
LLM_MODEL=llama3.2-3b
RUST_LOG=info
```

### av-ui-desktop (Tauri)
```bash
TAURI_PRIVATE_KEY=...             # Code signing key
TAURI_KEY_PASSWORD=...            # Key password
AV_SERVICE_URL=http://localhost:3001
```

---

## Security Considerations

### Privilege Requirements
- **Linux eBPF:** CAP_BPF, CAP_PERFMON (or root)
- **macOS ES:** System Extension entitlement
- **Windows Minifilter:** Driver signing (WHQL for Win10+)
- **Sandbox VMs:** Nested virtualization or dedicated hardware

### IPC Security
- **XPC (macOS):** Entitlements-based access control
- **Unix Sockets (Linux):** File permissions (0600)
- **Named Pipes (Windows):** ACLs per process
- **REST APIs:** HTTPS with certificate pinning

### Data Security
- **Threat Database:** Encrypted at rest (AES-256-GCM)
- **Quarantine Storage:** Isolated filesystem with restricted permissions
- **Logs:** Centralized syslog with TLS encryption
- **Settings:** Stored in system keyring (not plaintext)

---

## Troubleshooting & Debugging

### av-service High CPU Usage
1. Check for infinite loop in Yara rules
2. Verify database integrity: `av-service --verify-db`
3. Monitor syscall rate: `perf top -p $(pgrep av-service)`

### av-sandbox VMs Not Launching
1. Verify hypervisor: `virsh -c qemu:///system nodeinfo`
2. Check snapshot permissions: `ls -la /var/lib/libvirt/qemu/snapshot/`
3. Review logs: `journalctl -u libvirtd -f`

### av-ai Inference Timeout
1. Verify Ollama running: `curl http://localhost:11434/api/tags`
2. Check model loaded: `ollama list` should show llama3.2-3b
3. Increase timeout: `LLM_TIMEOUT_SECS=120`

### av-ui-desktop Can't Connect
1. Verify av-service: `curl http://localhost:3001/api/v1/status`
2. Check firewall rules: `sudo ufw status`
3. Review browser console: Dev Tools > Network tab

---

## Performance Targets

| Metric | Target | Notes |
|--------|--------|-------|
| File scan latency | <100ms | p95 |
| Threat detection rate | >99% | Known malware |
| False positive rate | <0.1% | Per 1M files |
| Sandbox overhead | <2s | VM launch + execute |
| LLM response time | <5s | For explanation |
| Memory per av-service | <512MB | At 10K syscalls/sec |
| Kernel overhead (eBPF) | <2% CPU | At 100K syscalls/sec |

---

## Future Enhancements

1. **Cloud Analysis Backend** - Threat DNA matching
2. **Behavioral ML Models** - Neural network-based detection
3. **Community Threat Intel** - Distributed database
4. **Hardware Accelerated** - GPU-based scanning
5. **Mobile Support** - iOS/Android extensions
6. **EDR Integration** - Compliance with SIEMs

---

## References

- [Endpoint Security Framework (Apple)](https://developer.apple.com/documentation/endpointsecurity)
- [eBPF Documentation](https://ebpf.io/)
- [Windows Minifilter Documentation](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/minifilter-driver-concepts)
- [Tauri Documentation](https://tauri.app/docs/)
- [Yara Rules Documentation](https://yara.readthedocs.io/)
- [Ollama Documentation](https://github.com/ollama/ollama)
