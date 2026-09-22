# CyberShield: Arch Linux Complete Deployment Guide

**Production-Grade Antivirus with eBPF LSM Monitoring, Multi-Engine Detection, and Threat Intelligence**

Version: 2.0 (Arch Linux Edition)  
Last Updated: February 13, 2026  
Tested on: Arch Linux (kernel 6.4+, systemd 254+)

---

## Table of Contents

- [Quick Start](#quick-start)
- [System Requirements](#system-requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [eBPF Kernel Monitoring](#ebpf-kernel-monitoring)
- [Scanning and Operations](#scanning-and-operations)
- [VM Sandbox Setup](#vm-sandbox-setup)
- [LLM Threat Explanations](#llm-threat-explanations)
- [Testing and Validation](#testing-and-validation)
- [Security Hardening](#security-hardening)
- [Troubleshooting](#troubleshooting)
- [Advanced Configuration](#advanced-configuration)
- [Publishing to AUR](#publishing-to-aur)

---

## Quick Start

### Installation (5 minutes)

```bash
# 1. Clone repository or download installation script
git clone https://github.com/cybershield/cybershield.git
cd cybershield

# 2. Run installation (requires sudo)
sudo ./arch-install.sh --build-ebpf

# 3. Start service
sudo systemctl start av-service
sudo systemctl enable av-service

# 4. Verify installation
sudo ./test-cybershield.sh --quick

# 5. View logs
journalctl -u av-service -f
```

### First Scan

```bash
# Update ClamAV signatures
sudo freshclam

# Scan a directory
av-service /path/to/scan

# Scan with all engines (slower, more thorough)
av-service --full /path/to/scan

# Show verbose output
av-service --verbose /path/to/scan
```

---

## System Requirements

### Minimum Hardware
- **CPU:** 2 cores (4+ cores recommended)
- **RAM:** 2GB minimum, 4GB+ recommended
- **Disk:** 10GB free (for ClamAV signatures, YARA rules, eBPF object)
- **Network:** Optional (VirusTotal API uses minimal bandwidth)

### Arch Linux Kernel Requirements
- **Kernel Version:** 5.8 or higher (6.0+ recommended)
- **Required:** `CONFIG_BPF=y` (BPF support)
- **Optional:** `CONFIG_BPF_LSM=y` (real-time kernel monitoring)
- **Recommended:** `CONFIG_DEBUG_INFO_BTF=y` (kernel type information)

Check your kernel:
```bash
uname -r
grep CONFIG_BPF /boot/config-$(uname -r)
grep CONFIG_BPF_LSM /boot/config-$(uname -r)  # Optional - LSM monitoring
```

If `CONFIG_BPF_LSM=y` is missing, switch to a kernel that supports it:
```bash
# Option 1: linux-zen (hardened kernel)
sudo pacman -S linux-zen linux-zen-headers

# Option 2: linux-hardened (maximum hardening)
yay -S linux-hardened linux-hardened-headers  # From AUR

# Then rebuild eBPF objects and reinstall:
sudo ./arch-install.sh --build-ebpf
```

### Required Packages

**Runtime Dependencies (installed by arch-install.sh):**
- `glibc` — C standard library
- `openssl` — TLS/SSL support
- `sqlite` — Local threat database
- `yara` — YARA rule engine
- `clamav` — ClamAV antivirus
- `libvirt` — QEMU virtualization (optional, for VM sandbox)
- `libyara` — YARA library bindings

**Build Dependencies (installed with `--build-ebpf` flag):**
- `rustup`/`cargo` — Rust compiler and package manager
- `llvm` — LLVM compiler infrastructure
- `clang` — C compiler (required for eBPF)
- `pkg-config` — Package metadata tool
- `linux-headers` — Kernel headers for BPF compilation
- `git` — Version control
- `protobuf` — Protocol buffer compiler

---

## Installation

### Step 1: Pre-Installation Checks

Verify system requirements:
```bash
# Check Arch Linux
grep "^ID=arch$" /etc/os-release

# Check kernel version (must be 5.8+)
uname -r

# Check BPF support (required)
grep "^CONFIG_BPF=y" /boot/config-$(uname -r)

# Check BPF_LSM support (optional, for eBPF monitoring)
grep "^CONFIG_BPF_LSM=y" /boot/config-$(uname -r)

# Check BTF support (recommended)
grep "^CONFIG_DEBUG_INFO_BTF=y" /boot/config-$(uname -r)

# Verify BTF available
ls -la /sys/kernel/btf/vmlinux
```

### Step 2: Download/Clone Repository

```bash
# Via Git (recommended)
git clone https://github.com/cybershield/cybershield.git
cd cybershield

# OR: Download release tarball
wget https://github.com/cybershield/cybershield/releases/download/v2.0/cybershield-2.0-arch.tar.gz
tar -xzf cybershield-2.0-arch.tar.gz
cd cybershield
```

### Step 3: Run Installation Script

```bash
# Make script executable
chmod +x arch-install.sh

# Run installation with eBPF compilation
sudo ./arch-install.sh --build-ebpf

# OR: Skip dependencies if already installed
sudo ./arch-install.sh --build-ebpf --skip-deps

# Installation will:
# 1. Verify Arch Linux and kernel version
# 2. Install pacman dependencies
# 3. Create unprivileged user: avsvc
# 4. Create directories: /opt/cybershield, /etc/cybershield, /var/lib/cybershield
# 5. Compile Rust binaries with LTO optimizations
# 6. Compile eBPF LSM kernel object (lsm_file_monitor.o)
# 7. Install systemd service and socket units
# 8. Generate configuration: /etc/cybershield/config.toml
# 9. Download YARA rules
# 10. Update ClamAV signatures
# 11. Verify installation
```

**Installation takes 5-15 minutes depending on system speed and internet bandwidth.**

### Step 4: Enable and Start Service

```bash
# Enable auto-start on boot
sudo systemctl enable av-service
sudo systemctl enable av-service.socket

# Start service immediately
sudo systemctl start av-service

# Verify service status
sudo systemctl status av-service
```

### Step 5: Post-Installation Verification

```bash
# Run quick test suite
sudo ./test-cybershield.sh --quick

# View service logs
journalctl -u av-service -n 50

# Check systemd hardening
systemd-analyze security av-service
```

---

## Configuration

### Main Configuration File

**Location:** `/etc/cybershield/config.toml`

The configuration file is TOML format with sections for each subsystem:

```toml
[database]
path = "/var/lib/cybershield/hash_db.sqlite"
max_pool_size = 10
cache_retention_days = 90

[heuristics]
enabled = true
entropy_threshold = 7.8      # Detects packing/encryption
suspicious_string_threshold = 5

[clamav]
enabled = true
cli_path = "/usr/bin/clamscan"
timeout_seconds = 10
max_file_size = 2147483648   # 2GB

[yara]
enabled = true
rules_directory = "/var/lib/cybershield/rules"
timeout_seconds = 15

[virustotal]
enabled = true
api_key = ""                 # Set via: export VIRUSTOTAL_API_KEY=...
rate_limit = 4               # 4 requests/minute (free tier)
cache_days = 30

[ebpf]
enabled = false              # Set to true if CONFIG_BPF_LSM=y
object_path = "/opt/cybershield/lib/lsm_file_monitor.o"
ring_buffer_size = 256       # Pages

[sandbox]
enabled = false              # Requires libvirt
libvirt_uri = "qemu:///system"
timeout_seconds = 60

[llm]
enabled = false              # Requires Ollama service
model = "llama3.2:3b"
ollama_host = "http://localhost:11434"
```

### VirusTotal API Configuration

To use VirusTotal threat intelligence:

1. **Create API key:**
   - Go to https://www.virustotal.com
   - Create free account (4 queries/minute) or premium account (higher limits)
   - Copy API key

2. **Configure av-service:**

   **Option A: Environment variable (temporary)**
   ```bash
   export VIRUSTOTAL_API_KEY="your-api-key-here"
   av-service /path/to/scan
   ```

   **Option B: Systemd environment (persistent)**
   ```bash
   sudo systemctl edit av-service
   # Add line: Environment="VIRUSTOTAL_API_KEY=your-api-key-here"
   sudo systemctl daemon-reload
   sudo systemctl restart av-service
   ```

   **Option C: Config file (future support)**
   ```toml
   [virustotal]
   api_key = "your-api-key-here"
   ```

3. **Privacy Note:** CyberShield only sends SHA256 hashes to VirusTotal, never full file contents.

### Environment Variables

Create `/etc/default/av-service` for service-wide settings:

```bash
# Log level (debug, info, warn, error)
RUST_LOG=info

# Database path
HASH_DB_PATH=/var/lib/cybershield/hash_db.sqlite

# VirusTotal API key
VIRUSTOTAL_API_KEY=your-key-here

# Custom rules directory
YARA_RULES_PATH=/var/lib/cybershield/rules

# Temp directory for sandbox
TEMP_DIR=/var/tmp/cybershield
```

---

## eBPF Kernel Monitoring

CyberShield includes real-time kernel-level file monitoring via eBPF LSM (Linux Security Module).

### Prerequisites

Check kernel support:

```bash
# Check if eBPF LSM is enabled
grep CONFIG_BPF_LSM /boot/config-$(uname -r)

# If output is: CONFIG_BPF_LSM=y   → Supported ✓
# If output is: CONFIG_BPF_LSM=n   → Not supported ✗

# Check if kernel BTF is available
ls -la /sys/kernel/btf/vmlinux

# Check bpftool availability
which bpftool
```

### Enabling eBPF LSM (if not available)

If your kernel doesn't have `CONFIG_BPF_LSM=y`, use a different kernel:

```bash
# Option 1: Switch to linux-zen (recommended)
sudo pacman -S linux-zen linux-zen-headers
# Reboot and select zen kernel from GRUB menu

# Option 2: Compile custom kernel
# (Advanced - refer to Arch Linux wiki)
```

### Building eBPF Objects

The installation script (`arch-install.sh`) automatically builds eBPF objects. To manually rebuild:

```bash
# Option A: Use build script
sudo ./build-ebpf.sh

# Option B: Manual compilation
sudo clang -O2 -target bpf \
  -D__KERNEL__ -D__BPF_TRACING__ \
  -I/usr/include/linux \
  -I. \  # vmlinux.h directory
  -c lsm_file_monitor.c \
  -o lsm_file_monitor.o

# Verify eBPF object
file lsm_file_monitor.o
llvm-objdump -h lsm_file_monitor.o
```

### Enabling eBPF Monitoring in av-service

Edit `/etc/cybershield/config.toml`:

```toml
[ebpf]
enabled = true
object_path = "/opt/cybershield/lib/lsm_file_monitor.o"
ring_buffer_size = 256
monitor_file_opens = true
monitor_executions = true
monitor_writes = true
```

Restart service:
```bash
sudo systemctl restart av-service
```

### Monitoring eBPF Events

View kernel BPF programs:
```bash
# List running BPF programs
sudo bpftool prog list

# Show program details
sudo bpftool prog show id <ID>

# View program bytecode
sudo bpftool prog dump xlated id <ID>
```

View kernel ring buffer events (if tracing available):
```bash
# Watch eBPF events in real-time
sudo cat /sys/kernel/debug/tracing/trace_pipe | grep "av-service"

# Or use trace-cmd if available
sudo trace-cmd start -e bpf_prog_tag
sudo trace-cmd show
```

### eBPF Program Structure

The eBPF program (`lsm_file_monitor.c`) monitors:

| Hook | Purpose | Details |
|------|---------|---------|
| `lsm_file_open` | File access | Captures open flags, permissions, file name |
| `lsm_inode_unlink` | File deletion | Tracks deletions and renames |
| `lsm_bprm_check_security` | Process execution | Monitors program execution and shebang interpreters |
| `lsm_file_permission` | File permissions | Compliance with kernel module requirements |

All hooks deliver events to ring buffer for userspace inspection via av-service.

---

## Scanning and Operations

### Basic Scanning

```bash
# Scan single file
av-service /path/to/file.exe

# Scan directory (recursive)
av-service /path/to/directory

# Scan with specific engine
av-service --engine clamav /path/to/file
av-service --engine yara /path/to/file
av-service --engine heuristics /path/to/file

# Scan with full analysis (all engines)
av-service --full /path/to/file

# Scan with verbose output
av-service -v /path/to/file

# Scan and log results
av-service --output json /path/to/file > results.json
av-service --output csv /path/to/file > results.csv
```

### Advanced Scanning

```bash
# Skip VirusTotal to save API quota
av-service --skip-virustotal /path/to/file

# Check cache only (no new analysis)
av-service --cache-only /path/to/file

# Force fresh scan (bypass cache)
av-service --force /path/to/file

# Scan with custom YARA rules
av-service --yara-rules /custom/rules.yar /path/to/file

# Scan in sandbox (requires libvirt)
av-service --sandbox /suspicious/file.exe

# Get detailed threat report
av-service --report /path/to/file
```

### Batch Operations

```bash
# Scan all files in directory with progress bar
find /home -type f -exec av-service {} \; -print

# Scan with parallel processing (8 threads)
find /home -type f | xargs -P 8 av-service

# Generate audit log
av-service /path/to/scan > /tmp/audit-$(date +%Y%m%d).log

# Export results to database
av-service --db-export /var/lib/cybershield/scan_results.sqlite /path/to/scan
```

### Service Management

```bash
# View service status
systemctl status av-service

# Start/stop service
sudo systemctl start av-service
sudo systemctl stop av-service

# Restart service
sudo systemctl restart av-service

# View systemd unit
systemctl cat av-service
systemctl cat av-service.socket

# Edit service
sudo systemctl edit av-service

# View resource usage
systemctl status av-service --no-pager

# Check service dependencies
systemctl list-dependencies av-service
```

---

## VM Sandbox Setup

CyberShield can execute suspicious files in isolated QEMU VMs with behavior monitoring.

### Prerequisites

```bash
# Install libvirt and QEMU
sudo pacman -S libvirt qemu virt-manager

# Enable and start libvirtd
sudo systemctl enable libvirtd
sudo systemctl start libvirtd

# Verify libvirt works
virsh version
```

### Creating a Sandbox VM

```bash
# 1. Create minimal VM image (Arch Linux minimal)
# Download minimal image
wget https://mirror.pkgbuild.com/images/latest/Arch-Linux-x86_64-basic.qcow2

# Create VM from image
sudo virt-install \
  --name cybershield-sandbox \
  --ram 2048 \
  --disk path=/var/lib/libvirt/images/cybershield-sandbox.qcow2,size=20 \
  --os-type linux \
  --os-variant archlinux \
  --graphics none \
  --console pty,target_type=serial

# 2. Configure VM for testing
# Add read-only mount for files to scan
sudo virsh attach-disk cybershield-sandbox /var/lib/cybershield/test-files --target vdb --readonly

# 3. Create snapshot before sandbox execution
sudo virsh snapshot-create-as cybershield-sandbox initial \
  --description "Clean snapshot before test file execution"

# 4. Execute test file in VM
av-service --sandbox /suspicious/file.exe

# 5. View VM behavior
# In another terminal:
sudo virsh console cybershield-sandbox

# 6. Revert to clean snapshot
sudo virsh snapshot-revert cybershield-sandbox initial
```

### Automated Sandbox Execution

Configure in `/etc/cybershield/config.toml`:

```toml
[sandbox]
enabled = true
libvirt_uri = "qemu:///system"
vm_snapshot_base = "/var/lib/cybershield/vms"
timeout_seconds = 60
cpu_cores = 2
memory_mb = 2048
snapshot_name_prefix = "cybershield-test"
post_execution_action = 1  # 0=none, 1=revert_snapshot, 2=delete_vm
monitor_syscalls = true
monitor_network = true
monitor_file_io = true
```

### Monitoring Sandbox Execution

```bash
# List VMs
sudo virsh list --all

# Monitor running sandbox
sudo virsh console cybershield-sandbox

# View captured syscalls
sudo journalctl -f | grep "cybershield-sandbox"

# Get VM state
sudo virsh dominfo cybershield-sandbox

# Check snapshot status
sudo virsh snapshot-list cybershield-sandbox

# Revert to known-good state
sudo virsh snapshot-revert cybershield-sandbox initial --force
```

---

## LLM Threat Explanations

CyberShield can generate natural language explanations of detected threats using local LLM inference.

### Prerequisites

```bash
# Install Ollama (local LLM inference service)
sudo pacman -S ollama

# OR: Build from source
git clone https://github.com/ollama/ollama.git
cd ollama
make

# Enable and start Ollama service
sudo systemctl enable ollama
sudo systemctl start ollama
```

### Setting Up LLM

```bash
# 1. Download Llama 3.2 3B quantized model (3GB, ~2 minutes)
ollama pull llama3.2:3b

# Verify model loaded
ollama list

# 2. Test Ollama inference
curl http://localhost:11434/api/generate -d '{
  "model": "llama3.2:3b",
  "prompt": "What is malware?",
  "stream": false
}'

# 3. Enable LLM in av-service config
sudo nano /etc/cybershield/config.toml
# Uncomment/set:
# [llm]
# enabled = true
# model = "llama3.2:3b"
# ollama_host = "http://localhost:11434"

sudo systemctl restart av-service
```

### Using LLM Threat Explanations

```bash
# Scan file and get LLM explanation
av-service --llm /suspicious/file.exe

# Generate threat report with explanations
av-service --report --llm /malicious/directory

# Only explain malicious findings
av-service --llm-malicious-only /path/to/scan
```

### Alternative: Quantized Models

Llama 3.2 3B (~3GB, recommended for 4GB+ RAM):
```bash
ollama pull llama3.2:3b
```

Mistral 7B (~5GB, more capable, requires 8GB+ RAM):
```bash
ollama pull mistral:latest
```

TinyLlama 1.1B (~1GB, fastest, 2GB+ RAM):
```bash
ollama pull tinyllama
```

Update config to use alternative model:
```toml
[llm]
model = "mistral:latest"  # or "tinyllama"
```

### Integrating av-ai Component

The `av-ai` binary handles threat explanation generation:

```bash
# Build av-ai with LLM support
cd av-ai
cargo build --release --features llm

# Use av-ai directly
av-ai --threat "Trojan.Generic detected in .exe file" \
      --context "Hash: abc123def456, Size: 2.5MB"

# Or via av-service pipeline
av-service --ai-explain /malware/file.exe
```

---

## Testing and Validation

### Automated Testing

```bash
# Run full test suite
sudo ./test-cybershield.sh --full

# Quick verification
sudo ./test-cybershield.sh --quick

# eBPF-specific tests
sudo ./test-cybershield.sh --ebpf

# VM sandbox tests
sudo ./test-cybershield.sh --lvm
```

### Manual Testing

#### Test 1: Service Status
```bash
sudo systemctl status av-service
# Expected: active (running)
```

#### Test 2: ClamAV Detection
```bash
# Create EICAR test file (harmless, recognized by all antivirus)
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.txt

# Scan with ClamAV
clamscan /tmp/eicar.txt
# Expected: Eicar-Test-File.UNOFFICIAL FOUND

# Scan with av-service
av-service /tmp/eicar.txt
# Expected: THREAT DETECTED: Eicar-Test-File
```

#### Test 3: Heuristics Detection
```bash
# Create suspicious file
echo -ne '\x4d\x5a\x90\x00' > /tmp/suspicious.exe  # MZ header (PE executable)
dd if=/dev/urandom of=/tmp/suspicious.exe bs=1 count=10000 seek=64 2>/dev/null

# Scan
av-service --engine heuristics /tmp/suspicious.exe
# Expected: Suspicious entropy/patterns detected
```

#### Test 4: Hash Database Caching
```bash
# Initial scan
av-service /tmp/eicar.txt

# Cached scan (should be instant)
time av-service /tmp/eicar.txt
# Expected: <100ms (cached), not using external engines
```

#### Test 5: Systemd Hardening
```bash
# Analyze security profile
systemd-analyze security av-service

# Expected: Exposed API calls: ~20, Hardening: GOOD
```

#### Test 6: Log Verification
```bash
# View service logs
journalctl -u av-service --no-pager -n 100

# Check log files
sudo tail -f /var/log/cybershield/av-service.log
```

#### Test 7: eBPF Events (if enabled)
```bash
# List BPF programs
sudo bpftool prog list

# Monitor events
sudo cat /sys/kernel/debug/tracing/trace_pipe | grep "av-service"
```

### Stress Testing

```bash
# Scan many files in parallel
find /home -type f -size +1M | xargs -P 4 av-service

# Monitor resource usage
watch -n 1 systemctl status av-service

# Check memory/CPU limits
systemctl show -p MemoryMax,MemoryCurrent,CPUUsageNSec av-service

# Disk I/O monitoring
sudo iotop -p $(systemctl show -p MainPID av-service | cut -d= -f2)
```

---

## Security Hardening

CyberShield includes comprehensive systemd security hardening by default.

### Hardening Features

| Feature | Setting | Purpose |
|---------|---------|---------|
| **Write XOR Execute** | `MemoryDenyWriteExecute=yes` | Prevents JIT/shellcode attacks |
| **Read-Only File System** | `ProtectSystem=strict` | /usr, /boot, /etc read-only |
| **Home Directory** | `ProtectHome=yes` | Hides /home, /root from service |
| **No New Privileges** | `NoNewPrivileges=yes` | Cannot gain privileges via suid/capabilities |
| **Private /tmp** | `PrivateTmp=yes` | Service gets isolated /tmp |
| **Syscall Filter** | `SystemCallFilter=@system-service` | Explicit syscall allowlist |
| **Capability Restriction** | `CapabilityBoundingSet=CAP_SYS_ADMIN` | Dropped all non-essential capabilities |
| **Memory Limits** | `MemoryMax=2G` | Prevents DoS via memory exhaustion |
| **CPU Limits** | `CPUQuota=80%` | Limits CPU usage to 80% of 1 core |
| **Namespace Isolation** | `RestrictNamespaces=yes` | Cannot create new namespaces |

### Verify Hardening

```bash
# Analyze service security
systemd-analyze security av-service

# Check specific setting
systemctl show av-service -p MemoryDenyWriteExecute
systemctl show av-service -p ProtectSystem
systemctl show av-service -p SystemCallFilter

# View full unit configuration
systemctl cat av-service
```

### Additional Hardening

Further harden your system:

```bash
# Enable kernel module signing
sudo /usr/bin/mokutil --enable-validation

# Enable SELINUX (if desired)
# pacman -S selinux-python-tools selinux-refpolicy
# Note: CyberShield uses AppArmor/seccomp, SELINUX is optional

# Lock down sudo access
sudo visudo
# Add: Defaults use_pty
# Add: Defaults log_input, log_output

# Enable firewall
sudo pacman -S ufw
sudo ufw enable
```

---

## Troubleshooting

### Service Won't Start

```bash
# Check error message
journalctl -u av-service -n 50 --all

# Common issues:

# 1. Config syntax error
toml-cli /etc/cybershield/config.toml

# 2. Binary permissions
ls -la /opt/cybershield/bin/av-service
sudo chmod +x /opt/cybershield/bin/av-service

# 3. User doesn't exist
id avsvc

# 4. Directories missing
ls -la /var/lib/cybershield
sudo mkdir -p /var/lib/cybershield
sudo chown avsvc:avsvc /var/lib/cybershield
```

### High Memory Usage

```bash
# Check current memory
systemctl show -p MemoryCurrent av-service

# Adjust limit in config
sudo systemctl edit av-service
# Change: MemoryMax=2G to MemoryMax=1G (or appropriate value)

# Or modify systemd drop-in
sudo mkdir -p /etc/systemd/system/av-service.service.d/
sudo nano /etc/systemd/system/av-service.service.d/memory.conf
# [Service]
# MemoryMax=1G

sudo systemctl daemon-reload
sudo systemctl restart av-service
```

### Slow Scans

```bash
# Check which engine is slow
av-service --verbose --time /path/to/file

# Profile each engine
av-service --engine heuristics --time /path/to/file  # Fast
av-service --engine clamav --time /path/to/file      # Medium
av-service --engine yara --time /path/to/file        # Slow
av-service --engine virustotal --time /path/to/file  # Variable (network)

# Solutions:
# - Disable slow engines: [yara] enabled = false
# - Increase timeouts: yara timeout_seconds = 30
# - Skip VirusTotal for large scans: av-service --skip-virustotal
# - Use --cache-only for repeated files: av-service --cache-only
```

### ClamAV Signature Errors

```bash
# Update signatures
sudo freshclam

# Check status
freshclam -c

# If error: "ERROR: Unexpected mirror URL format"
# Edit: /etc/clamav/freshclam.conf
# Uncomment recommended mirrors

# Restart service
sudo systemctl restart clamav-daemon
```

### eBPF LSM Not Working

```bash
# Check kernel support
grep CONFIG_BPF_LSM /boot/config-$(uname -r)

# If CONFIG_BPF_LSM=n, switch kernel
sudo pacman -S linux-zen linux-zen-headers
# Reboot and select zen kernel

# After reboot, rebuild eBPF
sudo /opt/cybershield/bin/build-ebpf.sh

# Verify eBPF loaded
sudo bpftool prog list | grep lsm_file_monitor
```

### VirusTotal API Rate Limiting

```bash
# Check current rate
av-service --virustotal-status

# If rate limited, wait or:
# - Upgrade to premium account (higher rate)
# - Disable for this session: av-service --skip-virustotal

# Adjust rate limit in config
[virustotal]
rate_limit = 2  # Reduce from 4 to 2 requests/minute
```

### YARA Rules Not Loading

```bash
# Check rules directory
ls -la /var/lib/cybershield/rules/

# If empty, download rules
cd /var/lib/cybershield
sudo git clone https://github.com/Yara-Rules/rules.git .
sudo chown -R avsvc:avsvc *

# Or manually update
sudo freshclam --update
```

---

## Advanced Configuration

### Custom YARA Rules

```bash
# Create custom rule
sudo nano /var/lib/cybershield/rules/custom.yar
```

Example rule:
```yara
rule MyTrojan {
    strings:
        $s1 = "malicious_function"
        $s2 = {4D 5A 90 00}  // MZ header
    condition:
        all of them
}
```

Test rule:
```bash
yara /var/lib/cybershield/rules/custom.yar /test/file.exe
```

### Custom Heuristic Rules

Edit configuration:
```toml
[heuristics]
entropy_threshold = 7.5     # Lower = more sensitive
suspicious_string_threshold = 3
detect_obfuscation = true
detect_embedded = true
```

### Performance Optimization

For high-volume scanning environments:

```toml
[performance]
max_concurrent_scans = 8      # Increase parallelism
cache_size_mb = 1000          # Larger cache
thread_pool_size = 0          # Auto-detect (4+ cores)
engine_order = ["hash", "heuristics", "clamav"]  # Skip YARA/VT for speed
batch_size = 200              # Larger batches

[database]
max_pool_size = 20            # More DB connections
```

### Logging Configuration

```toml
[logging]
level = "debug"               # Verbose logging
format = "json"               # Machine-parseable
output = "both"               # File + journalctl
log_directory = "/var/log/cybershield"
max_size_mb = 500             # Large log files
retention_days = 90
```

View debug logs:
```bash
RUST_LOG=debug systemctl restart av-service
journalctl -u av-service --no-pager -n 200
```

---

## Publishing to AUR

To publish CyberShield to the Arch Linux AUR (Arch User Repository):

### 1. Register with AUR

- Go to https://aur.archlinux.org
- Create account
- Configure SSH key for authentication

### 2. Prepare PKGBUILD

- Finalize `PKGBUILD` with version number
- Test locally: `makepkg -si`
- Verify binary works correctly

### 3. Push to AUR

```bash
# Clone AUR git repository
git clone ssh+git://aur@aur.archlinux.org/cybershield.git

# Copy PKGBUILD and supporting files
cp ./PKGBUILD cybershield/
cp ./.SRCINFO cybershield/  # or generate with mksrcinfo

# Commit and push
cd cybershield
git add PKGBUILD .SRCINFO
git commit -m "Update to version 2.0"
git push origin master
```

### 4. Generate `.SRCINFO`

```bash
# Generate checksums in PKGBUILD
makepkg --printsrcinfo > .SRCINFO
```

### 5. Maintenance

Update PKGBUILD with new versions:
```bash
git pull origin master  # Pull latest changes
# Edit PKGBUILD: update version, pkgrel, sha256sums
makepkg --printsrcinfo > .SRCINFO
git commit -am "Update to version 2.x"
git push origin master
```

---

## Reference: Command Reference

### av-service CLI

```bash
av-service [OPTIONS] [PATH]

ARGUMENTS:
  [PATH]    File or directory to scan

OPTIONS:
  --engine <ENGINE>         Scan with specific engine: hash, heuristics, clamav, yara, virustotal
  --full                    Use all engines (default uses hash→heuristics→clamav)
  --sandbox                 Execute in QEMU VM sandbox
  --llm                     Generate threat explanations using LLM
  --skip-virustotal         Don't query VirusTotal API
  --force                   Bypass cache, rescan everything
  --cache-only              Only check cache, don't scan
  --yara-rules <PATH>       Custom YARA rules file
  --output <FORMAT>         Output format: json, csv, text (default: text)
  --report                  Generate detailed threat report
  --verbose, -v             Verbose output
  --time                    Show execution time per engine
  --db-export <PATH>        Export results to SQLite database
  --help                    Show help message
```

### systemctl Service Management

```bash
# Service control
sudo systemctl start av-service       # Start service
sudo systemctl stop av-service        # Stop service
sudo systemctl restart av-service     # Restart service
sudo systemctl reload av-service      # Reload config (if supported)

# Service status
systemctl status av-service           # Current status
systemctl is-active av-service        # Is running? (returns exit code)
systemctl is-enabled av-service       # Is auto-start enabled?

# Logging
journalctl -u av-service              # View all logs
journalctl -u av-service -f           # Follow logs in real-time
journalctl -u av-service -n 100       # Last 100 entries
journalctl -u av-service --since "1 hour ago"  # Last hour

# Configuration
sudo systemctl edit av-service        # Edit service unit
sudo systemctl cat av-service         # View service unit
sudo systemctl show av-service        # Show all properties
```

### Common Tasks

```bash
# Scan home directory
av-service /home/user

# Scan with all engines
av-service --full /suspicious/file.exe

# Quick scan (cache + heuristics only)
av-service --cache-only /file.exe

# Get malware report
av-service --report /malware/sample

# Export scan results
av-service --output json /path | jq '.results'

# Monitor real-time scanning
journalctl -u av-service -f

# Check service health
systemd-analyze security av-service
```

---

## Support and Contributing

- **GitHub Issues:** https://github.com/cybershield/cybershield/issues
- **Documentation:** https://docs.cybershield.io
- **Security Reports:** security@cybershield.io (responsible disclosure)
- **Contributing:** See CONTRIBUTING.md in repository

---

## License

CyberShield av-service is licensed under the GNU General Public License v3.0.

**eBPF kernel module:** GPL v2 (required by kernel)  
**User-space components:** GPL v3  
**Dependencies:** Various licenses (see LICENSE files)

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 2.0 | Feb 13, 2026 | Arch Linux deployment, eBPF LSM, LLM integration, systemd hardening |
| 1.5 | Jan 2026 | Multi-engine detection, VirusTotal integration |
| 1.0 | Dec 2025 | Initial release: ClamAV + YARA + heuristics |

---

**Last Updated:** February 13, 2026  
**Maintained by:** CyberShield Development Team  
**Status:** Production Ready for Arch Linux
