# CyberShield - Arch Linux Full Working Preview

## Overview

CyberShield is a **production-grade, multi-engine antivirus** for Arch Linux with:

- **Real-time detection**: Hash DB, ClamAV, YARA, Heuristics, VirusTotal
- **REST API**: Port 3001 for scan, status, threats, quarantine
- **No fake data**: All threat data comes from actual scans
- **Desktop UI**: Tauri + React app that connects to av-service

---

## Quick Start (5 minutes)

### 1. Install Dependencies

```bash
# Arch Linux
sudo pacman -S --needed rust clamav yara sqlite clang linux-headers base-devel
```

### 2. Build & Run av-service

```bash
cd /path/to/CYBER-DEFENCE-ANTIVIRUS

# Build av-service
cd av-service && cargo build --release && cd ..

# Create quarantine directory
mkdir -p /tmp/cybershield-quarantine

# Run av-service (REST API on 3001, Unix socket for kernel events)
HASH_DB_PATH=/tmp/cybershield/hash_db.sqlite \
QUARANTINE_DIR=/tmp/cybershield-quarantine \
AV_SOCKET_PATH=/tmp/cybershield/av_event.sock \
./av-service/target/release/av-service &
```

### 3. Test Scan (EICAR - Safe Test File)

```bash
# Create EICAR test file (detected by all antivirus)
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.txt

# Trigger scan via API
curl -X POST http://127.0.0.1:3001/api/v1/scan -H "Content-Type: application/json" -d '{"path":"/tmp/eicar.txt"}'

# Send path to socket (alternative - triggers real-time scan)
echo "/tmp/eicar.txt" | nc -U -w1 /tmp/cybershield/av_event.sock 2>/dev/null || true

# Check detected threats
curl http://127.0.0.1:3001/api/v1/threats
```

### 4. Run Desktop UI

```bash
cd av-ui-desktop
npm install
npm run tauri dev
```

The UI connects to `http://127.0.0.1:3001` and displays:
- **Dashboard**: Real stats, quick scan, threat charts from actual data
- **Threat Log**: Threats detected by scans (no demo/fake entries)
- **Settings**: Security configuration

---

## Full Arch Installation

```bash
sudo ./arch-install.sh --build-ebpf
sudo systemctl start av-service
```

Configuration: `/etc/cybershield/config.toml`

---

## API Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/status` | GET | Service status, version |
| `/api/v1/scan` | POST | Queue file for scanning `{"path":"/path/to/file"}` |
| `/api/v1/threats` | GET | List detected threats (real scan results) |
| `/api/v1/quarantine` | POST | Quarantine file `{"path":"/path"}` |
| `/api/v1/quarantine` | GET | List quarantined files |

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AV_SERVICE_PORT` | 3001 | REST API port |
| `AV_SOCKET_PATH` | /var/run/av_event.sock | Unix socket for kernel IPC |
| `HASH_DB_PATH` | hash_db.sqlite | SQLite threat cache |
| `QUARANTINE_DIR` | /var/lib/cybershield/quarantine | Quarantine storage |
| `VT_API_KEY` / `VIRUSTOTAL_API_KEY` | - | VirusTotal API (optional) |
| `YARA_RULES` | - | Path to YARA rules file/dir |

---

## No Fake Data Guarantee

- **Threats**: Only from real scans (Hash DB, ClamAV, YARA, Heuristics, VirusTotal)
- **Charts**: Derived from actual threat counts and types
- **Quarantine**: Real files in quarantine directory
- **Status**: Live from av-service health

---

## EICAR Test

The EICAR test string is a harmless file recognized by all antivirus products:

```
X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
```

ClamAV detects it as `Eicar-Test-Signature`. Use for validation only.
