# CyberShield Quick Reference

## Installation (2-5 minutes)

### Ubuntu/Debian
```bash
git clone https://github.com/cybershield/cybershield.git
cd cybershield
sudo chmod +x install.sh
sudo ./install.sh --build-from-source

# Verify
sudo systemctl status av-service
journalctl -u av-service -f
```

### Arch Linux
```bash
git clone https://github.com/cybershield/cybershield.git
cd cybershield
makepkg -si
sudo systemctl enable --now av-service
```

### Docker
```bash
docker-compose up -d
docker-compose logs -f av-service
```

---

## Configuration

### Set VirusTotal API Key
```bash
# Option 1: Environment variable
export VIRUSTOTAL_API_KEY="your-api-key"

# Option 2: Systemd service
sudo systemctl edit av-service
# Add: Environment="VIRUSTOTAL_API_KEY=your-key"

# Option 3: Config file
sudo nano /etc/cybershield/config.toml
```

### Install Ollama (Optional - for LLM explanations)
```bash
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull llama3.2:3b
```

---

## Common Commands

### Service Management
```bash
sudo systemctl start av-service        # Start
sudo systemctl stop av-service         # Stop
sudo systemctl restart av-service      # Restart
sudo systemctl status av-service       # Check status
journalctl -u av-service -f           # View logs
```

### Scanning
```bash
# Android: Use CyberShield app
# GUI: Tauri application (when ready)
# CLI: Send file paths to socket
echo "/path/to/file" | nc -u -w 1 /var/run/av_event.sock
```

### Database Management
```bash
# View threat count
sqlite3 /var/lib/cybershield/hash_db.sqlite \
  "SELECT COUNT(*) as total_threats FROM threat_cache;"

# Recent threats
sqlite3 /var/lib/cybershield/hash_db.sqlite \
  "SELECT * FROM threat_cache ORDER BY scan_time DESC LIMIT 10;"

# Clear old entries (30+ days)
sqlite3 /var/lib/cybershield/hash_db.sqlite \
  "DELETE FROM threat_cache WHERE scan_time < datetime('now', '-30 days');"
```

### YARA Rules
```bash
# Check loaded rules
ls -la /var/lib/cybershield/rules/

# Update public rules
cd /var/lib/cybershield/rules
git pull  # If using git

# Test rule
yara -r /var/lib/cybershield/rules/ /tmp/test.txt
```

### ClamAV
```bash
# Update signatures
sudo freshclam

# Scan file
clamscan /tmp/test.txt

# Check installed
which clamscan
clamscan --version
```

---

## Troubleshooting

### Service won't start
```bash
# Check logs
sudo journalctl -u av-service -n 50 --no-pager

# Verify config
sudo nano /etc/cybershield/config.toml

# Check permissions
ls -la /var/lib/cybershield/
sudo chown cybershield:cybershield /var/lib/cybershield/*
```

### VirusTotal API errors
```bash
# Verify API key
echo $VIRUSTOTAL_API_KEY

# Test connectivity
curl -H "x-apikey: $VIRUSTOTAL_API_KEY" \
  "https://www.virustotal.com/api/v3/files/abc123"

# Check rate limiting
sudo journalctl -u av-service | grep -i "rate"
```

### High CPU/Memory usage
```bash
# Check resource limits
sudo systemctl show -p MemoryLimit av-service

# Monitor in real-time
top -p $(pidof av-service)

# Check running scans
sudo journalctl -u av-service | grep -i "scanning"
```

### Android app issues
```bash
# Check Android logs
adb logcat com.cybershield.android

# Verify permissions
adb shell pm dump com.cybershield.android | grep permissions

# Clear app data
adb shell pm clear com.cybershield.android
```

---

## Performance Tips

### For Large Deployments
```bash
# Increase file descriptor limit
sudo systemctl edit av-service
# Add: LimitNOFILE=1000000

# Increase memory limit
# LimitMEMLOCK=unlimited
# MemoryMax=8G

# Increase concurrent scans
# In config.toml: max_concurrent_scans = 8
```

### Optimization
```bash
# Use SSD for database
# Increase cache size
# [performance]
# cache_size_mb = 1000

# Tune YARA timeout
# yara_timeout = 20  # increase for large rules
```

---

## Security Hardening

### Firewall (if needed)
```bash
# UFW (Ubuntu)
sudo ufw allow from 127.0.0.1 to any port 11434  # Ollama

# iptables
sudo iptables -A INPUT -p udp -d /var/run/av_event.sock -j ACCEPT
```

### Regular Updates
```bash
# ClamAV signatures
sudo crontab -e
# Add: 0 3 * * * /usr/bin/freshclam > /var/log/cybershield/freshclam.log

# YARA rules
# 0 4 * * 0 cd /var/lib/cybershield/rules && git pull
```

### Log Monitoring
```bash
# Check for errors
sudo journalctl -u av-service -p err -f

# Monitor for suspicious activity
sudo journalctl -u av-service | grep -i "malicious"

# Generate report
sudo journalctl -u av-service --since today > threat-report.txt
```

---

## File Locations

### Configuration
- `/etc/cybershield/config.toml` - Main config
- `/etc/cybershield/env` - Environment variables
- `/etc/systemd/system/av-service.service` - Systemd unit

### Data & Logs
- `/var/lib/cybershield/hash_db.sqlite` - Threat cache
- `/var/lib/cybershield/rules/` - YARA rules
- `/var/log/cybershield/` - Log files
- `/var/run/cybershield/` - Runtime files

### Binaries
- `/opt/cybershield/bin/av-service` - Main service
- `/opt/cybershield/bin/av-sandbox` - Sandbox (if compiled)
- `/opt/cybershield/bin/av-ai` - LLM component (if compiled)

### Documentation
- `/usr/share/doc/cybershield/` - Docs (if installed via package)

---

## API Integration

### VirusTotal SHA256 Lookup
```bash
curl -H "x-apikey: $VIRUSTOTAL_API_KEY" \
  "https://www.virustotal.com/api/v3/files/ABC123DEF456..."
```

### Local YARA Scanning
```bash
yara -r /var/lib/cybershield/rules/ /suspicious/file.exe
```

### ClamAV Scanning
```bash
clamscan --recursive /suspicious/folder/
```

---

## Development

### Building av-service
```bash
cd av-service
cargo build --release
./target/release/av-service
```

### Building Android App
```bash
cd cybershield-android
./gradlew build
./gradlew assembleDebug
adb install app/build/outputs/apk/debug/cybershield-debug.apk
```

### Running Tests
```bash
# Rust tests
cd av-service && cargo test

# Android tests
cd cybershield-android && ./gradlew test
```

---

## Feature Status

### ✅ Ready
- Multi-engine detection (ClamAV, YARA, VT, heuristics)
- Android data layer (Room, API, repository)
- Systemd service (hardened)
- Installation automation
- Logging & monitoring

### 🟡 In Progress
- Android UI (40% complete)
- Desktop Tauri UI (10% complete)

### ❌ Not Yet
- Advanced kernel modules
- LLM integration (av-ai)
- CI/CD pipeline
- Web dashboard

---

## Getting Help

### Check Documentation
- `INSTALLATION.md` - Setup guide
- `ARCHITECTURE.md` - Technical design
- `PROJECT_STATUS.md` - Implementation details

### Review Logs
```bash
# Detailed logs
RUST_LOG=debug journalctl -u av-service

# Filter by level
journalctl -u av-service -p err
journalctl -u av-service -p warn
```

### Test Components
```bash
# Test ClamAV
clamscan --version

# Test YARA
yara -V

# Test VirusTotal connectivity
curl https://www.virustotal.com/api/v3/files/test

# Test local socket
nc -u /var/run/av_event.sock < /dev/null
```

---

## Quick Facts

- **License:** Apache 2.0
- **Primary Language:** Rust (backend), Kotlin (Android)
- **Min Requirements:** Linux 5.8+, 2GB RAM, 1GB disk
- **Supported Platforms:** Linux (Arch, Ubuntu, Debian), Windows, macOS, Android
- **API:** VirusTotal v3 (SHA256 only, privacy-first)
- **Database:** SQLite with r2d2 pooling
- **Rate Limiting:** 4 requests/minute (Semaphore-based)
- **Timeout Defaults:** 10s (VT, ClamAV), 15s (YARA)
- **Service User:** `cybershield` (unprivileged)
- **Memory Cap:** 2GB (configurable)

---

**For more details, see full documentation in project root directory.**
