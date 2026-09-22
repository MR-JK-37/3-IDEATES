# CyberShield Ultimate - Installation & Deployment Guide

## Table of Contents
1. [Quick Start](#quick-start)
2. [Platform-Specific Installation](#platform-specific-installation)
3. [Development Setup](#development-setup)
4. [Production Deployment](#production-deployment)
5. [Troubleshooting](#troubleshooting)

---

## Quick Start

### Prerequisites
- OS: Linux, macOS, or Windows (with WSL2)
- RAM: 8GB minimum, 16GB recommended
- Disk: 10GB free space
- Internet: For downloading dependencies

### Option A: Docker Compose (Recommended for Dev/Testing)

1. **Clone the repository:**
   ```bash
   git clone https://github.com/cybershield/ultimate-antivirus.git
   cd CYBER-DEFENCE-ANTIVIRUS
   ```

2. **Start services:**
   ```bash
   docker-compose up -d
   ```

3. **Initialize Ollama model:**
   ```bash
   docker exec cybershield-ollama ollama pull llama3.2-3b
   ```

4. **Verify services:**
   ```bash
   curl http://localhost:3001/api/v1/status  # av-service
   curl http://localhost:3002/api/v1/status  # av-sandbox
   curl http://localhost:3003/api/v1/status  # av-ai
   curl http://localhost:11434/api/tags      # Ollama
   ```

5. **View logs:**
   ```bash
   docker-compose logs -f av-service
   ```

---

## Platform-Specific Installation

### Linux (Ubuntu/Debian)

#### Step 1: System Dependencies
```bash
sudo apt-get update
sudo apt-get install -y \
    curl \
    wget \
    build-essential \
    pkg-config \
    libssl-dev \
    libvirt-dev \
    qemu-system \
    iptables \
    apparmor-utils
```

#### Step 2: Install Rust
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
rustup default stable
```

#### Step 3: Install Node.js (for UI)
```bash
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs
```

#### Step 4: Install Docker & Docker Compose
```bash
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
```

#### Step 5: Clone & Build
```bash
git clone https://github.com/cybershield/ultimate-antivirus.git
cd CYBER-DEFENCE-ANTIVIRUS

# Build av-service
cd av-service && cargo build --release && cd ..

# Build av-sandbox
cd av-sandbox && cargo build --release && cd ..

# Build av-ai
cd av-ai && cargo build --release && cd ..

# Build av-ui-desktop
cd av-ui-desktop && npm install && npm run build && cd ..
```

#### Step 6: Setup eBPF Components
```bash
cd av-kernel-linux
bash build.sh
sudo bash install.sh
```

#### Step 7: Create SystemD Services
```bash
sudo tee /etc/systemd/system/cybershield-av-service.service > /dev/null <<EOF
[Unit]
Description=CyberShield AV Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/home/USER/CYBER-DEFENCE-ANTIVIRUS/av-service/target/release/av-service
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable cybershield-av-service
sudo systemctl start cybershield-av-service
```

#### Step 8: Verify Installation
```bash
systemctl status cybershield-av-service
curl http://localhost:3001/api/v1/status
```

---

### macOS

#### Step 1: Install Homebrew
```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

#### Step 2: Install Dependencies
```bash
brew install rust nodejs docker libvirt
brew tap homebrew/cask
brew install xcode-select
sudo xcode-select --install
```

#### Step 3: Clone Repository
```bash
git clone https://github.com/cybershield/ultimate-antivirus.git
cd CYBER-DEFENCE-ANTIVIRUS
```

#### Step 4: Build Services
```bash
# av-service
cd av-service && cargo build --release && cd ..

# av-sandbox (requires Homebrew qemu)
cd av-sandbox && cargo build --release && cd ..

# av-ai
cd av-ai && cargo build --release && cd ..

# av-ui-desktop
cd av-ui-desktop && npm install && npm run tauri build && cd ..
```

#### Step 5: Install macOS System Extension
```bash
cd av-kernel-macos
bash build.sh
# Follow on-screen instructions for code signing
```

#### Step 6: Create LaunchDaemon
```bash
sudo tee /Library/LaunchDaemons/com.cybershield.avservice.plist > /dev/null <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.cybershield.avservice</string>
    <key>ProgramArguments</key>
    <array>
        <string>/path/to/av-service</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
EOF

sudo launchctl load /Library/LaunchDaemons/com.cybershield.avservice.plist
```

#### Step 7: Launch Desktop App
```bash
# Run from release build
open av-ui-desktop/target/release/bundle/macos/CyberShield\ Ultimate.app
```

---

### Windows (with WSL2)

#### Step 1: Enable WSL2
```powershell
# Run as Administrator
wsl --install
wsl --set-default-version 2
```

#### Step 2: Install Ubuntu in WSL2
```powershell
wsl --install -d Ubuntu-22.04
```

#### Step 3: Install Windows Minifilter Driver
```cmd
# Admin command prompt
cd av-kernel-windows
msbuild minifilter.sln /p:Configuration=Release /p:Platform=x64
# Install .sys driver via Device Manager or:
pnputil /add-driver av-kernel-windows\filter.inf /install
```

#### Step 4: Install Windows Service
```powershell
# Admin PowerShell
cd av-service
cargo build --release
sc create CyberShield binPath= "C:\path\to\av-service.exe" DisplayName= "CyberShield AV Service"
sc start CyberShield
```

#### Step 5: Install Desktop App
```powershell
cd av-ui-desktop
npm install
npm run tauri build
# Run the generated .msi installer
```

#### Step 6: WSL2 Backend Setup (Optional)
```bash
# Inside WSL2
wsl
cd /mnt/c/path/to/CYBER-DEFENCE-ANTIVIRUS
bash setup-wsl.sh
```

---

## Development Setup

### Frontend Development
```bash
cd av-ui-desktop
npm install
npm run dev              # Start Vite dev server (port 5173)
npm run tauri dev        # Launch Tauri app with hot reload
```

### Backend Development
```bash
# Watch and rebuild av-service
cd av-service
cargo watch -x "build --release"

# In another terminal, run the service
RUST_LOG=debug cargo run --release
```

### Testing
```bash
# Run all tests
cargo test --workspace

# Test specific component
cd av-service && cargo test

# Run with logging
RUST_LOG=debug cargo test -- --nocapture
```

---

## Production Deployment

### Option 1: Kubernetes (Enterprise)

#### Prerequisites
- Kubernetes cluster (1.21+)
- Helm 3+
- Persistent Volume provisioner

#### Deployment
```bash
# Add Helm repository
helm repo add cybershield https://helm.cybershield.io
helm repo update

# Install CyberShield
helm install cybershield cybershield/cybershield-ultimate \
  --namespace cybershield \
  --create-namespace \
  --set av-service.replicas=3 \
  --set av-sandbox.replicas=2 \
  --set av-ai.replicas=2

# Verify deployment
kubectl get pods -n cybershield
kubectl logs -f deployment/av-service -n cybershield
```

#### Configuration
```yaml
# values.yaml
av-service:
  replicas: 3
  resources:
    requests:
      cpu: 500m
      memory: 1Gi
    limits:
      cpu: 2
      memory: 4Gi
  persistence:
    enabled: true
    size: 100Gi

av-sandbox:
  enabled: true
  hypervisor: kvm
  resources:
    requests:
      cpu: 2
      memory: 4Gi

av-ai:
  replicas: 2
  ollamaUrl: http://ollama:11434
  model: llama3.2-3b
```

### Option 2: Docker Compose (Small Deployments)

```bash
# Production docker-compose
docker-compose -f docker-compose.prod.yml up -d

# Scale services
docker-compose up -d --scale av-service=3 --scale av-ai=2

# Monitor
docker-compose ps
docker-compose logs -f av-service
```

### Option 3: Bare Metal (On-Premises)

```bash
# 1. Create dedicated user
sudo useradd -m -d /opt/cybershield cybershield

# 2. Copy binaries
sudo cp av-service/target/release/av-service /usr/local/bin/
sudo cp av-sandbox/target/release/av-sandbox /usr/local/bin/
sudo cp av-ai/target/release/av-ai /usr/local/bin/

# 3. Setup directories
sudo mkdir -p /var/lib/cybershield/{db,quarantine,logs}
sudo chown -R cybershield:cybershield /var/lib/cybershield
sudo chmod 750 /var/lib/cybershield

# 4. Create systemd services (see examples above)
# 5. Enable and start services
sudo systemctl daemon-reload
sudo systemctl enable cybershield-*
sudo systemctl start cybershield-*

# 6. Configure firewall
sudo ufw allow 3001/tcp  # av-service
sudo ufw allow 3002/tcp  # av-sandbox
sudo ufw allow 3003/tcp  # av-ai
```

---

## Configuration

### av-service Config
```bash
cat > /etc/cybershield/av-service.conf <<EOF
[Server]
port = 3001
bind_address = 0.0.0.0

[Database]
url = postgresql://user:pass@localhost/av_db
pool_size = 10

[Rules]
yara_rules_dir = /etc/cybershield/yara
update_interval = 86400

[Integration]
sandbox_url = http://localhost:3002
ai_url = http://localhost:3003
EOF
```

### av-sandbox Config
```bash
cat > /etc/cybershield/av-sandbox.conf <<EOF
[Server]
port = 3002

[Virtualization]
hypervisor_uri = qemu:///system
vm_memory_mb = 2048
vm_timeout_secs = 60

[Snapshots]
baseline_path = /var/lib/cybershield/vm/baseline
snapshot_retention_days = 7
EOF
```

### av-ai Config
```bash
cat > /etc/cybershield/av-ai.conf <<EOF
[Server]
port = 3003

[LLM]
ollama_url = http://localhost:11434
model = llama3.2-3b
timeout_secs = 30
max_tokens = 512
EOF
```

---

## Troubleshooting

### av-service Issues

**Service won't start:**
```bash
# Check logs
journalctl -u cybershield-av-service -n 50 -f

# Verify database connectivity
psql -h localhost -U cybershield -d av_database -c "SELECT 1"

# Test port binding
sudo lsof -i :3001
```

**High memory usage:**
```bash
# Monitor memory
watch -n 1 'ps aux | grep av-service'

# Check for database query issues
journalctl -u cybershield-av-service | grep "slow query"

# Adjust connection pool
AV_DB_POOL_SIZE=5 systemctl restart cybershield-av-service
```

### av-sandbox Issues

**VMs not launching:**
```bash
# Verify libvirt
virsh -c qemu:///system list --all

# Check KVM support
grep -E 'vmx|svm' /proc/cpuinfo

# Enable nested virt (if needed)
sudo modprobe -r kvm_intel
sudo modprobe kvm_intel nested=1
```

**Permissions errors:**
```bash
# Add user to libvirt group
sudo usermod -aG libvirt $USER
newgrp libvirt

# Check socket permissions
ls -la /var/run/libvirt/libvirt-sock
```

### av-ai Issues

**Ollama connection refused:**
```bash
# Verify Ollama running
ps aux | grep ollama

# Check port
curl http://localhost:11434/api/tags

# Restart Ollama
docker restart cybershield-ollama
```

**Model not loaded:**
```bash
# Pull model
docker exec cybershield-ollama ollama pull llama3.2-3b

# Verify model
curl http://localhost:11434/api/tags | jq
```

### Desktop UI Issues

**Can't connect to services:**
```bash
# Check network connectivity
ping localhost:3001
curl http://localhost:3001/api/v1/status

# Review Tauri logs
RUST_LOG=debug npm run tauri dev

# Check browser console
Ctrl+Shift+I → Console tab
```

**Build failures:**
```bash
# Clear build cache
rm -rf av-ui-desktop/node_modules src-tauri/target
npm ci
npm run tauri build

# Check Node version
node --version  # Should be 16+
npm --version   # Should be 8+
```

---

## Verification Checklist

### Post-Installation
- [ ] All services running: `docker-compose ps`
- [ ] Health checks passing: `curl http://localhost:3001/api/v1/status`
- [ ] Database initialized: `psql ... -l`
- [ ] Ollama model loaded: `curl http://localhost:11434/api/tags`
- [ ] Desktop UI accessible: Browser to localhost:5173
- [ ] Logs clean: `docker-compose logs | grep -i error`

### Production
- [ ] HTTPS configured with valid certificates
- [ ] Firewall rules in place
- [ ] Database backups scheduled
- [ ] Log aggregation set up (ELK, Splunk, etc.)
- [ ] Monitoring dashboards visible
- [ ] Alerting rules configured
- [ ] Incident response plan documented

---

## Support & Resources

- **Documentation:** https://docs.cybershield.io
- **Issues:** https://github.com/cybershield/ultimate-antivirus/issues
- **Community:** https://discord.gg/cybershield
- **Enterprise Support:** support@cybershield.io
