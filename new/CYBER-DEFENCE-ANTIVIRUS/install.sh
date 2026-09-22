#!/bin/bash
# CyberShield Installation Script for Ubuntu/Debian
# Usage: sudo ./install.sh [--build-from-source]
# Supports: Ubuntu 20.04+, Debian 11+

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_FROM_SOURCE="${1:-}"
INSTALL_PREFIX="/opt/cybershield"
CONFIG_DIR="/etc/cybershield"
SYSTEMD_DIR="/etc/systemd/system"

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== CyberShield Installation Script ===${NC}"
echo "Target directory: $INSTALL_PREFIX"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run as root (use sudo)${NC}"
    exit 1
fi

# Detect OS/Distribution
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$NAME
    OS_VERSION=$VERSION_ID
else
    echo -e "${RED}Error: Could not detect OS version${NC}"
    exit 1
fi

echo -e "${GREEN}Detected: $OS $OS_VERSION${NC}"

# Function to check command existence
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Install dependencies based on distro
echo -e "${YELLOW}Installing dependencies...${NC}"

if [[ "$ID" == "ubuntu" ]] || [[ "$ID" == "debian" ]]; then
    apt-get update
    apt-get install -y \
        yara \
        clamav \
        clamav-daemon \
        libvirt-daemon-system \
        libvirt-clients \
        qemu-kvm \
        cargo \
        rustc \
        clang \
        pkg-config \
        libssl-dev \
        libsqlite3-dev \
        libglib2.0-dev \
        linux-headers-generic \
        curl \
        git

    # Optional: Install Ollama for LLM support
    if ! command_exists ollama; then
        echo -e "${YELLOW}Installing Ollama for LLM support...${NC}"
        curl -fsSL https://ollama.ai/install.sh | sh
    fi
else
    echo -e "${RED}Unsupported distribution: $ID${NC}"
    exit 1
fi

# Create installation directories
echo -e "${YELLOW}Creating installation directories...${NC}"
mkdir -p "$INSTALL_PREFIX"/bin
mkdir -p "$CONFIG_DIR"
mkdir -p /var/lib/cybershield/rules
mkdir -p /var/log/cybershield

# Build from source if requested
if [ "$BUILD_FROM_SOURCE" == "--build-from-source" ]; then
    echo -e "${YELLOW}Building from source...${NC}"

    # Build av-service
    if [ -d "$SCRIPT_DIR/av-service" ]; then
        echo "Building av-service..."
        cd "$SCRIPT_DIR/av-service"
        cargo build --release
        cp target/release/av-service "$INSTALL_PREFIX/bin/"
    fi

    # Build kernel module (if applicable)
    if [ -d "$SCRIPT_DIR/av-kernel-linux" ]; then
        echo "Building eBPF kernel module..."
        cd "$SCRIPT_DIR/av-kernel-linux"
        cargo build --release
        # Note: Actual kernel module compilation may require additional steps
    fi

    # Build sandbox component
    if [ -d "$SCRIPT_DIR/av-sandbox" ]; then
        echo "Building sandbox component..."
        cd "$SCRIPT_DIR/av-sandbox"
        cargo build --release
        cp target/release/av-sandbox "$INSTALL_PREFIX/bin/"
    fi

    # Build AI component
    if [ -d "$SCRIPT_DIR/av-ai" ]; then
        echo "Building AI component..."
        cd "$SCRIPT_DIR/av-ai"
        cargo build --release
        cp target/release/av-ai "$INSTALL_PREFIX/bin/"
    fi
else
    # Download pre-built binaries if available
    echo -e "${YELLOW}Downloading pre-built binaries...${NC}"
    # This would download from a release repository
    # For now, build from source if binaries not found
    if [ ! -f "$SCRIPT_DIR/av-service/target/release/av-service" ]; then
        echo "Building from source (binaries not found)..."
        cd "$SCRIPT_DIR/av-service"
        cargo build --release
        cp target/release/av-service "$INSTALL_PREFIX/bin/"
    fi
fi

# Set permissions
echo -e "${YELLOW}Setting permissions...${NC}"
chmod 755 "$INSTALL_PREFIX"/bin/*
chmod 755 /var/lib/cybershield
chmod 755 /var/log/cybershield

# Install configuration files
echo -e "${YELLOW}Installing configuration files...${NC}"
if [ -f "$SCRIPT_DIR/config/default.toml" ]; then
    cp "$SCRIPT_DIR/config/default.toml" "$CONFIG_DIR/config.toml"
fi

# Install systemd service
echo -e "${YELLOW}Installing systemd service...${NC}"
cat > "$SYSTEMD_DIR/av-service.service" << 'EOF'
[Unit]
Description=CyberShield Antivirus Service
After=network.target
Documentation=man:av-service(1)

[Service]
Type=simple
ExecStart=/opt/cybershield/bin/av-service
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=av-service
Environment="HASH_DB_PATH=/var/lib/cybershield/hash_db.sqlite"
Environment="VIRUSTOTAL_API_KEY="

# Security hardening
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
NoNewPrivileges=yes
ReadWritePaths=/var/lib/cybershield /var/log/cybershield /var/run/cybershield

[Install]
WantedBy=multi-user.target
EOF

# Install socket activation (optional)
cat > "$SYSTEMD_DIR/av-service.socket" << 'EOF'
[Unit]
Description=CyberShield Antivirus Service Socket
Before=av-service.service

[Socket]
ListenDatagram=/var/run/av_event.sock
SocketMode=0660

[Install]
WantedBy=sockets.target
EOF

# Update ClamAV database
echo -e "${YELLOW}Updating ClamAV signatures...${NC}"
freshclam || echo "Warning: freshclam failed, you may need to update signatures manually"

# Download YARA rules if available
echo -e "${YELLOW}Setting up YARA rules...${NC}"
if [ -d "$SCRIPT_DIR/rules" ]; then
    cp -r "$SCRIPT_DIR/rules"/* /var/lib/cybershield/rules/
else
    # Clone Yara-Rules repository
    echo "Downloading public YARA rules from GitHub..."
    git clone --depth 1 https://github.com/Yara-Rules/rules.git /tmp/yara-rules
    cp /tmp/yara-rules/*.yar /var/lib/cybershield/rules/
    rm -rf /tmp/yara-rules
fi

# Create service user (optional, for privilege separation)
if ! id -u cybershield >/dev/null 2>&1; then
    echo -e "${YELLOW}Creating unprivileged service user 'cybershield'...${NC}"
    useradd --system --no-create-home --shell /bin/false cybershield
fi

# Reload systemd daemon
echo -e "${YELLOW}Reloading systemd configuration...${NC}"
systemctl daemon-reload

# Display installation summary
echo ""
echo -e "${GREEN}=== Installation Complete ===${NC}"
echo ""
echo "Installation details:"
echo "  Binary path: $INSTALL_PREFIX/bin/av-service"
echo "  Config path: $CONFIG_DIR/config.toml"
echo "  Rules path: /var/lib/cybershield/rules/"
echo "  Database: /var/lib/cybershield/hash_db.sqlite"
echo "  Logs: /var/log/cybershield/"
echo ""
echo "VirusTotal API Key:"
echo "  Set your API key in environment or config:"
echo "  export VIRUSTOTAL_API_KEY=your_key_here"
echo ""
echo "Next steps:"
echo "  1. Configure VirusTotal API key:"
echo "     sudo nano $CONFIG_DIR/config.toml"
echo ""
echo "  2. Start the service:"
echo "     sudo systemctl start av-service"
echo "     sudo systemctl enable av-service"
echo ""
echo "  3. Check status:"
echo "     sudo systemctl status av-service"
echo "     sudo journalctl -u av-service -f"
echo ""

# Check for Ollama installation
if command_exists ollama; then
    echo -e "${GREEN}✓ Ollama found - LLM threat explanations available${NC}"
    echo "  Download Llama 3.2 3B model:"
    echo "    ollama pull llama3.2:3b"
    echo ""
fi

# Check for Docker (for enhanced sandboxing)
if command_exists docker; then
    echo -e "${GREEN}✓ Docker found - Enhanced sandbox analysis available${NC}"
else
    echo -e "${YELLOW}⚠ Docker not found - Install for enhanced sandbox features${NC}"
    echo "  Install Docker: https://docs.docker.com/engine/install/"
    echo ""
fi

echo -e "${GREEN}CyberShield is ready to use!${NC}"
