#!/bin/bash
# CyberShield Installation Script for Arch Linux
# Usage: sudo ./arch-install.sh [--skip-deps] [--build-ebpf]
# Features: Full system setup, user/group creation, dependency management

set -e

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_USER="avsvc"
SERVICE_GROUP="avsvc"
INSTALL_PREFIX="/opt/cybershield"
CONFIG_DIR="/etc/cybershield"
SYSTEMD_DIR="/etc/systemd/system"
DATA_DIR="/var/lib/cybershield"
LOG_DIR="/var/log/cybershield"

# Parse flags
SKIP_DEPS=""
BUILD_EBPF=""
for arg in "$@"; do
    case "$arg" in
        --skip-deps) SKIP_DEPS="--skip-deps" ;;
        --build-ebpf|--full) BUILD_EBPF="--build-ebpf" ;;
    esac
done

# Functions
print_header() {
    echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}$1${NC}"
    echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
}

print_info() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}[⚠]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "This script must be run as root"
        exit 1
    fi
    print_info "Running as root"
}

check_arch() {
    if ! grep -q "^ID=arch$" /etc/os-release 2>/dev/null; then
        print_error "This script is for Arch Linux only"
        exit 1
    fi
    print_info "Detected: Arch Linux"
}

verify_kernel() {
    local kernel_version=$(uname -r)
    local kernel_config="/boot/config-${kernel_version}"
    
    if [ ! -f "$kernel_config" ]; then
        print_warn "Kernel config not found at $kernel_config"
        print_warn "Some features may be unavailable"
        return 0
    fi
    
    # Check for BPF_LSM
    if grep -q "CONFIG_BPF_LSM=y" "$kernel_config"; then
        print_info "✓ BPF_LSM enabled in kernel - eBPF monitoring available"
    else
        print_warn "BPF_LSM not enabled in current kernel ($kernel_version)"
        print_warn "eBPF monitoring will be disabled. To enable:"
        print_warn "  - Use: pacman -S linux-zen (or linux-hardened from AUR)"
        print_warn "  - Or: Compile kernel with CONFIG_BPF_LSM=y"
    fi
    
    # Check for BPF support
    if grep -q "CONFIG_BPF=y" "$kernel_config"; then
        print_info "✓ BPF support enabled"
    else
        print_error "BPF not enabled in kernel - required for eBPF monitoring"
        return 1
    fi
}

install_dependencies() {
    if [ "$SKIP_DEPS" == "--skip-deps" ]; then
        print_warn "Skipping dependency installation"
        return 0
    fi
    
    print_header "Installing Dependencies"
    
    # Runtime dependencies
    local runtime_deps=(
        "glibc"
        "openssl"
        "sqlite"
        "yara"
        "clamav"
        "libvirt"
    )
    
    # Build dependencies
    local build_deps=(
        "rustup"
        "cargo"
        "llvm"
        "clang"
        "pkg-config"
        "linux-headers"
        "git"
    )
    
    print_info "Updating package database..."
    pacman -Sy --noconfirm
    
    print_info "Installing runtime dependencies..."
    pacman -S --noconfirm "${runtime_deps[@]}"
    
    if [ "$BUILD_EBPF" == "--build-ebpf" ] || [ "$BUILD_EBPF" == "--full" ]; then
        print_info "Installing build dependencies for eBPF..."
        pacman -S --noconfirm "${build_deps[@]}"
    else
        print_warn "Skipping build dependencies (use --build-ebpf for full build)"
    fi
    
    # Verify installations
    print_info "Verifying critical tools..."
    
    local critical_tools=("yara" "clamscan" "sqlite3")
    for tool in "${critical_tools[@]}"; do
        if command -v "$tool" &> /dev/null; then
            print_info "✓ $tool installed"
        else
            print_error "$tool not found - critical for operation"
            return 1
        fi
    done
    
    # Check Rust
    if ! command -v rustc &> /dev/null; then
        print_warn "Rust not in PATH - installing from rustup..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source "$HOME/.cargo/env"
    fi
    print_info "✓ Rust toolchain available: $(rustc --version)"
    
    # Check Clang for eBPF
    if [ "$BUILD_EBPF" == "--build-ebpf" ] || [ "$BUILD_EBPF" == "--full" ]; then
        if ! command -v clang &> /dev/null; then
            print_error "Clang not found - required for eBPF compilation"
            return 1
        fi
        print_info "✓ Clang available: $(clang --version | head -1)"
    fi
}

create_user_group() {
    print_header "Creating Service User & Group"
    
    # Check if group exists
    if ! getent group "$SERVICE_GROUP" > /dev/null 2>&1; then
        print_info "Creating group: $SERVICE_GROUP"
        groupadd --system --gid 980 "$SERVICE_GROUP" 2>/dev/null || {
            # Fallback if UID already exists
            groupadd --system "$SERVICE_GROUP"
        }
    else
        print_info "✓ Group $SERVICE_GROUP already exists"
    fi
    
    # Check if user exists
    if ! id "$SERVICE_USER" > /dev/null 2>&1; then
        print_info "Creating user: $SERVICE_USER"
        useradd --system \
            --gid "$SERVICE_GROUP" \
            --uid 980 \
            --home-dir "$DATA_DIR" \
            --shell /usr/sbin/nologin \
            --comment "CyberShield Antivirus Service" \
            "$SERVICE_USER" 2>/dev/null || {
            # Fallback if UID already exists
            useradd --system \
                --gid "$SERVICE_GROUP" \
                --home-dir "$DATA_DIR" \
                --shell /usr/sbin/nologin \
                --comment "CyberShield Antivirus Service" \
                "$SERVICE_USER"
        }
    else
        print_info "✓ User $SERVICE_USER already exists"
    fi
    
    # Add libvirt access if available
    if getent group libvirt > /dev/null 2>&1; then
        print_info "Adding $SERVICE_USER to libvirt group..."
        usermod -a -G libvirt "$SERVICE_USER" 2>/dev/null || true
    fi
    
    print_info "✓ User/group setup complete"
}

create_directories() {
    print_header "Creating Data Directories"
    
    # Create directories
    mkdir -p "$INSTALL_PREFIX/bin"
    mkdir -p "$INSTALL_PREFIX/lib"
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$DATA_DIR/rules"
    mkdir -p "$DATA_DIR/vms"
    mkdir -p "$LOG_DIR"
    mkdir -p /var/run/cybershield
    
    # Set ownership and permissions
    chown -R "$SERVICE_USER:$SERVICE_GROUP" "$DATA_DIR" "$LOG_DIR" /var/run/cybershield
    chmod 0700 "$DATA_DIR" "$LOG_DIR" /var/run/cybershield
    chmod 0755 "$INSTALL_PREFIX"
    chmod 0755 "$INSTALL_PREFIX/bin"
    
    print_info "✓ Created: $INSTALL_PREFIX"
    print_info "✓ Created: $CONFIG_DIR"
    print_info "✓ Created: $DATA_DIR"
    print_info "✓ Created: $LOG_DIR"
    print_info "✓ Created: /var/run/cybershield"
}

build_binaries() {
    if [ ! -d "$SCRIPT_DIR/av-service" ]; then
        print_error "av-service source not found at $SCRIPT_DIR/av-service"
        return 1
    fi
    
    print_header "Building CyberShield Components"
    
    # Build av-service
    print_info "Building av-service..."
    cd "$SCRIPT_DIR/av-service"
    RUSTFLAGS="-C opt-level=3 -C lto=fat -C codegen-units=1" \
        cargo build --release --locked 2>&1 | tail -20
    
    if [ ! -f "target/release/av-service" ]; then
        print_error "Failed to build av-service"
        return 1
    fi
    
    cp target/release/av-service "$INSTALL_PREFIX/bin/"
    chmod 755 "$INSTALL_PREFIX/bin/av-service"
    print_info "✓ Installed av-service"
    
    # Build av-sandbox if available
    if [ -d "$SCRIPT_DIR/av-sandbox" ]; then
        print_info "Building av-sandbox..."
        cd "$SCRIPT_DIR/av-sandbox"
        cargo build --release --locked 2>&1 | tail -20
        
        if [ -f "target/release/av-sandbox" ]; then
            cp target/release/av-sandbox "$INSTALL_PREFIX/bin/"
            chmod 755 "$INSTALL_PREFIX/bin/av-sandbox"
            print_info "✓ Installed av-sandbox"
        fi
    fi
    
    # Build av-ai if available
    if [ -d "$SCRIPT_DIR/av-ai" ]; then
        print_info "Building av-ai (LLM component)..."
        cd "$SCRIPT_DIR/av-ai"
        cargo build --release --locked 2>&1 | tail -20
        
        if [ -f "target/release/av-ai" ]; then
            cp target/release/av-ai "$INSTALL_PREFIX/bin/"
            chmod 755 "$INSTALL_PREFIX/bin/av-ai"
            print_info "✓ Installed av-ai"
        fi
    fi
    
    cd "$SCRIPT_DIR"
}

compile_ebpf() {
    if [ "$BUILD_EBPF" != "--build-ebpf" ] && [ "$BUILD_EBPF" != "--full" ]; then
        print_info "Skipping eBPF build (use --build-ebpf to enable)"
        return 0
    fi
    
    if [ ! -d "$SCRIPT_DIR/av-kernel-linux/ebpf" ]; then
        print_warn "eBPF source not found - skipping compilation"
        return 0
    fi
    
    print_header "Compiling eBPF LSM Program"
    
    cd "$SCRIPT_DIR/av-kernel-linux/ebpf"
    
    # Verify clang
    if ! command -v clang &> /dev/null; then
        print_error "clang not found - cannot compile eBPF"
        return 1
    fi
    
    # Compile BPF object
    print_info "Compiling lsm_file_monitor.c..."
    clang -O2 -target bpf \
        -D__KERNEL__ -D__BPF_TRACING__ \
        -I/usr/include/linux \
        -c lsm_file_monitor.c -o lsm_file_monitor.o
    
    if [ ! -f "lsm_file_monitor.o" ]; then
        print_error "eBPF compilation failed"
        return 1
    fi
    
    # Install BPF object
    install -Dm644 lsm_file_monitor.o "$INSTALL_PREFIX/lib/lsm_file_monitor.o"
    chmod 644 "$INSTALL_PREFIX/lib/lsm_file_monitor.o"
    
    print_info "✓ eBPF LSM object installed to $INSTALL_PREFIX/lib/"
    cd "$SCRIPT_DIR"
}

install_systemd_units() {
    print_header "Installing Systemd Units"
    
    # Copy service file
    if [ -f "$SCRIPT_DIR/systemd/av-service.service" ]; then
        install -Dm644 "$SCRIPT_DIR/systemd/av-service.service" \
            "$SYSTEMD_DIR/av-service.service"
        print_info "✓ Installed av-service.service"
    fi
    
    # Create preset to enable on install
    mkdir -p /etc/systemd/system-preset
    cat > /etc/systemd/system-preset/40-cybershield.preset << 'EOF'
enable av-service.service
EOF
    chmod 644 /etc/systemd/system-preset/40-cybershield.preset
    print_info "✓ Created systemd preset"
    
    # Reload systemd daemon
    systemctl daemon-reload
    print_info "✓ Systemd daemon reloaded"
}

install_configuration() {
    print_header "Installing Configuration Files"
    
    # Create default config if it doesn't exist
    if [ ! -f "$CONFIG_DIR/config.toml" ]; then
        cat > "$CONFIG_DIR/config.toml" << 'EOF'
# CyberShield av-service Configuration
# Generated by arch-install.sh

# Hash Database Configuration
[database]
path = "/var/lib/cybershield/hash_db.sqlite"
max_pool_size = 10
timeout_seconds = 30

# Heuristics Analysis Engine
[heuristics]
enabled = true
entropy_threshold = 7.8
suspicious_string_threshold = 5

# ClamAV Antivirus Engine
[clamav]
enabled = true
cli_path = "/usr/bin/clamscan"
timeout_seconds = 10
max_file_size = 2147483648  # 2GB

# YARA Rule Matching Engine
[yara]
enabled = true
rules_directory = "/var/lib/cybershield/rules"
timeout_seconds = 15
scan_recursive = true

# VirusTotal API Integration (Privacy-First)
[virustotal]
enabled = true
api_key = ""  # Set via environment: VIRUSTOTAL_API_KEY
rate_limit = 4  # Free tier: 4 requests/minute
timeout_seconds = 10
cache_positive_hits = true
cache_days = 30

# eBPF LSM Kernel Monitoring
[ebpf]
enabled = false  # Set to true if BPF_LSM available
object_path = "/opt/cybershield/lib/lsm_file_monitor.o"
ring_buffer_size = 256  # Pages
monitor_file_opens = true
monitor_syscalls = true

# libvirt VM Sandbox Configuration
[sandbox]
enabled = false  # Set to true if libvirt available
libvirt_uri = "qemu:///system"
vm_snapshot_base = "/var/lib/cybershield/vms"
timeout_seconds = 60
cpu_cores = 2
memory_mb = 2048

# LLM-Based Threat Explanations
[llm]
enabled = false  # Set to true if Ollama running
model = "llama3.2:3b"
ollama_host = "http://localhost:11434"
timeout_seconds = 30
context_tokens = 2048

# Logging Configuration
[logging]
level = "info"  # debug, info, warn, error
format = "json"  # json or text
max_size_mb = 100
retention_days = 30
output = "both"  # file, journal, or both

# IPC Socket Configuration
[ipc]
socket_path = "/var/run/av_event.sock"
socket_mode = 0666
max_connections = 100
buffer_size = 65536

# Performance Tuning
[performance]
max_concurrent_scans = 4
cache_size_mb = 500
timeout_seconds = 30
batch_size = 100

# Security Settings
[security]
use_unprivileged_user = true
verify_file_signatures = false  # Not yet implemented
block_suspicious = false  # Set to true for strict mode
EOF
        chmod 644 "$CONFIG_DIR/config.toml"
        print_info "✓ Created default config: $CONFIG_DIR/config.toml"
    else
        print_warn "Config already exists: $CONFIG_DIR/config.toml"
    fi
    
    # Create environment file
    cat > /etc/default/av-service << 'EOF'
# CyberShield av-service environment variables
# Sourced by systemd unit

RUST_LOG=info
HASH_DB_PATH=/var/lib/cybershield/hash_db.sqlite

# Optional: VirusTotal API key
# VIRUSTOTAL_API_KEY=your_api_key_here

# Optional: Ollama/LLM configuration
# OLLAMA_HOST=http://localhost:11434
# LLM_MODEL=llama3.2:3b

# Thread pool configuration
# TOKIO_WORKER_THREADS=8
EOF
    chmod 644 /etc/default/av-service
    print_info "✓ Created environment file: /etc/default/av-service"
}

install_yara_rules() {
    print_header "Setting Up YARA Rules"
    
    # Check if git is available
    if ! command -v git &> /dev/null; then
        print_warn "git not found - cannot download YARA rules"
        print_warn "Manual installation: git clone https://github.com/Yara-Rules/rules.git /var/lib/cybershield/rules"
        return 0
    fi
    
    # Check if directory is empty
    if [ -z "$(ls -A "$DATA_DIR/rules" 2>/dev/null)" ]; then
        print_info "Downloading public YARA rules from GitHub..."
        git clone --depth 1 https://github.com/Yara-Rules/rules.git /tmp/yara-rules-temp
        
        # Copy rules, maintaining permissions
        cp -r /tmp/yara-rules-temp/*.yar "$DATA_DIR/rules/" 2>/dev/null || true
        rm -rf /tmp/yara-rules-temp
        
        # Set ownership
        chown -R "$SERVICE_USER:$SERVICE_GROUP" "$DATA_DIR/rules"
        chmod 644 "$DATA_DIR/rules"/*.yar 2>/dev/null || true
        
        print_info "✓ YARA rules installed to $DATA_DIR/rules/"
    else
        print_warn "YARA rules directory not empty - skipping download"
    fi
}

update_clamav_sigs() {
    print_header "Updating ClamAV Signatures"
    
    if ! command -v freshclam &> /dev/null; then
        print_error "freshclam not found - install clamav package"
        return 1
    fi
    
    # Stop clamd if running to avoid lock
    systemctl stop clamav-daemon.service 2>/dev/null || true
    
    print_info "Running freshclam to update signatures..."
    freshclam || {
        print_warn "freshclam failed - check network connectivity"
        print_warn "Manual update: sudo freshclam"
    }
    
    print_info "✓ ClamAV signatures updated"
}

verify_installation() {
    print_header "Verifying Installation"
    
    local errors=0
    
    # Check binaries
    if [ -f "$INSTALL_PREFIX/bin/av-service" ]; then
        print_info "✓ av-service binary installed"
    else
        print_error "av-service binary not found"
        ((errors++))
    fi
    
    # Check config
    if [ -f "$CONFIG_DIR/config.toml" ]; then
        print_info "✓ Configuration file present"
    else
        print_error "Configuration file not found"
        ((errors++))
    fi
    
    # Check systemd unit
    if [ -f "$SYSTEMD_DIR/av-service.service" ]; then
        print_info "✓ Systemd service installed"
    else
        print_error "Systemd service not found"
        ((errors++))
    fi
    
    # Check directories
    if [ -d "$DATA_DIR" ]; then
        print_info "✓ Data directory exists"
    else
        print_error "Data directory not found"
        ((errors++))
    fi
    
    # Test av-service binary
    if "$INSTALL_PREFIX/bin/av-service" --version &>/dev/null; then
        print_info "✓ av-service binary executable"
    else
        print_warn "av-service --version failed (may still be functional)"
    fi
    
    # Check user/group
    if id "$SERVICE_USER" > /dev/null 2>&1; then
        print_info "✓ Service user $SERVICE_USER exists"
    else
        print_error "Service user $SERVICE_USER not found"
        ((errors++))
    fi
    
    if [ $errors -gt 0 ]; then
        print_error "Verification failed with $errors error(s)"
        return 1
    fi
    
    print_info "✓ All verification checks passed"
    return 0
}

show_next_steps() {
    cat << 'EOF'

╔════════════════════════════════════════════════════════════════╗
║         CyberShield Installation Complete on Arch Linux        ║
╚════════════════════════════════════════════════════════════════╝

NEXT STEPS:

1. CONFIGURE VIRUSTOTAL API KEY (optional):
   $ sudo nano /etc/cybershield/config.toml
   # Set: api_key = "your-api-key"
   
   Or via environment:
   $ export VIRUSTOTAL_API_KEY="your-api-key"
   $ sudo -E systemctl edit av-service
   # Add under [Service]: Environment="VIRUSTOTAL_API_KEY=${VIRUSTOTAL_API_KEY}"

2. ENABLE eBPF KERNEL MONITORING (if available):
   $ grep CONFIG_BPF_LSM /boot/config-$(uname -r)
   
   If CONFIG_BPF_LSM=y is present, enable in config:
   $ sudo nano /etc/cybershield/config.toml
   # In [ebpf] section: enabled = true

3. INSTALL/UPDATE YARA RULES:
   Rules already downloaded to: /var/lib/cybershield/rules/
   
   To manually update:
   $ cd /var/lib/cybershield/rules
   $ sudo git pull

4. SETUP OPTIONAL FEATURES:

   a) Ollama for LLM threat explanations:
      $ pacman -S ollama
      $ ollama pull llama3.2:3b
      
      Then enable in config:
      $ sudo nano /etc/cybershield/config.toml
      # In [llm] section: enabled = true

   b) libvirt for sandbox VM analysis:
      $ sudo pacman -S libvirt virt-manager qemu
      $ sudo systemctl enable libvirtd
      $ sudo systemctl start libvirtd

5. START THE SERVICE:
   $ sudo systemctl enable av-service.service
   $ sudo systemctl enable av-service.socket
   $ sudo systemctl start av-service.service

6. VERIFY SERVICE IS RUNNING:
   $ sudo systemctl status av-service
   $ sudo journalctl -u av-service -f
   
7. TEST SCANNING (EICAR test file):
   $ wget http://www.eicar.org/download/eicar.com.txt -O /tmp/eicar.txt
   
   Check logs:
   $ sudo journalctl -u av-service --follow

CONFIGURATION REFERENCE:
• Config: /etc/cybershield/config.toml
• Environment: /etc/default/av-service
• Binaries: /opt/cybershield/bin/
• Database: /var/lib/cybershield/hash_db.sqlite
• YARA rules: /var/lib/cybershield/rules/
• Logs: /var/log/cybershield/ + journalctl -u av-service
• Socket: /var/run/av_event.sock (IPC)

DOCUMENTATION:
$ man av-service            # Manual page (if available)
$ cat /usr/share/doc/cybershield/README.md
$ cat /usr/share/doc/cybershield/ARCHITECTURE.md

TROUBLESHOOTING:
$ sudo systemctl status av-service       # Check service status
$ sudo journalctl -u av-service -n 50    # Last 50 log lines
$ sudo journalctl -u av-service -e       # Jump to end of logs
$ RUST_LOG=debug sudo /opt/cybershield/bin/av-service  # Run with debug logging

UNINSTALL:
$ pacman -R cybershield
$ sudo rm -rf /etc/cybershield /var/lib/cybershield /var/log/cybershield

EOF
}

# ════════════════════════════════════════════════════════════════════════════
# MAIN EXECUTION
# ════════════════════════════════════════════════════════════════════════════

main() {
    check_root
    check_arch
    
    print_header "CyberShield Installation Script for Arch Linux"
    
    verify_kernel || {
        print_warn "Kernel verification failed - some features may be unavailable"
    }
    
    install_dependencies || exit 1
    create_user_group || exit 1
    create_directories || exit 1
    
    build_binaries || exit 1
    compile_ebpf || {
        print_warn "eBPF compilation skipped or failed"
    }
    
    install_systemd_units || exit 1
    install_configuration || exit 1
    install_yara_rules || {
        print_warn "YARA rules installation failed or skipped"
    }
    
    update_clamav_sigs || {
        print_warn "ClamAV signature update failed - try manual: sudo freshclam"
    }
    
    verify_installation || exit 1
    
    print_header "Installation Summary"
    print_info "Installation prefix: $INSTALL_PREFIX"
    print_info "Configuration: $CONFIG_DIR/config.toml"
    print_info "Data directory: $DATA_DIR"
    print_info "Service user: $SERVICE_USER"
    print_info "Systemd unit: /etc/systemd/system/av-service.service"
    
    show_next_steps
}

# Run main function
main "$@"
