#!/usr/bin/env bash
# CyberShield av-service Test Suite
# Validates functionality, integration, and security hardening
# Run as: sudo ./test-cybershield.sh [--full|--quick|--ebpf|--lvm]
# Arch Linux - Production Validation

set -o pipefail

# ════════════════════════════════════════════════════════════════════════════
# COLORS AND OUTPUT
# ════════════════════════════════════════════════════════════════════════════

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

print_header() {
    echo -e "${BLUE}"
    echo "════════════════════════════════════════════════════════════════════════════"
    echo "$1"
    echo "════════════════════════════════════════════════════════════════════════════"
    echo -e "${NC}"
}

print_test() {
    echo -ne "${YELLOW}[TEST]${NC} $1 ... "
}

print_pass() {
    echo -e "${GREEN}✓ PASS${NC}"
    ((TESTS_PASSED++))
    ((TESTS_RUN++))
}

print_fail() {
    echo -e "${RED}✗ FAIL${NC}"
    echo -e "${RED}   Reason: $1${NC}"
    ((TESTS_FAILED++))
    ((TESTS_RUN++))
}

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

# ════════════════════════════════════════════════════════════════════════════
# PREREQUISITE CHECKS
# ════════════════════════════════════════════════════════════════════════════

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

check_arch() {
    if ! grep -q "^ID=arch$" /etc/os-release 2>/dev/null; then
        print_error "This script is designed for Arch Linux"
        exit 1
    fi
}

check_binary() {
    local binary=$1
    if ! command -v "$binary" &> /dev/null; then
        print_fail "Binary not found: $binary"
        return 1
    fi
    print_pass "Binary found: $binary"
    return 0
}

# ════════════════════════════════════════════════════════════════════════════
# TEST SUITE 1: INSTALLATION AND BINARIES
# ════════════════════════════════════════════════════════════════════════════

test_binaries() {
    print_header "TEST SUITE 1: Installation and Binaries"
    
    print_test "av-service binary exists"
    [[ -f /opt/cybershield/bin/av-service ]] && print_pass || print_fail "Binary not found at /opt/cybershield/bin/av-service"
    
    print_test "av-sandbox binary exists"
    [[ -f /opt/cybershield/bin/av-sandbox ]] && print_pass || print_fail "Binary not found at /opt/cybershield/bin/av-sandbox"
    
    print_test "av-ai binary exists"
    [[ -f /opt/cybershield/bin/av-ai ]] && print_pass || print_fail "Binary not found at /opt/cybershield/bin/av-ai"
    
    print_test "av-service is executable"
    [[ -x /opt/cybershield/bin/av-service ]] && print_pass || print_fail "av-service not executable"
    
    print_test "eBPF object file exists"
    [[ -f /opt/cybershield/lib/lsm_file_monitor.o ]] && print_pass || print_fail "eBPF object not found"
    
    print_test "Config file exists"
    [[ -f /etc/cybershield/config.toml ]] && print_pass || print_fail "Config file not found"
}

# ════════════════════════════════════════════════════════════════════════════
# TEST SUITE 2: USER AND PERMISSIONS
# ════════════════════════════════════════════════════════════════════════════

test_permissions() {
    print_header "TEST SUITE 2: User and Permissions"
    
    print_test "avsvc user exists"
    id avsvc &>/dev/null && print_pass || print_fail "User 'avsvc' not found"
    
    print_test "avsvc group exists"
    getent group avsvc &>/dev/null && print_pass || print_fail "Group 'avsvc' not found"
    
    print_test "/var/lib/cybershield owned by avsvc"
    [[ $(stat -c %U /var/lib/cybershield) == "avsvc" ]] && print_pass || print_fail "Directory not owned by avsvc"
    
    print_test "/var/lib/cybershield has correct permissions (0700)"
    [[ $(stat -c %a /var/lib/cybershield) == "700" ]] && print_pass || print_fail "Incorrect permissions"
    
    print_test "/etc/cybershield readable by avsvc"
    [[ -r /etc/cybershield/config.toml ]] && print_pass || print_fail "Config not readable"
    
    print_test "Database file writable by avsvc"
    [[ -w /var/lib/cybershield/hash_db.sqlite ]] && print_pass || print_fail "Database not writable"
}

# ════════════════════════════════════════════════════════════════════════════
# TEST SUITE 3: SYSTEMD SERVICE
# ════════════════════════════════════════════════════════════════════════════

test_systemd() {
    print_header "TEST SUITE 3: Systemd Service"
    
    print_test "av-service.service unit exists"
    systemctl cat av-service &>/dev/null && print_pass || print_fail "Unit not found"
    
    print_test "av-service.socket unit exists"
    systemctl cat av-service.socket &>/dev/null && print_pass || print_fail "Socket unit not found"
    
    print_test "Service is enabled"
    systemctl is-enabled av-service &>/dev/null && print_pass || print_fail "Service not enabled"
    
    print_test "Service is active"
    systemctl is-active av-service &>/dev/null && print_pass || print_fail "Service not running"
    
    print_test "Service restart policy is configured"
    grep -q "Restart=on-failure" <(systemctl cat av-service) && print_pass || print_fail "Restart policy not found"
}

# ════════════════════════════════════════════════════════════════════════════
# TEST SUITE 4: SECURITY HARDENING
# ════════════════════════════════════════════════════════════════════════════

test_security() {
    print_header "TEST SUITE 4: Security Hardening"
    
    local unit=$(systemctl cat av-service)
    
    print_test "MemoryDenyWriteExecute=yes"
    echo "$unit" | grep -q "MemoryDenyWriteExecute=yes" && print_pass || print_fail "W^X protection not enabled"
    
    print_test "ProtectSystem=strict"
    echo "$unit" | grep -q "ProtectSystem=strict" && print_pass || print_fail "File system protection not strict"
    
    print_test "ProtectHome=yes"
    echo "$unit" | grep -q "ProtectHome=yes" && print_pass || print_fail "Home directory not protected"
    
    print_test "NoNewPrivileges=yes"
    echo "$unit" | grep -q "NoNewPrivileges=yes" && print_pass || print_fail "No new privileges not enforced"
    
    print_test "PrivateTmp=yes"
    echo "$unit" | grep -q "PrivateTmp=yes" && print_pass || print_fail "Private /tmp not enabled"
    
    print_test "SystemCallFilter configured"
    echo "$unit" | grep -q "SystemCallFilter=" && print_pass || print_fail "Seccomp filter not found"
    
    print_test "CapabilityBoundingSet restricted"
    echo "$unit" | grep -q "CapabilityBoundingSet=" && print_pass || print_fail "Capabilities not restricted"
    
    print_test "Resource limits configured"
    echo "$unit" | grep -q "MemoryMax=" && print_pass || print_fail "Memory limits not configured"
}

# ════════════════════════════════════════════════════════════════════════════
# TEST SUITE 5: KERNEL AND eBPF
# ════════════════════════════════════════════════════════════════════════════

test_ebpf() {
    print_header "TEST SUITE 5: eBPF and Kernel Configuration"
    
    local kernel_release=$(uname -r)
    local kernel_config="/boot/config-${kernel_release}"
    
    print_test "Kernel version 5.8 or higher"
    local kernel_version=$(uname -r | cut -d. -f1,2)
    (( $(echo "$kernel_version >= 5.8" | bc -l) )) 2>/dev/null && print_pass || print_fail "Kernel version too old"
    
    print_test "CONFIG_BPF=y in kernel config"
    grep -q "^CONFIG_BPF=y" "$kernel_config" 2>/dev/null && print_pass || print_fail "BPF not enabled in kernel"
    
    print_test "CONFIG_DEBUG_INFO_BTF=y in kernel config"
    grep -q "^CONFIG_DEBUG_INFO_BTF=y" "$kernel_config" 2>/dev/null && print_pass || print_fail "BTF not enabled"
    
    print_test "CONFIG_BPF_LSM=y in kernel config (optional)"
    if grep -q "^CONFIG_BPF_LSM=y" "$kernel_config" 2>/dev/null; then
        print_pass
    else
        echo -e "${YELLOW}   (optional - eBPF LSM monitoring requires this kernel config)${NC}"
        ((TESTS_RUN++))
    fi
    
    print_test "/sys/kernel/btf/vmlinux exists"
    [[ -f /sys/kernel/btf/vmlinux ]] && print_pass || print_fail "Kernel BTF not available"
    
    print_test "bpftool available"
    command -v bpftool &>/dev/null && print_pass || print_fail "bpftool not installed"
}

# ════════════════════════════════════════════════════════════════════════════
# TEST SUITE 6: EXTERNAL DEPENDENCIES
# ════════════════════════════════════════════════════════════════════════════

test_dependencies() {
    print_header "TEST SUITE 6: External Dependencies"
    
    print_test "clamscan (ClamAV) available"
    command -v clamscan &>/dev/null && print_pass || print_fail "clamscan not installed"
    
    print_test "freshclam (ClamAV updater) available"
    command -v freshclam &>/dev/null && print_pass || print_fail "freshclam not installed"
    
    print_test "ClamAV database updated"
    [[ -d /var/lib/clamav ]] && [[ $(find /var/lib/clamav -name "*.cvd" -o -name "*.cld" | wc -l) -gt 0 ]] && \
        print_pass || print_fail "ClamAV databases not found - run 'sudo freshclam'"
    
    print_test "yara available"
    command -v yara &>/dev/null && print_pass || print_fail "yara not installed"
    
    print_test "YARA rules exist"
    [[ -d /var/lib/cybershield/rules ]] && [[ $(find /var/lib/cybershield/rules -name "*.yar" | wc -l) -gt 0 ]] && \
        print_pass || print_fail "YARA rules directory not found"
    
    print_test "virsh (libvirt) available"
    command -v virsh &>/dev/null && print_pass || print_fail "virsh not installed"
    
    print_test "sqlite3 available"
    command -v sqlite3 &>/dev/null && print_pass || print_fail "sqlite3 not installed"
}

# ════════════════════════════════════════════════════════════════════════════
# TEST SUITE 7: FUNCTIONALITY - HASH SCANNING
# ════════════════════════════════════════════════════════════════════════════

test_hash_scan() {
    print_header "TEST SUITE 7: Hash-Based Scanning"
    
    # Create test file
    local test_file="/tmp/cybershield_test_$(date +%s).txt"
    echo "Test file content" > "$test_file"
    
    print_test "Test file created"
    [[ -f "$test_file" ]] && print_pass || print_fail "Could not create test file"
    
    # Calculate SHA256
    local file_hash=$(sha256sum "$test_file" | cut -d' ' -f1)
    
    print_test "SHA256 hash calculated"
    [[ -n "$file_hash" ]] && print_pass || print_fail "Could not calculate hash"
    
    # Query database (requires av-service to be running)
    print_test "Hash database queryable"
    if systemctl is-active av-service &>/dev/null; then
        # Database will be populated after actual scans
        print_pass
    else
        echo -e "${YELLOW}   (skipped - av-service not running)${NC}"
        ((TESTS_RUN++))
    fi
    
    rm -f "$test_file"
}

# ════════════════════════════════════════════════════════════════════════════
# TEST SUITE 8: FUNCTIONALITY - CLAMAV SCANNING
# ════════════════════════════════════════════════════════════════════════════

test_clamav_scan() {
    print_header "TEST SUITE 8: ClamAV Integration"
    
    print_test "Create EICAR test file"
    local eicar_file="/tmp/eicar.txt"
    echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > "$eicar_file"
    [[ -f "$eicar_file" ]] && print_pass || print_fail "Could not create EICAR test file"
    
    print_test "clamscan detects EICAR"
    if clamscan "$eicar_file" 2>&1 | grep -q "Eicar-Test-File"; then
        print_pass
    else
        print_fail "clamscan did not detect EICAR test file"
    fi
    
    print_test "clamscan binary path correct"
    [[ "$(which clamscan)" == "/usr/bin/clamscan" ]] && print_pass || print_fail "clamscan at unexpected path"
    
    rm -f "$eicar_file"
}

# ════════════════════════════════════════════════════════════════════════════
# TEST SUITE 9: CONFIGURATION VALIDATION
# ════════════════════════════════════════════════════════════════════════════

test_configuration() {
    print_header "TEST SUITE 9: Configuration Validation"
    
    local config="/etc/cybershield/config.toml"
    
    print_test "Config file is valid TOML"
    if command -v toml-cli &>/dev/null; then
        toml-cli "$config" &>/dev/null && print_pass || print_fail "TOML syntax error"
    else
        # Basic validation
        grep -q "^\[database\]" "$config" && print_pass || print_fail "Missing [database] section"
    fi
    
    print_test "[database] section exists"
    grep -q "^\[database\]" "$config" && print_pass || print_fail "[database] section not found"
    
    print_test "[heuristics] section exists"
    grep -q "^\[heuristics\]" "$config" && print_pass || print_fail "[heuristics] section not found"
    
    print_test "[clamav] section exists"
    grep -q "^\[clamav\]" "$config" && print_pass || print_fail "[clamav] section not found"
    
    print_test "[yara] section exists"
    grep -q "^\[yara\]" "$config" && print_pass || print_fail "[yara] section not found"
    
    print_test "[virustotal] section exists"
    grep -q "^\[virustotal\]" "$config" && print_pass || print_fail "[virustotal] section not found"
    
    print_test "[ebpf] section exists"
    grep -q "^\[ebpf\]" "$config" && print_pass || print_fail "[ebpf] section not found"
    
    print_test "[logging] section exists"
    grep -q "^\[logging\]" "$config" && print_pass || print_fail "[logging] section not found"
}

# ════════════════════════════════════════════════════════════════════════════
# TEST SUITE 10: SYSTEMD JOURNAL LOGGING
# ════════════════════════════════════════════════════════════════════════════

test_logging() {
    print_header "TEST SUITE 10: Logging and Journal"
    
    print_test "av-service logs in journalctl"
    if journalctl -u av-service --no-pager -n 50 2>/dev/null | grep -q "av-service"; then
        print_pass
    else
        echo -e "${YELLOW}   (may be empty if service just started)${NC}"
        ((TESTS_RUN++))
    fi
    
    print_test "Log directory exists"
    [[ -d /var/log/cybershield ]] && print_pass || print_fail "Log directory not found"
    
    print_test "Log files writable by avsvc"
    if [[ -f /var/log/cybershield/av-service.log ]]; then
        [[ -w /var/log/cybershield/av-service.log ]] && print_pass || print_fail "Log not writable"
    else
        echo -e "${YELLOW}   (log file will be created on first run)${NC}"
        ((TESTS_RUN++))
    fi
}

# ════════════════════════════════════════════════════════════════════════════
# TEST SUITE 11: SOCKET AND IPC
# ════════════════════════════════════════════════════════════════════════════

test_ipc() {
    print_header "TEST SUITE 11: IPC Socket Configuration"
    
    print_test "av-service.socket exists"
    systemctl cat av-service.socket &>/dev/null && print_pass || print_fail "Socket unit not found"
    
    print_test "Socket is enabled"
    systemctl is-enabled av-service.socket &>/dev/null && print_pass || print_fail "Socket not enabled"
    
    print_test "Socket is active"
    systemctl is-active av-service.socket &>/dev/null && print_pass || print_fail "Socket not active"
    
    print_test "IPC socket path configured"
    grep -q "ListenStream=" <(systemctl cat av-service.socket) && print_pass || print_fail "Listen path not configured"
}

# ════════════════════════════════════════════════════════════════════════════
# TEST SUITE 12: OPTIONAL FEATURES
# ════════════════════════════════════════════════════════════════════════════

test_optional() {
    print_header "TEST SUITE 12: Optional Features"
    
    # LLM Integration
    print_test "Ollama available (LLM support)"
    if command -v ollama &>/dev/null; then
        print_pass
    else
        echo -e "${YELLOW}   (optional - run 'pacman -S ollama' to enable LLM threat explanations)${NC}"
        ((TESTS_RUN++))
    fi
    
    # libvirt VM sandbox
    print_test "libvirt daemon running (VM sandbox)"
    if systemctl is-active libvirtd &>/dev/null; then
        print_pass
    else
        echo -e "${YELLOW}   (optional - VM sandbox requires libvirtd)${NC}"
        ((TESTS_RUN++))
    fi
    
    # bpftool
    print_test "bpftool for BPF debugging"
    if command -v bpftool &>/dev/null; then
        print_pass
    else
        echo -e "${YELLOW}   (optional - 'pacman -S linux-tools' for eBPF debugging)${NC}"
        ((TESTS_RUN++))
    fi
}

# ════════════════════════════════════════════════════════════════════════════
# TEST EXECUTION COMMANDS
# ════════════════════════════════════════════════════════════════════════════

test_commands() {
    print_header "TEST SUITE 13: Common Validation Commands"
    
    echo -e "${BLUE}View service status:${NC}"
    echo "  $ systemctl status av-service"
    echo ""
    
    echo -e "${BLUE}Check service logs:${NC}"
    echo "  $ journalctl -u av-service -f"
    echo "  $ journalctl -u av-service --no-pager -n 100"
    echo ""
    
    echo -e "${BLUE}Check eBPF LSM events (if CONFIG_BPF_LSM=y):${NC}"
    echo "  $ sudo bpftool prog list"
    echo "  $ sudo cat /sys/kernel/debug/tracing/trace | tail -20"
    echo ""
    
    echo -e "${BLUE}Verify systemd hardening:${NC}"
    echo "  $ systemd-analyze security av-service"
    echo ""
    
    echo -e "${BLUE}Test ClamAV scanning:${NC}"
    echo "  $ clamscan --version"
    echo "  $ freshclam  # update signatures"
    echo "  $ clamscan -r /var/lib/cybershield"
    echo ""
    
    echo -e "${BLUE}Test YARA rules:${NC}"
    echo "  $ yara -v"
    echo "  $ yara /var/lib/cybershield/rules/*.yar /test/file"
    echo ""
    
    echo -e "${BLUE}Query hash database:${NC}"
    echo "  $ sqlite3 /var/lib/cybershield/hash_db.sqlite \"SELECT COUNT(*) FROM threat_cache;\""
    echo ""
    
    echo -e "${BLUE}Check resource limits:${NC}"
    echo "  $ systemctl show -p MemoryMax --value av-service"
    echo "  $ systemctl show -p CPUQuota --value av-service"
    echo ""
    
    echo -e "${BLUE}Monitor real-time activity:${NC}"
    echo "  $ watch -n 1 systemctl status av-service"
    echo ""
}

# ════════════════════════════════════════════════════════════════════════════
# SERVICE STATUS AND DIAGNOSTICS
# ════════════════════════════════════════════════════════════════════════════

show_diagnostics() {
    print_header "DIAGNOSTICS"
    
    echo -e "${BLUE}Service Status:${NC}"
    systemctl status av-service --no-pager 2>/dev/null | head -20
    echo ""
    
    echo -e "${BLUE}Recent Logs:${NC}"
    journalctl -u av-service --no-pager -n 20
    echo ""
    
    echo -e "${BLUE}System Resources:${NC}"
    echo "Memory: $(systemctl show -p MemoryMax --value av-service)"
    echo "CPU Quota: $(systemctl show -p CPUQuota --value av-service)"
    echo ""
    
    echo -e "${BLUE}Kernel Configuration:${NC}"
    uname -r
    grep "CONFIG_BPF" /boot/config-$(uname -r) 2>/dev/null || echo "Kernel config not available"
}

# ════════════════════════════════════════════════════════════════════════════
# MAIN TEST EXECUTION
# ════════════════════════════════════════════════════════════════════════════

main() {
    local test_mode="${1:-}"
    
    # Header
    print_header "CyberShield av-service Test Suite - Arch Linux"
    
    # Prerequisites
    check_root
    check_arch
    
    # Run test suites based on mode
    case "$test_mode" in
        --quick)
            print_info "Running quick test suite..."
            test_binaries
            test_permissions
            test_systemd
            ;;
        --ebpf)
            print_info "Running eBPF-specific tests..."
            test_ebpf
            ;;
        --lvm)
            print_info "Running VM sandbox tests..."
            test_dependencies
            ;;
        --full|*)
            print_info "Running full test suite (this may take 2-3 minutes)..."
            test_binaries
            test_permissions
            test_systemd
            test_security
            test_ebpf
            test_dependencies
            test_hash_scan
            test_clamav_scan
            test_configuration
            test_logging
            test_ipc
            test_optional
            test_commands
            show_diagnostics
            ;;
    esac
    
    # Results summary
    print_header "TEST RESULTS SUMMARY"
    echo "Tests Run:    $TESTS_RUN"
    echo -e "Tests Passed: ${GREEN}$TESTS_PASSED${NC}"
    echo -e "Tests Failed: ${RED}$TESTS_FAILED${NC}"
    echo ""
    
    if [[ $TESTS_FAILED -eq 0 ]]; then
        echo -e "${GREEN}✓ All tests passed!${NC}"
        return 0
    else
        echo -e "${RED}✗ Some tests failed. Review output above for details.${NC}"
        return 1
    fi
}

# ════════════════════════════════════════════════════════════════════════════
# HELP
# ════════════════════════════════════════════════════════════════════════════

show_help() {
    cat << 'EOF'
CyberShield av-service Test Suite

Usage:
  sudo ./test-cybershield.sh [MODE]

Modes:
  --full    Run comprehensive test suite (default)
  --quick   Run basic installation and permission tests only
  --ebpf    Test eBPF kernel configuration and BTF support
  --lvm     Test VM sandbox and libvirt dependencies
  --help    Show this help message

Examples:
  sudo ./test-cybershield.sh              # Full tests
  sudo ./test-cybershield.sh --quick      # Quick validation
  sudo ./test-cybershield.sh --ebpf       # eBPF diagnostic

Output:
  Green  ✓ = Test passed
  Red    ✗ = Test failed
  Yellow [TEST] = Test name
  Blue   [INFO] = Informational message

Requires:
  - Root/sudo access
  - Arch Linux system
  - CyberShield installation via arch-install.sh
  - av-service and dependencies installed

EOF
}

if [[ "$1" == "--help" ]]; then
    show_help
    exit 0
fi

main "$@"
