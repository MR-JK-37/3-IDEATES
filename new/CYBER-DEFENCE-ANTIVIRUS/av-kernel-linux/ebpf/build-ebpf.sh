#!/bin/bash
# eBPF Build Script for CyberShield LSM File Monitor
# Compiles lsm_file_monitor.c to BPF bytecode
# Usage: ./build-ebpf.sh [--help] [--clean] [--vmlinux-header-path]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KERNEL_VERSION=$(uname -r)
KERNEL_CONFIG_DEFAULT="/boot/config-${KERNEL_VERSION}"
KERNEL_CONFIG="$KERNEL_CONFIG_DEFAULT"
VMLINUX_HEADER_PATH="./vmlinux.h"
OUT_DIR="$SCRIPT_DIR/out"
SOURCES=("lsm_file_monitor.c" "../src/monitor.bpf.c")

echo "════════════════════════════════════════════════════════════"
echo "eBPF LSM File Monitor Build Script"
echo "════════════════════════════════════════════════════════════"

# Parse arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --help)
                show_help
                exit 0
                ;;
            --clean)
                clean_build
                exit 0
                ;;
            --vmlinux-header)
                VMLINUX_HEADER_PATH="$2"
                shift 2
                ;;
            --kernel-config)
                KERNEL_CONFIG="$2"
                shift 2
                ;;
            --out-dir)
                OUT_DIR="$2"
                shift 2
                ;;
            --source)
                SOURCES=("$2")
                shift 2
                ;;
            *)
                echo "[!] Unknown argument: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

# Check prerequisites
check_prerequisites() {
    echo "[*] Checking prerequisites..."
    
    # Check clang
    if ! command -v clang &> /dev/null; then
        echo "[!] ERROR: clang not found. Install with: pacman -S clang"
        exit 1
    fi
    echo "[✓] clang found: $(clang --version | head -1)"
    
    # Check llc (LLVM compiler)
    if ! command -v llc &> /dev/null; then
        echo "[!] ERROR: llc not found. Install with: pacman -S llvm"
        exit 1
    fi
    echo "[✓] llc found"
    
    # Check bpftool (optional but useful)
    if ! command -v bpftool &> /dev/null; then
        echo "[!] WARNING: bpftool not found. Install with: pacman -S bpf"
        echo "    This tool is optional but useful for BPF debugging"
    else
        echo "[✓] bpftool found"
    fi
    
    # Check kernel config
    if [ ! -f "$KERNEL_CONFIG" ]; then
        echo "[!] ERROR: Kernel config not found at $KERNEL_CONFIG"
        echo "    Install linux-headers: pacman -S linux-headers"
        exit 1
    fi
    echo "[✓] Kernel config found"
    
    # Check BPF_LSM support
    if ! grep -q "CONFIG_BPF=y" "$KERNEL_CONFIG"; then
        echo "[!] ERROR: CONFIG_BPF=y not set in kernel"
        echo "    This kernel does not support eBPF"
        exit 1
    fi
    echo "[✓] CONFIG_BPF=y enabled"
    
    if ! grep -q "CONFIG_BPF_LSM=y" "$KERNEL_CONFIG"; then
        echo "[!] WARNING: CONFIG_BPF_LSM=y not set in kernel"
        echo "    eBPF LSM monitoring will not work"
        echo "    Use kernel: linux-zen or linux-hardened, or compile with CONFIG_BPF_LSM=y"
        echo ""
        read -p "Continue anyway? (y/n) " -n 1 -r
        echo ""
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    else
        echo "[✓] CONFIG_BPF_LSM=y enabled"
    fi
    
    # Check btf (BPF Type Format) support
    if ! grep -q "CONFIG_DEBUG_INFO_BTF=y" "$KERNEL_CONFIG"; then
        echo "[!] WARNING: CONFIG_DEBUG_INFO_BTF not enabled"
        echo "    This is needed for LSM programs"
    else
        echo "[✓] CONFIG_DEBUG_INFO_BTF enabled"
    fi
}

# Generate vmlinux.h if needed
generate_vmlinux_header() {
    if [ ! -f "$VMLINUX_HEADER_PATH" ]; then
        echo "[*] vmlinux.h not found, attempting to generate..."
        
        if ! command -v bpftool &> /dev/null; then
            echo "[!] ERROR: bpftool not found (needed to generate vmlinux.h)"
            echo "    Install with: pacman -S bpf"
            echo "    Or: sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h"
            exit 1
        fi
        
        echo "[*] Generating vmlinux.h from kernel BTF..."
        sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > "$VMLINUX_HEADER_PATH"
        
        if [ ! -f "$VMLINUX_HEADER_PATH" ]; then
            echo "[!] ERROR: Failed to generate vmlinux.h"
            exit 1
        fi
        
        echo "[✓] Generated vmlinux.h ($(wc -l < $VMLINUX_HEADER_PATH) lines)"
    else
        echo "[✓] Using existing vmlinux.h"
    fi
}

# Compile BPF program
compile_single_bpf() {
    local source="$1"
    local output="$2"
    
    if [ ! -f "$source" ]; then
        echo "[!] ERROR: Source file $source not found"
        exit 1
    fi
    
    echo "[*] Compiling $source to BPF bytecode..."
    
    mkdir -p "$(dirname "$output")"
    clang -O2 -target bpf \
        -D__KERNEL__ -D__BPF_TRACING__ \
        -I/usr/include/linux \
        -I"$(dirname $VMLINUX_HEADER_PATH)" \
        -c "$source" -o "$output" 2>&1 || {
        echo "[!] ERROR: Compilation failed"
        exit 1
    }
    
    if [ ! -f "$output" ]; then
        echo "[!] ERROR: BPF object file not created"
        exit 1
    fi
    
    local size=$(stat -f%z "$output" 2>/dev/null || stat -c%s "$output" 2>/dev/null || echo "0")
    echo "[✓] Compiled successfully: $output ($size bytes)"
}

compile_bpf() {
    echo "[*] Output directory: $OUT_DIR"
    for source in "${SOURCES[@]}"; do
        local source_path
        source_path="$SCRIPT_DIR/$source"
        local output_name
        output_name="$(basename "${source%.*}").o"
        local output_path="$OUT_DIR/$output_name"
        compile_single_bpf "$source_path" "$output_path"
    done
}

# Verify compiled BPF programs
verify_single_bpf() {
    local output="$1"
    
    echo "[*] Verifying BPF object file..."
    
    # Check file type
    if ! file "$output" | grep -q "ELF\|executable"; then
        echo "[!] ERROR: Output is not an ELF object file"
        exit 1
    fi
    echo "[✓] Valid ELF object file"
    
    # Check BPF sections (if bpftool available)
    if command -v bpftool &> /dev/null; then
        echo "[*] BPF sections:"
        bpftool prog load "$output" type lsm > /dev/null 2>&1 || {
            echo "[!] WARNING: bpftool could not load program (may still be valid)"
        }
    fi
    
    # List ELF sections
    if command -v llvm-objdump &> /dev/null; then
        echo "[*] ELF sections:"
        llvm-objdump -h "$output" | grep -E '^\s+[0-9]+ '
    fi
    
    echo "[✓] Verification complete"
}

verify_bpf() {
    for source in "${SOURCES[@]}"; do
        local output_name
        output_name="$(basename "${source%.*}").o"
        verify_single_bpf "$OUT_DIR/$output_name"
    done
}

# Clean build artifacts
clean_build() {
    echo "[*] Cleaning build artifacts..."
    rm -rf "$OUT_DIR"
    echo "[✓] Cleaned"
}

# Show help
show_help() {
    cat << 'EOF'
eBPF LSM File Monitor Build Script

Usage: ./build-ebpf.sh [OPTIONS]

Options:
    --help              Show this help message
    --clean             Remove build artifacts
    --vmlinux-header    Path to vmlinux.h (default: ./vmlinux.h)
    --out-dir           Output directory for *.o files (default: ./out)
    --source            Compile only a single source path (relative to this script)
    --kernel-config     Path to kernel config (default: /boot/config-$(uname -r))

Examples:
    ./build-ebpf.sh                    # Standard build
    ./build-ebpf.sh --clean             # Remove artifacts
    ./build-ebpf.sh --kernel-config /boot/config-custom
    
Build Process:
    1. Check clang, llvm, linux-headers installed
    2. Verify kernel config (CONFIG_BPF_LSM=y required)
    3. Generate vmlinux.h from kernel BTF (if needed)
    4. Compile configured eBPF sources to BPF bytecode
    5. Verify output ELF object file
    
Output:
    out/*.o - BPF object files (loadable by av-service / eBPF loader)
    
Installation:
    sudo install -Dm644 out/*.o /opt/cybershield/lib/
    
Loading:
    The BPF program is loaded by av-service when:
    [ebpf]
    enabled = true
    object_path = "/opt/cybershield/lib/lsm_file_monitor.o"
    
Troubleshooting:
    - If CONFIG_BPF_LSM=y is not available:
      Use kernel: pacman -S linux-zen (or linux-hardened from AUR)
    
    - If vmlinux.h generation fails:
      Manual: sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
    
    - For debugging:
      sudo bpftool prog list
      sudo bpftool prog show
      sudo bpftool map dump name file_events
      
EOF
}

# Main build flow
main() {
    parse_args "$@"
    check_prerequisites
    generate_vmlinux_header
    compile_bpf
    verify_bpf
    
    cat << EOF

════════════════════════════════════════════════════════════
Build Complete!

Output: lsm_file_monitor.o ($(stat -f%z lsm_file_monitor.o 2>/dev/null || stat -c%s lsm_file_monitor.o) bytes)
Output dir: $OUT_DIR
Compiled objects:
$(ls -1 "$OUT_DIR"/*.o 2>/dev/null | sed 's/^/  - /')

To install:
    sudo install -Dm644 $OUT_DIR/*.o /opt/cybershield/lib/

To enable in av-service:
    sudo nano /etc/cybershield/config.toml
    # In [ebpf] section: enabled = true

To verify loaded programs:
    sudo bpftool prog list

To view ring buffer events:
    sudo bpftool map dump name file_events
    
════════════════════════════════════════════════════════════
EOF
}

main "$@"
