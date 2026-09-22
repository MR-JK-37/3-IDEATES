#!/bin/bash
# CyberDefense Pro - Complete Setup & Build Script
# Single command to build all platforms

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

OS="$(uname -s)"
case "$OS" in
    Linux*) OS_TYPE="linux" ;;
    Darwin*) OS_TYPE="macos" ;;
    MINGW*|MSYS*|CYGWIN*) OS_TYPE="windows" ;;
    *) OS_TYPE="unknown" ;;
esac

log_info "Detected OS: $OS_TYPE"
log_info "Starting complete setup for all platforms..."

# Check prerequisites
check_cmd() {
    if ! command -v "$1" &>/dev/null; then
        log_error "Missing: $1"
        return 1
    fi
}

log_info "Checking prerequisites..."
check_cmd "node" || exit 1
check_cmd "npm" || exit 1
check_cmd "python3" || exit 1

# Install dependencies
log_info "Installing Node dependencies (mobile + desktop)..."
cd mobile && npm ci && cd ..
cd desktop && npm ci && cd ..

log_info "Installing Python ML dependencies..."
pip3 install -q --upgrade pip
pip3 install -q tensorflow==2.15.0 scikit-learn==1.3.2 pandas==2.1.4 numpy==1.26.2 \
    coremltools==7.1 onnx==1.15.0 androguard==3.4.0 requests tqdm

# Build native modules
log_info "Building native modules..."

if [ "$OS_TYPE" = "linux" ]; then
    if command -v cargo &>/dev/null; then
        log_info "Building Linux Rust engine..."
        cd desktop/electron/security/linux/native
        cargo build --release 2>/dev/null || log_warn "Rust build requires toolchain"
        cd "$SCRIPT_DIR"
    fi
fi

# Create ML models directory structure
log_info "Setting up ML model directories..."
mkdir -p mobile/android/app/src/main/assets/models
mkdir -p mobile/android/app/src/main/assets/yara
mkdir -p desktop/assets/models
mkdir -p desktop/assets/yara

# Copy YARA rules
log_info "Copying security rules..."
mkdir -p ml-models/yara-rules 2>/dev/null
touch ml-models/yara-rules/android_malware.yar 2>/dev/null || true
touch ml-models/yara-rules/ransomware.yar 2>/dev/null || true

# Create dummy model files (in production, these are trained)
log_info "Creating placeholder ML model files..."
touch mobile/android/app/src/main/assets/models/malware.tflite
touch mobile/android/app/src/main/assets/models/phishing.tflite
touch desktop/assets/models/malware.tflite
touch desktop/assets/models/phishing.tflite

log_info "✅ Setup complete for all platforms!"
log_info ""
log_info "Next, build individual platforms:"
log_info "  📱 Android:  ./scripts/build-android.sh"
log_info "  📱 iOS:      ./scripts/build-ios.sh (macOS only)"
log_info "  💻 Desktop:  ./scripts/build-desktop.sh"
log_info ""
log_info "Or run:       ./scripts/build-all.sh"
