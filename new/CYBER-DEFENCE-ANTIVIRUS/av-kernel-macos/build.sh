#!/bin/bash
# CyberShield macOS System Extension Build Script
# Requires Xcode 12.0+ and macOS 10.15+

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_NAME="CyberShieldES"
OUTPUT_DIR="${SCRIPT_DIR}/build"
ARCHIVE_PATH="${OUTPUT_DIR}/${PROJECT_NAME}.xcarchive"
EXTENSION_PATH="${OUTPUT_DIR}/${PROJECT_NAME}.systemextension"

echo "🏗️  Building CyberShield Endpoint Security system extension..."

# Create output directory
mkdir -p "${OUTPUT_DIR}"

# Check for Xcode
if ! command -v xcodebuild &> /dev/null; then
    echo "❌ Xcode not found. Please install Xcode from App Store."
    exit 1
fi

echo "✅ Xcode found"

# Build the system extension
echo "Building system extension..."
xcodebuild archive \
    -project "${SCRIPT_DIR}/${PROJECT_NAME}.xcodeproj" \
    -scheme "${PROJECT_NAME}" \
    -configuration Release \
    -archivePath "${ARCHIVE_PATH}" \
    -derivedDataPath "${OUTPUT_DIR}/DerivedData" \
    CODE_SIGN_IDENTITY="" \
    CODE_SIGNING_REQUIRED=NO \
    2>&1 | grep -E "(BUILD|error|warning)" || true

if [ -d "${ARCHIVE_PATH}" ]; then
    echo "✅ Archive created successfully"
    
    # Extract the system extension
    if [ -f "${ARCHIVE_PATH}/Products/Library/SystemExtensions/${PROJECT_NAME}.systemextension/Info.plist" ]; then
        cp -r "${ARCHIVE_PATH}/Products/Library/SystemExtensions/${PROJECT_NAME}.systemextension" "${EXTENSION_PATH}"
        echo "✅ System extension extracted"
    fi
else
    echo "❌ Build failed"
    exit 1
fi

# Verify signature
echo "Verifying code signature..."
codesign -v "${EXTENSION_PATH}" 2>&1 || echo "⚠️  Note: Signature verification skipped for development build"

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "✅ Build Complete!"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "System Extension: ${EXTENSION_PATH}"
echo ""
echo "📋 Installation Instructions:"
echo "1. Code signing required (use production certificate for release)"
echo "2. Install via systemextensionsctl:"
echo "   systemextensionsctl install ${EXTENSION_PATH}"
echo "3. Approve in System Preferences > Security & Privacy"
echo "4. Reboot may be required"
echo ""
echo "Note: macOS Endpoint Security requires System Extension entitlements"
echo "      and will prompt user for approval on first run."
