#!/bin/bash
# Build iOS IPA (requires macOS + Xcode)

set -e

if [ "$(uname)" != "Darwin" ]; then
    echo "❌ iOS build requires macOS"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "🍎 Building iOS IPA..."

cd "$SCRIPT_DIR/../mobile/ios"

# Install pods
if [ ! -d "Pods" ]; then
    echo "📦 Installing CocoaPods..."
    pod install
fi

# Build for device
xcodebuild \
    -workspace CyberDefense.xcworkspace \
    -scheme CyberDefense \
    -configuration Release \
    -derivedDataPath build \
    -destination generic/platform=iOS \
    clean archive \
    -archivePath "CyberDefense.xcarchive"

# Export IPA
xcodebuild \
    -exportArchive \
    -archivePath "CyberDefense.xcarchive" \
    -exportOptionsPlist "ExportOptions.plist" \
    -exportPath "build/Export"

IPA_PATH="build/Export/CyberDefense.ipa"

if [ -f "$IPA_PATH" ]; then
    echo "✅ IPA built: $IPA_PATH"
    echo ""
    echo "Next steps:"
    echo "1. Notarize: xcrun notarytool submit $IPA_PATH --apple-id <email> --password <password>"
    echo "2. Submit to App Store Connect"
else
    echo "❌ Build failed"
    exit 1
fi
