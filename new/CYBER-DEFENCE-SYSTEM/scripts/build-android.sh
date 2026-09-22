#!/bin/bash
# Build Android APK

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/../mobile/android"

echo "🔨 Building Android APK..."

# Check for Android SDK
if [ -z "$ANDROID_HOME" ]; then
    echo "❌ ANDROID_HOME not set. Install Android SDK."
    exit 1
fi

# Verify tools
if [ ! -f "$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager" ] && [ ! -f "$ANDROID_HOME/tools/bin/sdkmanager" ]; then
    echo "❌ Android SDK tools not found."
    exit 1
fi

# Build
./gradlew clean assembleRelease

BUILD_OUTPUT="app/build/outputs/apk/release/app-release-unsigned.apk"

if [ -f "$BUILD_OUTPUT" ]; then
    echo "✅ APK built: $BUILD_OUTPUT"
    echo "To sign and align: jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore keystore.jks $BUILD_OUTPUT alias_name && zipalign -v 4 $BUILD_OUTPUT app-release.apk"
else
    echo "❌ Build failed"
    exit 1
fi
