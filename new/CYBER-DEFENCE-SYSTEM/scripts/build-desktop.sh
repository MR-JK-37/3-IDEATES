#!/bin/bash
# Build Desktop Electron App

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "💻 Building Desktop Electron App..."

cd "$SCRIPT_DIR/../desktop"

# Check if node_modules exists
if [ ! -d "node_modules" ]; then
    echo "📦 Installing dependencies..."
    npm ci
fi

# Build
npm run build

# Package native modules
if [ -d "../native/linux" ]; then
    echo "🔨 Building Linux native module..."
    cd ../native/linux
    cargo build --release 2>/dev/null || echo "⚠️  Rust build skipped"
    cd "$SCRIPT_DIR/../desktop"
fi

# Package for distribution
case "$(uname)" in
    Linux)
        echo "📦 Building for Linux..."
        npm run build:linux || echo "⚠️  Linux build skipped"
        ;;
    Darwin)
        echo "📦 Building for macOS..."
        npm run build:macos || echo "⚠️  macOS build skipped"
        ;;
    MINGW*|MSYS*|CYGWIN*)
        echo "📦 Building for Windows..."
        npm run build:win || echo "⚠️  Windows build skipped"
        ;;
esac

echo "✅ Build complete!"
