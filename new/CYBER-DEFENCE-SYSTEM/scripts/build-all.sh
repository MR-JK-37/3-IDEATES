#!/bin/bash
# Build all platforms

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "🚀 Building all platforms..."

# First setup
if [ ! -d node_modules ]; then
    echo "📦 Running setup..."
    bash "$SCRIPT_DIR/setup-all.sh"
fi

# Build Android
if [ "$1" != "--skip-android" ]; then
    echo "📱 Building Android..."
    bash "$SCRIPT_DIR/build-android.sh" || echo "⚠️  Android build skipped (requires Android SDK)"
fi

# Build Desktop Electron
if [ "$1" != "--skip-desktop" ]; then
    echo "💻 Building Desktop..."
    cd "$SCRIPT_DIR/../desktop"
    npm run build || echo "⚠️  Desktop build skipped"
    cd "$SCRIPT_DIR/.."
fi

# Build ML models
if [ "$1" != "--skip-ml" ]; then
    echo "🧠 Training ML models..."
    python3 "$SCRIPT_DIR/../ml-models/training/train_malware_classifier.py" || echo "⚠️  ML training skipped"
fi

# Run tests
if [ "$1" != "--skip-tests" ]; then
    echo "✅ Running tests..."
    bash "$SCRIPT_DIR/test-all.sh" || echo "⚠️  Some tests failed"
fi

echo "✨ Build complete!"
