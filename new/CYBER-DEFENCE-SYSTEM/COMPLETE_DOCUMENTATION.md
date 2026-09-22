# CyberDefense Pro - Complete Documentation

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Building](#building)
3. [Platform-Specific Guides](#platform-specific-guides)
4. [API Reference](#api-reference)
5. [Testing](#testing)
6. [Deployment](#deployment)
7. [Troubleshooting](#troubleshooting)

## Architecture Overview

### System Design

```
┌─────────────────────────────────────────────────────┐
│          User Interface Layer                       │
│  (React Native / Electron)                          │
└─────────────────┬───────────────────────────────────┘
                  │
        ┌─────────┼─────────┐
        ▼         ▼         ▼
   ┌────────┐ ┌────────┐ ┌────────┐
   │Android │ │  iOS   │ │Desktop │
   │ Native │ │ Native │ │ Native │
   └────────┘ └────────┘ └────────┘
        │         │         │
        └─────────┼─────────┘
                  ▼
     ┌────────────────────────────┐
     │   Local Databases          │
     │  (Room/CoreData/SQLite)    │
     └────────────────────────────┘
```

### Key Components

**Mobile (React Native)**
- Shared UI layer for iOS/Android
- React Navigation for screen management
- Redux for state management
- Native bridge modules for platform-specific features

**Android Security Engine (Kotlin)**
- `ThreatDetectionEngine`: Process/file/network analysis
- `FileMonitorService`: FileObserver-based file monitoring
- `TelemetryService`: Continuous process monitoring
- Room database for local threat storage

**iOS Security Engine (Swift)**
- Endpoint Security Framework (macOS/iOS 15+)
- Code signature verification
- Network Extension for traffic monitoring
- CoreData for local persistence

**Windows Security Engine (C#)**
- FileSystemWatcher for file monitoring
- ETW (Event Tracing for Windows) for process tracking
- WMI for system event monitoring
- Windows Defender API integration

**macOS Security Engine (Swift)**
- Endpoint Security Framework
- Code signature verification + notarization checks
- Process injection detection
- Kernel extension monitoring

**Linux Security Engine (Rust)**
- inotify-based file monitoring
- Unix socket IPC for event streaming
- Entropy-based ransomware detection
- Real-time JSON event streaming

**Machine Learning Pipeline**
- Malware classifier (TensorFlow)
- Multi-format model conversion (TFLite/CoreML/ONNX)
- Embedded models (no cloud calls)
- Quantized LLM for threat explanations

## Building

### Prerequisites

```bash
# Common
- Node.js 18+
- Python 3.9+
- Git

# Android
- Android SDK 30+
- Android NDK r23+
- JDK 11+

# iOS
- Xcode 14+
- CocoaPods

# Windows
- Visual Studio 2019+
- .NET 6/7

# macOS
- Xcode 14+

# Linux
- Rust 1.70+
- gcc
```

### One-Command Setup

```bash
# Install all dependencies and build native modules
bash scripts/setup-all.sh

# Build all platforms
bash scripts/build-all.sh

# Or build individually
bash scripts/build-android.sh      # Android APK
bash scripts/build-ios.sh          # iOS IPA (macOS only)
bash scripts/build-desktop.sh      # Electron app
bash scripts/build-linux.sh        # Linux binary
```

### Manual Setup

```bash
# 1. Install Node dependencies
cd mobile && npm ci && cd ..
cd desktop && npm ci && cd ..

# 2. Install Python ML dependencies
pip install tensorflow==2.15.0 scikit-learn pandas numpy \
    coremltools onnx androguard

# 3. Build native modules
cd desktop/native/linux && cargo build --release

# 4. Train ML models
python3 ml-models/training/train_malware_classifier.py

# 5. Run tests
bash scripts/test-all.sh
```

## Platform-Specific Guides

### Android

**Build APK:**
```bash
cd mobile/android
./gradlew assembleRelease
# Output: app/build/outputs/apk/release/app-release.apk
```

**Key Features:**
- File modification monitoring (FileObserver)
- Process analysis with /proc parsing
- Entropy-based ransomware detection
- Room database for threat history

**Permissions:**
- `READ_EXTERNAL_STORAGE` - File scanning
- `INTERNET` - Telemetry (optional)
- `QUERY_ALL_PACKAGES` - App analysis
- `RECEIVE_BOOT_COMPLETED` - Auto-start

### iOS

**Build IPA:**
```bash
cd mobile/ios
xcodebuild -scheme CyberDefense -configuration Release \
    -derivedDataPath build archive -archivePath CyberDefense.xcarchive
```

**Key Features:**
- Endpoint Security Framework (iOS 15+)
- Code signature verification
- Keychain access monitoring
- Network Extension for traffic analysis

**Entitlements Required:**
- `com.apple.security.endpoint-security`
- `com.apple.security.network`
- `com.apple.private.security.no-sandbox`

### Windows

**Build MSI Installer:**
```bash
cd desktop/native/windows
dotnet build -c Release
# Creates: bin/Release/CyberDefense.exe
```

**Key Features:**
- FileSystemWatcher monitoring
- ETW for process tracking
- Windows Defender API integration
- Digital signature verification

### macOS

**Build DMG:**
```bash
cd desktop/native/macos
xcodebuild -scheme CyberDefense -configuration Release \
    -derivedDataPath build
# Codesign and notarize before distribution
```

**Key Features:**
- Endpoint Security Framework
- Code signature + notarization verification
- Process injection detection
- Kernel extension monitoring

### Linux

**Build Binary:**
```bash
cd desktop/native/linux
cargo build --release
# Output: target/release/cyberdefense_linux_engine
```

**Key Features:**
- inotify-based file monitoring
- Unix socket event streaming
- Entropy detection
- Real-time JSON events

**Run:**
```bash
CYBERSHIELD_SOCKET=/tmp/cybershield.sock \
    ./target/release/cyberdefense_linux_engine start --dirs ~/Documents ~/Downloads
```

## API Reference

### React Native Modules

All platforms expose these methods via `NativeBridgeModule`:

```typescript
// Start continuous monitoring
CyberDefenseModule.startMonitoring(): Promise<{status: 'monitoring'}>

// Stop monitoring
CyberDefenseModule.stopMonitoring(): Promise<{status: 'stopped'}>

// Fetch recent threats (last N)
CyberDefenseModule.getRecentThreats(limit: number): Promise<Threat[]>

// Scan individual file
CyberDefenseModule.scanFile(path: string): Promise<{
    score: number,      // 0.0-1.0
    reasons: string[]
}>

// Get monitoring status
CyberDefenseModule.getSystemStatus(): Promise<{
    isMonitoring: boolean,
    lastScanTime: number,
    osVersion: string
}>
```

### Threat Object

```typescript
interface Threat {
    id: string;
    timestamp: Date;
    type: 'process' | 'file' | 'network' | 'system';
    severity: 'low' | 'medium' | 'high' | 'critical';
    source: string;        // Process/app name
    details: string;       // Human-readable description
    mitigated?: boolean;
}
```

### Desktop Electron API

```javascript
// window.cybershield (available via preload.js)
window.cybershield.getThreats()    // Get recent threats
window.cybershield.scanFile(path)  // Scan individual file
```

## Testing

### Run All Tests

```bash
bash scripts/test-all.sh
```

### Unit Tests

**Android:**
```bash
cd mobile/android
./gradlew test
```

**Python/ML:**
```bash
python3 ml/runner.py --test
python3 -m pytest ml/tests/
```

### Integration Tests

**Test Entropy Detection:**
```python
import sys
sys.path.insert(0, 'ml')
from runner import calculate_entropy

test_data = bytes.fromhex('0123456789abcdef' * 100)
entropy = calculate_entropy(test_data)
assert entropy > 4.0  # Random data has high entropy
```

**Test File Monitoring:**
```bash
# Create test directory
mkdir -p /tmp/cybershield-test

# Start Linux engine
CYBERSHIELD_SOCKET=/tmp/test.sock \
    ./desktop/native/linux/target/release/cyberdefense_linux_engine start \
    --dirs /tmp/cybershield-test &

# Create test file
echo "test" > /tmp/cybershield-test/testfile.txt

# Check socket events
nc -U /tmp/test.sock
```

### E2E Tests

Test complete threat detection pipeline:

```bash
# 1. Start monitoring
curl -X POST http://localhost:3000/api/monitoring/start

# 2. Create suspicious file
dd if=/dev/urandom of=/tmp/suspicious.bin bs=1M count=50

# 3. Check detection
curl http://localhost:3000/api/threats?limit=10

# 4. Verify threat created
# Should see threat with "Mass file write" or "High entropy"
```

## Deployment

### Android (Google Play)

1. Build signed APK:
```bash
cd mobile/android
./gradlew bundleRelease  # For Play Console
```

2. Upload to Google Play Console with privacy policy + permissions justification

### iOS (App Store)

1. Build and archive:
```bash
cd mobile/ios
xcodebuild archive -scheme CyberDefense
```

2. Notarize (required for distribution)
3. Submit to App Store with privacy policy

### Desktop (Windows/macOS/Linux)

**Windows:**
```bash
# Create MSI installer using WiX
# Requires code signing certificate
```

**macOS:**
```bash
# Code sign
codesign -s - desktop/native/macos/build

# Notarize for distribution
xcrun notarytool submit CyberDefense.dmg \
    --apple-id <id> \
    --password <password> \
    --team-id <team-id>
```

**Linux:**
```bash
# Create deb package
dpkg -b cybershield-linux cybershield_1.0_amd64.deb

# Create rpm package (requires FPM)
fpm -s dir -t rpm -n cybershield -v 1.0 \
    --after-install scripts/post-install.sh \
    usr/local/bin/cyberdefense_linux_engine=/path/to/binary
```

## Troubleshooting

### Android

**Issue: "Permission denied" errors**
- Solution: Grant MANAGE_EXTERNAL_STORAGE at runtime
```kotlin
ActivityCompat.requestPermissions(this, 
    arrayOf(Manifest.permission.MANAGE_EXTERNAL_STORAGE), 
    PERMISSION_REQUEST_CODE)
```

**Issue: Service killed by system**
- Solution: Use `startForegroundService()` and post notification
```kotlin
startForegroundService(Intent(this, TelemetryService::class.java))
```

### iOS

**Issue: Endpoint Security not working**
- Requires full disk access + entitlements
- System Settings → Security & Privacy → Full Disk Access

**Issue: Code signature errors**
```bash
codesign -v --deep CyberDefense.app
```

### Windows

**Issue: ETW session permission denied**
- Run as Administrator
- Or grant SeSystemProfilePrivilege

### macOS

**Issue: "CyberDefense not verified"**
- Solution: Notarize and staple:
```bash
xcrun stapler staple CyberDefense.dmg
```

**Issue: Endpoint Security client creation failed**
- Ensure: entitlement_key present + full disk access granted

### Linux

**Issue: inotify watch limit exceeded**
```bash
# Increase limit
echo 'fs.inotify.max_user_watches=524288' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

**Issue: Socket permission denied**
```bash
# Ensure socket directory has proper permissions
mkdir -p /tmp/cybershield
chmod 700 /tmp/cybershield
```

## Security Considerations

1. **Data Privacy**
   - All data stored locally (no cloud transmission)
   - Encrypted with AES-256 (key derived from device key)
   - 30-day auto-cleanup of events

2. **Code Integrity**
   - All binaries signed (Windows/macOS)
   - Code notarized (macOS)
   - Source code open for audit

3. **Permissions**
   - Request minimum necessary permissions
   - Explain each permission in app
   - Allow granular enable/disable

4. **ML Models**
   - Embedded in app bundle (no external fetches)
   - Quantized to reduce size
   - Explain threat reasons to user

## Support

- GitHub Issues: github.com/cybershield/issues
- Documentation: docs/ folder
- Email: support@cybershield.dev

---

**Version:** 1.0.0  
**Last Updated:** 2024  
**License:** MIT
