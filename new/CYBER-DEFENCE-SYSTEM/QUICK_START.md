# CyberDefense Pro - Quick Start Guide

## One-Command Setup

```bash
# Clone repository
git clone https://github.com/cybershield/defense.git
cd defense

# Single command: setup + build + test all platforms
bash scripts/setup-all.sh && bash scripts/build-all.sh
```

## Individual Platform Quick Starts

### Android

```bash
# Build APK
bash scripts/build-android.sh

# Output: mobile/android/app/build/outputs/apk/release/app-release.apk

# Install on device
adb install app-release.apk

# Launch
adb shell am start -n com.cybershield.defense/.MainActivity
```

**Expected Flow:**
1. App starts → Requests permissions
2. Dashboard shows "Monitoring Active"
3. Open any file → Threats tab shows activity
4. Long-press file → "Scan File" option

### iOS

```bash
# Build IPA (macOS only)
bash scripts/build-ios.sh

# Output: mobile/ios/build/Export/CyberDefense.ipa

# Install via TestFlight
# 1. Upload IPA to App Store Connect
# 2. Add testers in TestFlight
# 3. Testers install from TestFlight app
```

### Windows

```bash
# Build Desktop App
bash scripts/build-desktop.sh

# Output: desktop/release/CyberDefense.exe

# Run
./desktop/release/CyberDefense.exe
```

**First Run:**
1. Windows Defender may prompt (expected)
2. Click "More info" → "Run anyway"
3. App launches to Dashboard
4. No setup needed (local-only)

### macOS

```bash
# Build DMG
bash scripts/build-desktop.sh

# Output: desktop/CyberDefense.dmg

# Mount and run
open CyberDefense.dmg
# Drag CyberDefense.app to Applications
```

**Security Note:** First run requires full disk access approval:
- System Settings → Privacy → Full Disk Access
- Add CyberDefense.app

### Linux

```bash
# Build Rust engine
bash scripts/build-linux.sh

# Output: desktop/native/linux/target/release/cyberdefense_linux_engine

# Run with file monitoring
CYBERSHIELD_SOCKET=/tmp/cybershield.sock \
    ./target/release/cyberdefense_linux_engine start \
    --dirs ~/Downloads ~/Documents

# In another terminal, connect to events
nc -U /tmp/cybershield.sock
```

## Testing

### Verify Installation

```bash
# Android
adb logcat | grep "CyberDefense"

# All platforms
bash scripts/test-all.sh
```

### Generate Test Threats

```bash
# Create random file (high entropy = suspicious)
dd if=/dev/urandom of=/tmp/test.bin bs=1M count=10

# App should detect it immediately
```

### Check Logs

```bash
# Android
adb logcat -s "CyberDefense"

# iOS (via Xcode console)
# Windows (Event Viewer → Windows Logs → Application)
# macOS (Console.app)
# Linux (journalctl -u cyberdefense)
```

## Common Tasks

### Stop Monitoring

**Android/iOS:**
```javascript
// JavaScript code
await CyberDefenseModule.stopMonitoring();
```

**Desktop:**
```bash
# Close app window
# Or: pkill -f cyberdefense_linux_engine
```

### View Threat History

**Mobile:**
- Open "Threats" tab
- Pull to refresh
- Tap threat for details

**Desktop (Electron):**
- Menu → View → Recent Threats
- Or: http://localhost:3000/threats

### Change Settings

**All Platforms:**
- Open Settings
- Toggle monitoring modules:
  - File Monitoring
  - Process Monitoring
  - Network Monitoring (mobile only)
- Adjust data retention (7-90 days)

### Export Threat Log

**Mobile:**
```javascript
const threats = await CyberDefenseModule.getRecentThreats(1000);
const json = JSON.stringify(threats, null, 2);
// Share via email/cloud storage
```

**Desktop:**
```bash
# SQLite database location
# Windows: %APPDATA%/CyberDefense/threats.db
# macOS: ~/Library/Application Support/CyberDefense/threats.db
# Linux: ~/.local/share/cybershield/threats.db
```

## Troubleshooting

### "Permission Denied" Errors

**Android:**
```bash
# Grant permissions via ADB
adb shell pm grant com.cybershield.defense android.permission.READ_EXTERNAL_STORAGE
```

**macOS:**
- System Settings → Privacy → Full Disk Access
- Add CyberDefense.app

### "No Threats Detected" (But Should Be)

1. Check if monitoring is active:
   - Dashboard should show 🟢 "Monitoring Active"
2. Create test threat:
   ```bash
   dd if=/dev/urandom of=/tmp/test.bin bs=1M count=50
   ```
3. Check permissions:
   - App needs read access to files being monitored
4. Restart app

### High CPU/Memory Usage

1. Close other apps
2. Disable Network Monitoring (if enabled)
3. Reduce monitoring frequency in Settings
4. Report if > 15% sustained CPU usage

### ML Models Not Loading

```bash
# Verify model files exist
ls -la mobile/android/app/src/main/assets/models/
ls -la desktop/assets/models/

# If missing, rebuild:
python3 ml-models/training/train_malware_classifier.py
```

## Architecture at a Glance

```
CyberDefense/
├── mobile/                     # iOS + Android source
│   ├── android/               # Kotlin native
│   ├── ios/                   # Swift native
│   └── src/                   # Shared React Native
├── desktop/                    # Desktop electron
│   ├── native/                # Platform-specific engines
│   │   ├── linux/            # Rust inotify engine
│   │   ├── windows/          # C# ETW engine
│   │   └── macos/            # Swift ES Framework
│   └── electron/              # Electron app
├── ml-models/                  # ML pipeline
│   ├── training/              # Training scripts
│   ├── yara-rules/            # Detection rules
│   └── datasets/              # Download scripts
├── scripts/                    # Build automation
├── tests/                      # Test suites
├── docs/                       # Documentation
└── README.md                   # This file
```

## Key Files

| File | Purpose |
|------|---------|
| `scripts/setup-all.sh` | Install all dependencies |
| `scripts/build-all.sh` | Build all platforms |
| `scripts/test-all.sh` | Run all tests |
| `mobile/react-native-app/package.json` | React Native config |
| `mobile/android/build.gradle` | Android config |
| `desktop/electron/main.js` | Desktop entry point |
| `desktop/native/linux/Cargo.toml` | Linux engine config |
| `ml-models/training/*.py` | ML training |
| `COMPLETE_DOCUMENTATION.md` | Full documentation |
| `DEPLOYMENT_GUIDE.md` | Publishing guide |

## Development Workflow

### Making Changes

```bash
# 1. Make code changes
vim mobile/src/screens/DashboardScreen.tsx

# 2. Rebuild affected platform
bash scripts/build-android.sh

# 3. Test
adb install -r app-release.apk

# 4. Commit
git add .
git commit -m "feat: update dashboard UI"
git push
```

### Adding New Features

1. **Create issue** with feature description
2. **Assign to self**
3. **Create branch**: `feature/feature-name`
4. **Implement** across all relevant platforms
5. **Test** on all platforms
6. **Create PR** with documentation
7. **Merge after review**

## Performance Targets

| Metric | Target |
|--------|--------|
| Memory (idle) | < 50 MB |
| CPU (monitoring) | < 5% |
| File detection latency | < 100ms |
| Threat DB query | < 50ms |
| Start time | < 2s |

## Security Notes

- ✅ All data is local-only (no cloud sync)
- ✅ AES-256 encryption for stored threats
- ✅ No telemetry collection
- ✅ Open source for audit
- ✅ Signed binaries (all platforms)

## Support

- **GitHub Issues**: Report bugs and request features
- **Discussions**: Community help and ideas
- **Email**: support@cybershield.dev
- **Security**: security@cybershield.dev (do not use public channels)

---

**Ready to build?** Run: `bash scripts/setup-all.sh && bash scripts/build-all.sh`

**Questions?** Check [COMPLETE_DOCUMENTATION.md](COMPLETE_DOCUMENTATION.md)
