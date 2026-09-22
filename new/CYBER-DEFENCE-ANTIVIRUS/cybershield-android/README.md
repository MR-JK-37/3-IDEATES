# CyberShield Android - Mobile Antivirus Client

Complete Android application for CyberShield antivirus system with real-time scanning, VirusTotal integration, and threat detection.

## Features

- Real-time file and APK scanning
- URL scanning with VirusTotal
- Background service for continuous protection
- Native YARA rule support via JNI
- SQLite threat database caching
- Material Design 3 UI
- Push notifications for threats
- Quarantine management
- Detailed threat reports

## Architecture

### Technologies
- **Language:** Kotlin
- **Min SDK:** 26+ (Android 8.0+)
- **Target SDK:** 35+ (Android 15)
- **Architecture:** MVVM with Jetpack components
- **JNI:** C/C++ for YARA rules
- **Storage:** SAF + Scoped Storage

### Components
```
app/
├── java/com/cybershield/android/
│   ├── ui/                          # UI Components
│   │   ├── MainActivity
│   │   ├── ScannerFragment
│   │   ├── URLScannerFragment
│   │   ├── ThreatLogFragment
│   │   └── SettingsFragment
│   ├── service/                     # Services
│   │   ├── ScannerService           # Background scanning
│   │   └── NotificationService      # Push notifications
│   ├── viewmodel/                   # MVVM ViewModels
│   │   ├── ScannerViewModel
│   │   └── ThreatLogViewModel
│   ├── repository/                  # Data layer
│   │   ├── FileRepository
│   │   ├── ThreatRepository
│   │   └── VirusTotalRepository
│   ├── database/                    # SQLite
│   │   ├── ThreatDatabase
│   │   └── ThreatDao
│   └── util/                        # Utilities
│       ├── YaraEngine
│       └── ClamAVHelper
├── jni/                             # Native code
│   └── yara_bridge.cpp
└── res/
    ├── layout/                      # UI layouts
    ├── drawable/                    # Assets
    └── values/                      # Resources
```

## Building

### Prerequisites
- Android Studio Hedgehog+
- NDK r25 or later
- YARA development headers
- ClamAV support libraries (optional)

### Build Commands

```bash
# Debug build
./gradlew assembleDebug

# Release build (requires keystore)
./gradlew assembleRelease -Pkey.alias=cybershield \
  -Pkey.password=... \
  -Pstore.password=...

# Build with YARA support
./gradlew assembleDebug -Pinclude_yara=true

# Run tests
./gradlew test connectedAndroidTest
```

## Manifest Permissions

```xml
<!-- File access -->
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE" />
<uses-permission android:name="android.permission.MANAGE_EXTERNAL_STORAGE" />

<!-- Network -->
<uses-permission android:name="android.permission.INTERNET" />

<!-- Notifications -->
<uses-permission android:name="android.permission.POST_NOTIFICATIONS" />

<!-- Background execution -->
<uses-permission android:name="android.permission.FOREGROUND_SERVICE" />
```

## API Integration

### VirusTotal API
- SHA256 hash lookup only (privacy-preserving)
- Rate limiting: 4 requests/minute
- Cache hits for known files

### Threat Database
- Local SQLite cache
- Background updates
- Pattern matching

## Installation

See main [INSTALLATION.md](../INSTALLATION.md#android) for detailed setup.

## Testing

- Unit tests for all repositories
- Integration tests with mock VirusTotal API
- UI tests for scanning workflows
- Performance benchmarks for large directory scans

## Security Considerations

1. **Privacy:** Never upload full files to VirusTotal
2. **Storage:** Quarantine via SAF with restricted permissions
3. **Process:** Scanning runs in background service (separate from UI)
4. **Updates:** Threat definitions update hourly

## License

MIT License - See [LICENSE](../LICENSE)
