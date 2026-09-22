# 🚀 CyberDefense Mobile - Setup Guide

## Prerequisites

- **Node.js** >= 18.0.0
- **React Native CLI**: `npm install -g react-native-cli`
- **Android Studio** (for Android development)
- **Java Development Kit (JDK)** 11 or higher
- **Android SDK** (API Level 23+)

## Installation Steps

### 1. Install Dependencies

```bash
npm install
```

### 2. Android Setup

#### Install Android Dependencies

1. Open Android Studio
2. Install Android SDK Platform 33
3. Install Android SDK Build-Tools 33.0.0
4. Install Android Emulator (optional, for testing)

#### Configure Android Environment

Add to your `~/.bashrc` or `~/.zshrc`:

```bash
export ANDROID_HOME=$HOME/Android/Sdk
export PATH=$PATH:$ANDROID_HOME/emulator
export PATH=$PATH:$ANDROID_HOME/platform-tools
export PATH=$PATH:$ANDROID_HOME/tools
export PATH=$PATH:$ANDROID_HOME/tools/bin
```

### 3. Link Native Modules

The native modules are already configured. To rebuild:

```bash
cd android
./gradlew clean
cd ..
```

### 4. Run the Application

#### On Android Device/Emulator

```bash
npm run android
```

#### On iOS (macOS only)

```bash
cd ios && pod install && cd ..
npm run ios
```

## Project Structure

```
3-IDEATES/
├── src/
│   ├── ui/              # React Native UI components
│   │   └── screens/     # Screen components
│   ├── engine/          # Security detection engines
│   ├── database/        # Encrypted database layer
│   ├── store/           # Redux store and slices
│   ├── services/        # Service layer
│   ├── utils/           # Utility functions
│   └── types/           # TypeScript type definitions
├── native/
│   └── android/         # Native Android modules
│       └── src/main/java/com/cyberdefense/
│           ├── ProcessMonitorModule.kt
│           ├── FileMonitorModule.kt
│           └── NetworkMonitorModule.kt
└── App.tsx              # Main application component
```

## Native Module Integration

### Process Monitor Module

Provides access to Android `ActivityManager` for process enumeration.

**Usage:**
```typescript
import {NativeModules} from 'react-native';
const {ProcessMonitorModule} = NativeModules;

const processes = await ProcessMonitorModule.getRunningProcesses();
```

### File Monitor Module

Monitors file system events using Android `FileObserver`.

**Usage:**
```typescript
import {NativeModules} from 'react-native';
const {FileMonitorModule} = NativeModules;

await FileMonitorModule.startWatching('/sdcard/Download');
```

### Network Monitor Module

Intercepts network traffic using Android `VpnService`.

**Usage:**
```typescript
import {NativeModules} from 'react-native';
const {NetworkMonitorModule} = NativeModules;

await NetworkMonitorModule.startVpnService();
```

## Permissions

The app requires the following Android permissions:

- `INTERNET` - Network access
- `ACCESS_NETWORK_STATE` - Network state monitoring
- `QUERY_ALL_PACKAGES` - Process enumeration
- `GET_TASKS` - Task monitoring
- `FOREGROUND_SERVICE` - Background monitoring
- `BIND_VPN_SERVICE` - Network traffic interception
- `READ_EXTERNAL_STORAGE` - File monitoring
- `WRITE_EXTERNAL_STORAGE` - File operations

## Development

### Type Checking

```bash
npm run type-check
```

### Linting

```bash
npm run lint
```

### Testing

```bash
npm test
```

## Building for Production

### Android APK

```bash
cd android
./gradlew assembleRelease
```

The APK will be located at:
`android/app/build/outputs/apk/release/app-release.apk`

### Android AAB (for Play Store)

```bash
cd android
./gradlew bundleRelease
```

## Troubleshooting

### Metro Bundler Issues

```bash
npm start -- --reset-cache
```

### Android Build Issues

```bash
cd android
./gradlew clean
./gradlew build
```

### Native Module Not Found

1. Ensure native modules are properly linked
2. Rebuild the app: `npm run android`
3. Clear cache: `npm start -- --reset-cache`

### VPN Permission Issues

The app requires VPN permission. On first launch, Android will prompt the user to grant VPN access.

## Security Considerations

- All processing happens on-device (no cloud uploads)
- Database is encrypted with AES-256
- No telemetry or analytics
- All threat data is stored locally

## Next Steps

1. **Train ML Models**: Add TensorFlow Lite models for phishing detection
2. **Implement Sandbox**: Complete malware sandbox implementation
3. **Add LLM Integration**: Integrate Gemini Nano for threat explanations
4. **Performance Optimization**: Optimize battery and memory usage
5. **Testing**: Test with real malware samples in isolated environment

## Support

For issues or questions, please refer to the main README.md file.
