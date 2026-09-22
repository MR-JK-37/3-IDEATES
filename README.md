# 🛡️ CyberDefense Mobile - Real-Time Cyber Defense Application

A production-grade mobile application for real-time cyber threat detection and protection.

## 🎯 Features

### ✅ Implemented

- **Real-Time Process Monitoring**: Detect hidden processes, rootkits, and suspicious behavior
  - Native Android module for process enumeration
  - CPU and memory usage analysis
  - Hidden process detection via baseline comparison
  - Risk score calculation

- **File System Monitoring**: Watch for malicious APK installations and file modifications
  - Real-time file watching via FileObserver
  - APK static analysis (structure ready)
  - System file modification detection

- **Network Traffic Analysis**: Intercept and analyze network traffic for data exfiltration
  - VPN service for traffic interception
  - Data exfiltration detection
  - DNS tunneling detection
  - Beaconing behavior detection

- **Phishing Detection**: ML-powered URL analysis
  - Rule-based URL analysis
  - Homograph attack detection
  - ML model integration (structure ready)

- **Modern UI**: Glassmorphism design with dark theme
  - Dashboard with system health overview
  - Live threat monitoring
  - Threat history timeline
  - Settings and configuration

- **Encrypted Database**: SQLite with AES-256 encryption
  - Threat storage
  - Process history
  - Network connection logs

### 🚧 In Progress

- **ML Model Training**: TensorFlow Lite models for phishing detection
- **Malware Sandbox**: Isolated execution environment
- **LLM Integration**: Gemini Nano for threat explanations
- **Advanced Visualizations**: Real-time network graphs

## 🏗️ Architecture

- **Frontend**: React Native with TypeScript
- **Backend**: Native Android (Kotlin) modules for system-level access
- **Database**: SQLite with AES-256 encryption
- **ML**: TensorFlow Lite for on-device inference
- **Privacy**: 100% on-device processing, no cloud uploads

## 🚀 Getting Started

### Prerequisites

- **Node.js** >= 18.0.0
- **React Native CLI**: `npm install -g react-native-cli`
- **Android Studio** (for Android development)
  - Android SDK Platform 33
  - Android SDK Build-Tools 33.0.0
  - JDK 11 or higher
- **Xcode** (for iOS development, macOS only)

### Quick Start

```bash
# 1. Install dependencies
npm install

# 2. For iOS (macOS only)
cd ios && pod install && cd ..

# 3. Run on Android
npm run android

# 4. Run on iOS
npm run ios
```

For detailed setup instructions, see [SETUP.md](./SETUP.md)

### Project Structure

```
3-IDEATES/
├── src/
│   ├── ui/              # React Native UI components
│   ├── engine/         # Security detection engines
│   ├── database/       # Encrypted database layer
│   ├── store/          # Redux store and slices
│   ├── services/       # Service layer
│   ├── utils/          # Utility functions
│   └── types/          # TypeScript definitions
├── native/
│   └── android/        # Native Android modules (Kotlin)
└── App.tsx             # Main application
```

For architecture details, see [ARCHITECTURE.md](./ARCHITECTURE.md)

## 📱 Permissions

The app requires the following permissions:
- Network access (for traffic monitoring)
- VPN service (for network interception)
- Package query (for process monitoring)
- File system access (for file monitoring)

All permissions are requested with clear explanations.

## 🔐 Privacy

- **No cloud uploads**: All processing happens on-device
- **No telemetry**: Zero analytics or tracking
- **Encrypted storage**: All data encrypted with AES-256
- **No PII collection**: Never collects personal information

## 🧪 Testing

```bash
# Run tests
npm test

# Type checking
npm run type-check

# Linting
npm run lint
```

## 📄 License

This project is for educational and security research purposes.

## ⚠️ Disclaimer

This application is designed for legitimate security research and personal device protection. Users are responsible for compliance with local laws and regulations.
