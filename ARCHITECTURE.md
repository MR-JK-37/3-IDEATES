# 🏗️ CyberDefense Mobile - Architecture Documentation

## Overview

CyberDefense Mobile is a production-grade real-time cyber defense application built with React Native and native Android modules. The application provides comprehensive threat detection and protection while maintaining complete privacy through on-device processing.

## Architecture Layers

### 1. Presentation Layer (UI)

**Technology**: React Native with TypeScript

**Components**:
- **Dashboard Screen**: System health overview, active threats, protection status
- **Live Monitor Screen**: Real-time threat visualization
- **Network Monitor Screen**: Traffic analysis and data leak detection
- **Threat History Screen**: Timeline of detected threats
- **Settings Screen**: Feature toggles and configuration
- **Sandbox Viewer Screen**: Isolated threat analysis

**State Management**: Redux Toolkit
- `threatsSlice`: Threat management
- `systemHealthSlice`: System health monitoring
- `settingsSlice`: Application settings
- `processesSlice`: Process information

### 2. Business Logic Layer

**Security Engines**:
- **ProcessMonitorEngine**: Detects hidden processes, rootkits, suspicious behavior
- **FileMonitorEngine**: Monitors file system for malicious APKs and modifications
- **NetworkMonitorEngine**: Intercepts and analyzes network traffic
- **PhishingDetectorEngine**: ML-powered URL analysis for phishing detection

**Services**:
- **EngineManager**: Coordinates all security engines
- **EngineService**: Initializes and manages engines lifecycle
- **DatabaseManager**: Encrypted database operations

### 3. Data Layer

**Database**: SQLite with AES-256 encryption
- **Tables**:
  - `threats`: Threat records
  - `threat_actions`: Actions taken on threats
  - `processes`: Process information
  - `network_connections`: Network connection history
  - `settings`: Application settings

**Storage**: React Native Encrypted Storage
- Encryption keys
- Sensitive configuration

### 4. Native Layer (Android)

**Modules**:
- **ProcessMonitorModule.kt**: Process enumeration via ActivityManager
- **FileMonitorModule.kt**: File system monitoring via FileObserver
- **NetworkMonitorModule.kt**: Traffic interception via VpnService

**Communication**: React Native Bridge
- Method calls: Native → JavaScript
- Events: Native → JavaScript (via EventEmitter)

## Data Flow

### Threat Detection Flow

```
1. Native Module detects event (process/file/network)
   ↓
2. Event sent to React Native via EventEmitter
   ↓
3. Security Engine receives event
   ↓
4. Engine analyzes event for threats
   ↓
5. Threat created and added to Redux store
   ↓
6. Threat saved to encrypted database
   ↓
7. UI updated with new threat
   ↓
8. User notified (if enabled)
```

### Process Monitoring Flow

```
1. ProcessMonitorEngine starts periodic scanning (every 5s)
   ↓
2. Calls ProcessMonitorModule.getRunningProcesses()
   ↓
3. Native module enumerates processes via ActivityManager
   ↓
4. Returns process list with CPU/memory usage
   ↓
5. Engine calculates risk scores
   ↓
6. Detects suspicious processes
   ↓
7. Creates threats for high-risk processes
   ↓
8. Updates Redux store
```

### Network Monitoring Flow

```
1. NetworkMonitorEngine starts VPN service
   ↓
2. NetworkMonitorModule creates local VPN
   ↓
3. All network traffic routed through VPN
   ↓
4. Packets analyzed in real-time
   ↓
5. Detects data exfiltration, suspicious connections
   ↓
6. Blocks malicious traffic
   ↓
7. Creates threats and alerts user
```

## Security Features

### 1. Process Monitoring

**Detection Methods**:
- Process enumeration via ActivityManager
- `/proc` filesystem parsing
- Hidden process detection (baseline comparison)
- CPU/memory usage analysis
- Parent-child relationship analysis

**Threat Types Detected**:
- Hidden processes (rootkits)
- High CPU usage without UI
- Unusual process relationships
- Excessive memory allocation

### 2. File System Monitoring

**Detection Methods**:
- Real-time file watching (FileObserver)
- APK static analysis
- Permission analysis
- Obfuscation detection

**Threat Types Detected**:
- Malicious APK installations
- System file modifications
- Executables in suspicious locations

### 3. Network Monitoring

**Detection Methods**:
- Traffic interception (VpnService)
- Packet analysis
- DNS tunneling detection
- Beaconing behavior detection
- IP reputation checking

**Threat Types Detected**:
- Data exfiltration
- Suspicious connections
- DNS tunneling
- C2 communication

### 4. Phishing Detection

**Detection Methods**:
- ML-based URL classification (TensorFlow Lite)
- Rule-based checks
- Homograph attack detection
- Domain analysis

**Threat Types Detected**:
- Phishing websites
- Lookalike domains
- Suspicious URL patterns

## Privacy Architecture

### On-Device Processing

- **100% Local**: All processing happens on-device
- **No Cloud Uploads**: Zero data sent to external servers
- **No Telemetry**: No analytics or tracking
- **Encrypted Storage**: All data encrypted with AES-256

### Data Encryption

```typescript
// Database encryption key stored in Android Keystore
const key = await EncryptedStorage.getItem('db_encryption_key');

// All threat data encrypted before storage
const cipher = Cipher.getInstance('AES/GCM/NoPadding');
cipher.init(Cipher.ENCRYPT_MODE, secretKey);
const encryptedData = cipher.doFinal(threatData.toByteArray());
```

## Performance Optimization

### Battery Optimization

- **Efficient Scanning**: Configurable scan intervals
- **Background Processing**: Uses foreground services
- **Resource Monitoring**: Tracks CPU/memory/battery usage
- **Target**: < 5% additional battery drain

### Memory Optimization

- **Process List Limiting**: Keep only active processes
- **Connection History**: Limit to last 1000 connections
- **Threat History**: Limit to last 1000 threats
- **Target**: < 150MB RAM usage

### CPU Optimization

- **Async Processing**: All I/O operations async
- **Debouncing**: Debounce frequent events
- **Throttling**: Throttle high-frequency scans
- **Target**: < 10% CPU usage average

## Testing Strategy

### Unit Tests

- Engine logic
- Threat detection algorithms
- Risk score calculations
- Utility functions

### Integration Tests

- Native module communication
- Database operations
- Redux store updates
- Engine coordination

### Security Tests

- Malware sample testing (isolated environment)
- Phishing URL testing
- Network attack simulation
- Rootkit detection validation

## Deployment

### Android APK Build

```bash
cd android
./gradlew assembleRelease
```

### Play Store Requirements

- Target SDK: 33
- Min SDK: 23
- Permissions: Declared in AndroidManifest.xml
- Privacy Policy: Required for VPN service

## Future Enhancements

1. **ML Model Training**: Train and deploy TensorFlow Lite models
2. **Malware Sandbox**: Complete isolated execution environment
3. **LLM Integration**: Gemini Nano for threat explanations
4. **iOS Support**: Native iOS modules
5. **Advanced Visualizations**: Real-time network graphs
6. **Threat Intelligence**: Offline threat database updates

## Security Considerations

### Code Obfuscation

- ProGuard rules for production builds
- String encryption for sensitive data
- Native code protection

### Certificate Pinning

- Implement for any future API calls
- Prevent MITM attacks

### Secure Random

- Use Android SecureRandom for keys
- Cryptographically secure random generation

## Compliance

### Privacy Regulations

- **GDPR**: Compliant (no data collection)
- **CCPA**: Compliant (no data sharing)
- **COPPA**: Compliant (no user tracking)

### Security Standards

- **OWASP Mobile Top 10**: Addressed
- **NIST Cybersecurity Framework**: Aligned
- **Android Security Best Practices**: Followed
