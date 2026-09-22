# CyberShield Ultimate - Desktop UI

A cross-platform desktop application for CyberShield Ultimate antivirus system built with **React 18** and **Tauri**.

## Features

- **Real-time threat monitoring** - Dashboard with live threat statistics (5-second sync)
- **Threat history** - Complete audit log of detected and blocked threats
- **Deep Search** - Recursive file discovery scan for large folders/home paths
- **System configuration** - Fine-grained security settings and policies
- **AI-powered insights** - LLM-generated threat explanations and recommendations
- **Process and network telemetry** - Dedicated log views with suspicious highlighting
- **Cross-platform** - Windows, macOS, and Linux support via Tauri

## Architecture

### Frontend Stack
- **React 18** - UI component framework
- **Tauri 1.5** - Cross-platform desktop framework
- **Recharts** - Data visualization and charting
- **Tailwind CSS** - Utility-first styling
- **TypeScript** - Type-safe development

### Backend Stack (Tauri)
- **Rust** - System-level integration
- **Tokio** - Async runtime
- **Serde** - JSON serialization
- **UUID** - Threat identification
- **Chrono** - Timestamp management

## Project Structure

```
av-ui-desktop/
├── src/                          # React source code
│   ├── App.tsx                   # Main component with routing
│   ├── App.css                   # Styling
│   └── components/
│       ├── Dashboard.tsx         # Threat statistics & charts
│       ├── ThreatLog.tsx         # Threat history table
│       └── Settings.tsx          # Configuration form
├── src-tauri/                    # Tauri Rust backend
│   ├── src/
│   │   └── main.rs              # Tauri command handlers
│   ├── build.rs                 # Build configuration
│   └── Cargo.toml               # Rust dependencies
├── vite.config.ts               # Vite build configuration
├── tauri.conf.json              # Tauri configuration
├── package.json                 # Node.js dependencies
├── tsconfig.json                # TypeScript configuration
└── README.md                     # This file
```

## Installation

### Prerequisites
- Node.js 16+ (with npm or yarn)
- Rust 1.70+
- Tauri CLI: `npm install -g @tauri-apps/cli`

### Setup

1. **Install dependencies:**
   ```bash
   cd av-ui-desktop
   npm install
   ```

2. **Development mode:**
   ```bash
   npm run tauri dev
   ```

3. **Build for production:**
   ```bash
   npm run tauri build
   ```

## Available Commands

### Development
- `npm run dev` - Start Vite dev server (for web)
- `npm run tauri dev` - Launch development app with hot reload
- `npm run build` - Build React app for production
- `npm run preview` - Preview production build

### Tauri Integration
- `npm run tauri build` - Package executable for current platform
- `npm run tauri build -- --target universal-apple-darwin` - macOS universal binary
- `npm run tauri build -- --target x86_64-unknown-linux-gnu` - Linux x86_64

## Tauri Commands Reference

### System Queries
- **`get_protection_status()`** - Returns current protection status
  ```typescript
  const status = await invoke('get_protection_status');
  // { is_protected: true, real_time_enabled: true, ... }
  ```

- **`get_recent_threats()`** - Fetches threat history
  ```typescript
  const threats = await invoke('get_recent_threats');
  // Array of Threat objects
  ```

- **`get_system_stats()`** - Returns system resource usage
  ```typescript
  const stats = await invoke('get_system_stats');
  // { threats_blocked: 5, cpu_usage: 2.5, memory_usage: 145 }
  ```

### Actions
- **`invoke_scan(path: string)`** - Trigger file/folder scan
  ```typescript
  const result = await invoke('invoke_scan', { path: '/home/user/Documents' });
  ```

- **`quarantine_file(path: string)`** - Move file to quarantine
  ```typescript
  await invoke('quarantine_file', { path: '/path/to/file' });
  ```

- **`restore_quarantined_file(path: string)`** - Restore from quarantine
  ```typescript
  await invoke('restore_quarantined_file', { path: '/quarantine/file' });
  ```

- **`get_threat_explanation(threat_name: string)`** - Get AI explanation
  ```typescript
  const explanation = await invoke('get_threat_explanation', 
    { threat_name: 'Trojan.Win32.Generic' });
  ```

### Service APIs consumed by the UI
- **`GET /api/v1/settings`** - Fetches persisted protection settings
- **`PUT /api/v1/settings`** - Saves real-time protection and scan policy settings
- **`POST /api/v1/scan/deep`** - Queues recursive deep scan (with max file cap)
- **`GET /api/v1/process-logs`** - Lists active processes with CPU/memory indicators
- **`GET /api/v1/network-logs`** - Lists active network connections
- **`POST /api/v1/explain-logs`** - Returns simplified explanation for `process` or `network`

### Service Communication
- **`log_threat(name, path, severity)`** - Called by av-service to report threats
- **`update_protection_status(is_protected)`** - Called by av-service to update status

## Integration with av-service

The desktop UI communicates with the antivirus core service (av-service) through:

1. **Tauri Commands** - Exposed Rust functions called from React
2. **IPC (Inter-Process Communication)** - Named pipes / Unix sockets
3. **REST API** - HTTP endpoints for service communication

**Integration Points:**
- **av-service** → **av-ui-desktop**: Threat detection events via WebSocket/REST
- **av-ui-desktop** → **av-service**: Scan requests, quarantine actions
- **av-ai** → **av-ui-desktop**: Threat explanations via REST

## Configuration

### Tauri Settings (tauri.conf.json)
- Window size, resizability
- Security allowlist
- Application metadata

### Vite Settings (vite.config.ts)
- Dev server port (5173)
- Build optimization
- Code splitting for vendor libraries

### TypeScript (tsconfig.json)
- React JSX support
- Target: ES2020
- Strict mode enabled

## Security Considerations

1. **Command Allowlist** - Only essential Tauri commands are allowed (see tauri.conf.json)
2. **CSP Headers** - Strict Content Security Policy to prevent XSS
3. **Privilege Boundaries** - Rust backend isolates system-level operations
4. **Encrypted Storage** - Sensitive settings stored securely via Tauri keyring

## Performance Optimizations

1. **Code Splitting** - Vendor libraries separated for better caching
2. **Lazy Loading** - React components loaded on-demand
3. **Chart Optimization** - Recharts memoized to prevent unnecessary re-renders
4. **Polling Strategy** - 5-second refresh interval

## Troubleshooting

### Tauri Dev Build Fails
```bash
# Clear Tauri cache
rm -rf src-tauri/target

# Reinstall dependencies
npm ci
npm run tauri build
```

### Live Sync Issues
- Verify av-service is running on expected port
- Check firewall rules
- Enable debug logging: `RUST_LOG=debug npm run tauri dev`

### macOS Code Signing
```bash
# Generate signing identity
security create-keychain CyberShield.keychain
codesign -s - src-tauri/target/release/cybershield-ui.app
```

## Platform-Specific Notes

### Windows
- Requires Visual Studio Build Tools for code signing
- Executable location: `src-tauri/target/release/cybershield-ui.exe`

### macOS
- Requires developer certificate for distribution
- Executable location: `src-tauri/target/release/bundle/macos/CyberShield Ultimate.app`

### Linux
- Requires `libwebkit2gtk-4.0-dev` and `libssl-dev`
- Executable location: `src-tauri/target/release/cybershield-ui`

## Development Workflow

1. **Make UI changes** in `src/components/`
2. **Update Tauri commands** in `src-tauri/src/main.rs`
3. **Run dev build**: `npm run tauri dev`
4. **Test changes** in launched window (hot reload available for React)
5. **Build release**: `npm run tauri build`

## Contributing

When adding new features:

1. Create new React component in `src/components/`
2. Add Tauri command handler if needed
3. Update TypeScript types
4. Add error handling with user-friendly messages
5. Update README with new commands/features

## License

MIT License - See LICENSE file for details

## Support

For issues, feature requests, or questions:
- GitHub Issues: [cybershield-ui/issues](https://github.com/cybershield/issues)
- Documentation: [CyberShield Wiki](https://wiki.cybershield.io)
- Community: [Discord Server](https://discord.gg/cybershield)
