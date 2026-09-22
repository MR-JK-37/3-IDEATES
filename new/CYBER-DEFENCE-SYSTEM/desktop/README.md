CyberShield Desktop Scaffold

This folder contains an Electron scaffold with a simple renderer and platform-specific
security engine placeholders under `desktop/electron/security/`.

Quick start (requires Node.js and Electron installed):

```bash
cd desktop/electron
npm install
npm start
```

IPC surface exposed in renderer via `window.cybershield.getThreats()` and `window.cybershield.scanFile(path)`.

Replace the placeholder engines with platform-native modules (Rust/C#/Swift) for production.
