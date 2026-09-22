Linux Security Engine (Rust) - CyberShield

This module is a minimal Rust-based security engine prototype for Linux.
It exposes a CLI with two commands:

- `start --dirs <dir1> <dir2> ...` : start monitoring directories (blocking)
- `scan <file>` : compute entropy and return JSON with `path`, `size`, `entropy`

Integration notes:
- Electron can call `desktop/native/linux/target/release/cyberdefense_linux_engine scan /path/to/file`
  to get per-file analysis (entropy) as JSON.
- For production, extend `monitor_paths` to map watch descriptors to directories
  and emit structured events (e.g., over a Unix socket or write to local SQLite DB).

Build:
```bash
cd desktop/native/linux
cargo build --release
```

Run demo scan:
```bash
./target/release/cyberdefense_linux_engine scan /path/to/file
```

Limitations:
- This is a prototype; `monitor_paths` currently logs events but does not reconstruct full path from watch descriptor.
- Add eBPF-based process monitoring and a proper event queue for real deployments.
