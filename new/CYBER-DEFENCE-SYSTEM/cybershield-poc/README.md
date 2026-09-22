CyberShield PoC - Linux Ransomware Detector

Overview
--------
This PoC implements a lightweight Linux filesystem monitor that detects rapid mass file modifications and high-entropy writes — indicative of ransomware.

Features
--------
- Recursive polling-based watcher (no external dependencies)
- Single-pass test mode (`--once`) for CI or quick verification
- Rolling 10-second window detection for mass modifications
- Entropy-based per-file analysis

Run (single-pass test)
---------------------
```bash
python3 cybershield-poc/poc_detector.py --dirs ./ --once
```

Run (continuous)
----------------
```bash
python3 cybershield-poc/poc_detector.py --dirs /home/$USER/Downloads /home/$USER/Documents
```

Notes
-----
This PoC is intended as a prototype for integration into a native agent later (Kotlin/Android, eBPF, or ETW on Windows).
