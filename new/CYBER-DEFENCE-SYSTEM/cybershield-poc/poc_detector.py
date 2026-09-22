#!/usr/bin/env python3
"""
PoC ransomware detector (polling watcher)

Scans directories recursively and detects mass file modifications and
high-entropy writes within a short rolling window. Designed as a simple,
dependency-free prototype for Linux endpoint monitoring.

Usage:
  python3 poc_detector.py --dirs ./Downloads ./Documents --once

Author: CyberShield PoC
"""

import argparse
import collections
import math
import os
import sys
import time
from typing import Dict, Tuple

# Configuration
WINDOW_SECONDS = 10
MASS_MOD_THRESHOLD = 50  # files in WINDOW_SECONDS
HIGH_ENTROPY_THRESHOLD = 7.5


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = collections.Counter(data)
    length = len(data)
    entropy = -sum((count / length) * math.log2(count / length) for count in freq.values())
    return entropy


def scan_files_snapshot(dirs):
    """Return dict path -> (mtime, size, entropy)"""
    snapshot: Dict[str, Tuple[float, int, float]] = {}
    for base in dirs:
        for root, dirsnames, filenames in os.walk(base):
            for fn in filenames:
                path = os.path.join(root, fn)
                try:
                    st = os.stat(path)
                    mtime = st.st_mtime
                    size = st.st_size
                    entropy = 0.0
                    # Only sample up to first 64 KiB for speed
                    if size > 0:
                        with open(path, "rb") as f:
                            sample = f.read(65536)
                            entropy = shannon_entropy(sample)
                    snapshot[path] = (mtime, size, entropy)
                except (PermissionError, FileNotFoundError, IsADirectoryError):
                    continue
                except Exception as e:
                    print(f"[WARN] Failed to snapshot {path}: {e}")
    return snapshot


def detect_changes(prev_snap, curr_snap, event_window: collections.deque):
    modified_paths = []
    entropy_alerts = []

    for path, (mtime, size, entropy) in curr_snap.items():
        prev = prev_snap.get(path)
        if prev is None:
            # New file created -> treat as modification
            modified_paths.append(path)
            event_window.append(time.time())
            if entropy >= HIGH_ENTROPY_THRESHOLD:
                entropy_alerts.append((path, entropy))
        else:
            prev_mtime, prev_size, prev_entropy = prev
            if mtime > prev_mtime or size != prev_size:
                modified_paths.append(path)
                event_window.append(time.time())
                if entropy >= HIGH_ENTROPY_THRESHOLD and entropy - prev_entropy > 0.5:
                    entropy_alerts.append((path, entropy, prev_entropy))

    # Evict old events
    cutoff = time.time() - WINDOW_SECONDS
    while event_window and event_window[0] < cutoff:
        event_window.popleft()

    return modified_paths, entropy_alerts, len(event_window)


def human_short(p):
    try:
        return os.path.basename(p)
    except Exception:
        return p


def main():
    ap = argparse.ArgumentParser(description="PoC ransomware detector (polling)")
    ap.add_argument("--dirs", nargs="+", required=True, help="Directories to monitor")
    ap.add_argument("--once", action="store_true", help="Run one scan pass and exit")
    ap.add_argument("--interval", type=float, default=1.0, help="Polling interval in seconds")
    args = ap.parse_args()

    dirs = [os.path.abspath(d) for d in args.dirs]
    for d in dirs:
        if not os.path.isdir(d):
            print(f"[ERROR] Not a directory: {d}")
            sys.exit(2)

    print(f"[INFO] Monitoring directories: {dirs}")
    prev_snap = scan_files_snapshot(dirs)
    event_window = collections.deque()

    if args.once:
        print("[INFO] Single-pass scan mode")
        curr_snap = scan_files_snapshot(dirs)
        modified, entropy_alerts, window_count = detect_changes(prev_snap, curr_snap, event_window)
        print(f"[INFO] Modified files detected: {len(modified)}")
        if window_count >= MASS_MOD_THRESHOLD:
            print("[ALERT] Mass file modification detected (possible ransomware)")
        for e in entropy_alerts:
            if len(e) == 2:
                path, ent = e
                print(f"[ALERT] High-entropy write: {path} entropy={ent:.2f}")
            else:
                path, ent, prev_ent = e
                print(f"[ALERT] Entropy increase: {path} {prev_ent:.2f} -> {ent:.2f}")
        sys.exit(0)

    print("[INFO] Starting continuous monitoring (press Ctrl-C to stop)")
    try:
        while True:
            time.sleep(args.interval)
            curr_snap = scan_files_snapshot(dirs)
            modified, entropy_alerts, window_count = detect_changes(prev_snap, curr_snap, event_window)
            if modified:
                print(f"[EVENT] {len(modified)} files modified (recent window={window_count})")
            if window_count >= MASS_MOD_THRESHOLD:
                print("[ALERT] Mass file modification detected (possible ransomware)")
                for i, p in enumerate(modified[:10], 1):
                    print(f"  {i}. {human_short(p)}")
            for e in entropy_alerts:
                if len(e) == 2:
                    path, ent = e
                    print(f"[ALERT] High-entropy write: {path} entropy={ent:.2f}")
                else:
                    path, ent, prev_ent = e
                    print(f"[ALERT] Entropy increase: {path} {prev_ent:.2f} -> {ent:.2f}")
            prev_snap = curr_snap
    except KeyboardInterrupt:
        print("\n[INFO] Stopping monitor")


if __name__ == "__main__":
    main()
