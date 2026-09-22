#!/usr/bin/env python3
"""Demo runner that integrates entropy features, YARA rules, and TFLite inference.

This script is intended for local testing of the ML+YARA integration. It
computes entropy for a file, checks local YARA rules (if `yara` is installed),
and runs a TFLite model (if available) to produce a threat score.

The script gracefully degrades when dependencies are absent.
"""

import argparse
import os
import sys
from pathlib import Path

# Ensure local module import works when run as a script
sys.path.insert(0, str(Path(__file__).resolve().parent))
from inference import TFLiteModel

import collections
import math


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = collections.Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def yara_check(path: str, rules_path: str) -> bool:
    try:
        import yara
    except Exception:
        print("[INFO] yara-python not installed; skipping YARA checks")
        return False
    try:
        rules = yara.compile(filepath=rules_path)
        matches = rules.match(path)
        return bool(matches)
    except Exception as e:
        print(f"[WARN] YARA check failed: {e}")
        return False


def run_on_file(path: str, model_path: str, yara_rules: str):
    if not os.path.isfile(path):
        print(f"[ERROR] File not found: {path}")
        return

    size_kb = os.path.getsize(path) / 1024.0
    sample = b""
    with open(path, 'rb') as f:
        sample = f.read(65536)

    entropy = shannon_entropy(sample)
    print(f"[INFO] File: {path} size_kb={size_kb:.1f} entropy={entropy:.2f}")

    yara_hit = yara_check(path, yara_rules) if yara_rules else False
    if yara_hit:
        print("[ALERT] YARA rule matched — suspicious file content")

    model = TFLiteModel(model_path)
    model.load()
    # Example feature vector: [entropy, size_kb, mass_mod_count, cmd_score, net_score]
    # For demo, mass_mod_count and scores are simulated
    features = [entropy, size_kb, 0.0, 0.0, 0.0]
    score = model.predict(features)
    print(f"[RESULT] ML threat score: {score:.3f}")


def demo_mode(model_path: str, yara_rules: str):
    print("[INFO] Running demo mode with synthetic file")
    # Create a synthetic buffer that simulates high entropy
    synthetic = os.urandom(65536)
    tmp = Path('ml_demo_sample.bin')
    tmp.write_bytes(synthetic)
    try:
        run_on_file(str(tmp), model_path, yara_rules)
    finally:
        tmp.unlink(missing_ok=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--file', help='Target file to analyze')
    ap.add_argument('--model', default='ml/models/model.tflite', help='Path to TFLite model')
    ap.add_argument('--yara', default='ml/yara_rules/ransomware_rules.yar', help='YARA rules file')
    ap.add_argument('--test', action='store_true', help='Run demo synthetic test')
    args = ap.parse_args()

    if args.test:
        demo_mode(args.model, args.yara)
        return

    if not args.file:
        print('Specify --file or --test')
        sys.exit(2)

    run_on_file(args.file, args.model, args.yara)


if __name__ == '__main__':
    main()
