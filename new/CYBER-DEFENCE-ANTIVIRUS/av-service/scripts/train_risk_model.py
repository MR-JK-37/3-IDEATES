#!/usr/bin/env python3
"""
Train a lightweight malware risk model and export JSON weights consumed by
av-service/src/engines/ml.rs.

Input CSV format (header required):
entropy,executable_ext,script_ext,doc_or_media_ext,valid_pe,embedded_pe,obfuscation,suspicious_strings,label

`label`: 0 clean, 1 malicious/suspicious
"""

import argparse
import json
from pathlib import Path

import pandas as pd
from sklearn.linear_model import LogisticRegression


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Training CSV path")
    parser.add_argument(
        "--output",
        default="config/ml/risk_model.json",
        help="Model weights output path",
    )
    parser.add_argument("--suspicious-threshold", type=float, default=0.72)
    parser.add_argument("--malicious-threshold", type=float, default=0.90)
    args = parser.parse_args()

    df = pd.read_csv(args.input)
    features = [
        "entropy",
        "executable_ext",
        "script_ext",
        "doc_or_media_ext",
        "valid_pe",
        "embedded_pe",
        "obfuscation",
        "suspicious_strings",
    ]
    x = df[features]
    y = df["label"]

    model = LogisticRegression(max_iter=2000, class_weight="balanced")
    model.fit(x, y)

    coef = model.coef_[0]
    payload = {
        "bias": float(model.intercept_[0]),
        "w_entropy": float(coef[0]),
        "w_executable_ext": float(coef[1]),
        "w_script_ext": float(coef[2]),
        "w_doc_or_media_ext": float(coef[3]),
        "w_valid_pe": float(coef[4]),
        "w_embedded_pe": float(coef[5]),
        "w_obfuscation": float(coef[6]),
        "w_suspicious_strings": float(coef[7]),
        "suspicious_threshold": args.suspicious_threshold,
        "malicious_threshold": args.malicious_threshold,
    }

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"saved {out}")


if __name__ == "__main__":
    main()
