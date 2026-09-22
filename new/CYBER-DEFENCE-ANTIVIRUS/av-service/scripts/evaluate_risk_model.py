#!/usr/bin/env python3
"""
Evaluate the trained risk model on a feature CSV.
"""

import argparse
import json
from pathlib import Path

import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix


def sigmoid(x):
    import math

    return 1.0 / (1.0 + math.exp(-x))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="config/ml/risk_model.json")
    ap.add_argument("--input", required=True)
    args = ap.parse_args()

    model = json.loads(Path(args.model).read_text(encoding="utf-8"))
    df = pd.read_csv(args.input)
    y_true = df["label"].astype(int).tolist()

    y_pred = []
    for _, row in df.iterrows():
        raw = (
            model["bias"]
            + model["w_entropy"] * row["entropy"]
            + model["w_executable_ext"] * row["executable_ext"]
            + model["w_script_ext"] * row["script_ext"]
            + model["w_doc_or_media_ext"] * row["doc_or_media_ext"]
            + model["w_valid_pe"] * row["valid_pe"]
            + model["w_embedded_pe"] * row["embedded_pe"]
            + model["w_obfuscation"] * row["obfuscation"]
            + model["w_suspicious_strings"] * row["suspicious_strings"]
        )
        p = sigmoid(raw)
        y_pred.append(int(p >= model["suspicious_threshold"]))

    print("confusion_matrix:")
    print(confusion_matrix(y_true, y_pred))
    print("")
    print(classification_report(y_true, y_pred, digits=4))


if __name__ == "__main__":
    main()
