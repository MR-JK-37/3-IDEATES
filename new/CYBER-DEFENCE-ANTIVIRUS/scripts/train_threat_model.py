#!/usr/bin/env python3
"""
CyberShield helper to assemble a malware-analysis system prompt and local training seed set.
This script does not perform remote fine-tuning by itself.
"""

from __future__ import annotations

import json
from pathlib import Path
import re

RULES_DIR = Path("/var/lib/cybershield/yara-rules")
OUT_DIR = Path("/var/lib/cybershield/ai-model")


def classify_from_name(name: str) -> str:
    lower = name.lower()
    if "ransom" in lower:
        return "ransomware"
    if "trojan" in lower:
        return "trojan"
    if "backdoor" in lower or "rat" in lower:
        return "backdoor"
    if "rootkit" in lower:
        return "rootkit"
    if "worm" in lower:
        return "worm"
    if "miner" in lower:
        return "cryptominer"
    if "spy" in lower:
        return "spyware"
    return "suspicious"


def build_training_data() -> list[dict[str, str]]:
    examples: list[dict[str, str]] = []
    if not RULES_DIR.exists():
        return examples

    for rule_file in RULES_DIR.rglob("*.yar"):
        try:
            content = rule_file.read_text(errors="ignore")
        except OSError:
            continue

        for match in re.finditer(r"rule\s+([A-Za-z0-9_]+)", content):
            rule_name = match.group(1)
            examples.append(
                {
                    "input": f"YARA rule matched: {rule_name}",
                    "output": classify_from_name(rule_name),
                }
            )
    return examples


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    training_data = build_training_data()

    system_prompt = """You are a malware analyst trained on real malware behavior patterns.
Classify threats into practical categories and explain risk to non-technical users clearly.
Prefer actionable guidance: block, quarantine, monitor, or allow.
"""

    (OUT_DIR / "system_prompt.txt").write_text(system_prompt)
    (OUT_DIR / "training_seed.json").write_text(json.dumps(training_data, indent=2))
    print(f"wrote {len(training_data)} seed examples to {OUT_DIR}/training_seed.json")


if __name__ == "__main__":
    main()
